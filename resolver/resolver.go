package resolver

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	mrand "math/rand"
	"net"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/context"
)

func init() {
	b := [8]byte{}
	_, err := rand.Read(b[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read bytes for psrng initialization: %s\n", err)
		return
	}
	i, err := binary.ReadVarint(bytes.NewBuffer(b[:]))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read bytes for psrng initialization: %s\n", err)
		return
	}
	mrand.Seed(i)
}

var (
	maxReferrals = 10

	dnsPort = "53"

	errTooManyReferrals   = errors.New("Too many referrals")
	errNoNSAuthorties     = errors.New("No NS authority records found")
	errNoAuthorityAddress = errors.New("No A/AAAA records found for the chosen authority")
)

// QueryLog describes a query to a upstream nameserver
type QueryLog struct {
	Query       *dns.Question
	AnswerType  string
	CacheHit    bool `json:",omitempty"`
	DNSSECValid bool
	Latency     time.Duration
	Error       error `json:",omitempty"`
	Truncated   bool  `json:",omitempty"`

	// Only present if CacheHit == false
	NS *rootNS `json:",omitempty"`

	Composites []*QueryLog `json:",omitempty"`
}

// LookupLog describes a iterative resolution
type LookupLog struct {
	Query       *dns.Question
	DNSSECValid bool
	Started     time.Time
	Latency     time.Duration

	Composites []*QueryLog
}

type authMap map[string][]string

func buildAuthMap(auths []dns.RR, extras []dns.RR) *authMap {
	am := make(authMap, len(extras))
	for _, a := range auths {
		if a.Header().Rrtype == dns.TypeNS {
			ns := a.(*dns.NS)
			am[ns.Hdr.Name] = append(am[ns.Hdr.Name], ns.Ns)
		}
	}
	return &am
}

// Answer contains the answer to a iterative resolution performed
// by RecursiveResolver.Lookup
type Answer struct {
	Answer        []dns.RR
	Authority     []dns.RR
	Additional    []dns.RR
	Rcode         int
	Authenticated bool
}

type rootNS struct {
	Name string
	Addr string
	Zone string
}

// RecursiveResolver defines the parameters for running a recursive resolver
type RecursiveResolver struct {
	useIPv6   bool
	useDNSSEC bool

	c *dns.Client

	cache           QuestionAnswerCache
	rootNameservers []rootNS
}

// NewRecursiveResolver returns an initialized RecursiveResolver
func NewRecursiveResolver(useIPv6 bool, useDNSSEC bool, rootHints []dns.RR, rootKeys []dns.RR, cache QuestionAnswerCache) *RecursiveResolver {
	if cache == nil {
		cache = newQACache()
	}
	rr := &RecursiveResolver{
		useIPv6:   useIPv6,
		useDNSSEC: useDNSSEC,
		c:         new(dns.Client),
		cache:     cache,
	}
	// Initialize root nameservers
	addrs := extractRRSet(rootHints, dns.TypeA, "")
	if useIPv6 {
		addrs = append(addrs, extractRRSet(rootHints, dns.TypeAAAA, "")...)
	}
	for _, a := range addrs {
		switch r := a.(type) {
		case *dns.A:
			rr.rootNameservers = append(rr.rootNameservers, rootNS{a.Header().Name, r.A.String(), "."})
		case *dns.AAAA:
			rr.rootNameservers = append(rr.rootNameservers, rootNS{a.Header().Name, r.AAAA.String(), "."})
		}
	}
	// Add root DNSSEC keys to cache indefinitely
	rr.cache.Add(&dns.Question{Name: ".", Qtype: dns.TypeDNSKEY, Qclass: dns.ClassINET}, rootKeys, nil, nil, true, true)
	return rr
}

func (rr *RecursiveResolver) query(ctx context.Context, q dns.Question, auth *rootNS) (*dns.Msg, *QueryLog, error) {
	ql := &QueryLog{Query: &q, NS: auth}
	s := time.Now()
	defer func() { ql.Latency = time.Since(s) }()
	m := new(dns.Msg)
	m.SetEdns0(4096, rr.useDNSSEC)
	m.Question = []dns.Question{q}
	if answer, auth, extra, authenticated, present := rr.cache.Get(&q); present {
		m.Rcode = dns.RcodeSuccess
		m.Answer = answer
		m.Ns = auth
		m.Extra = extra
		ql.CacheHit = true
		ql.NS = nil
		ql.DNSSECValid = authenticated
		return m, ql, nil
	}
	r, _, err := rr.c.Exchange(m, net.JoinHostPort(auth.Addr, dnsPort))
	if err != nil {
		return nil, ql, err
	}

	// check all returned records are in-bailiwick, ignore extra section?
	for _, section := range [][]dns.RR{r.Answer, r.Ns} {
		for _, record := range section {
			if record.Header().Rrtype != dns.TypeOPT && !strings.HasSuffix(record.Header().Name, auth.Zone) {
				return nil, ql, errors.New("Out of bailiwick record in message") // or just strip invalid records...?
			}
		}
	}
	return r, ql, nil
}

func (rr *RecursiveResolver) lookupNS(ctx context.Context, name string) (*rootNS, error) {
	// XXX: this should prob take into account the parent iterations...?
	// XXX: this should do parallel v4/v6 lookups if a v6 stack is supported
	// XXX: how to take into account below ingored validated meaning...?
	r, _, err := rr.Lookup(ctx, dns.Question{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET})
	if err != nil {
		return nil, err
	}
	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("Authority lookup failed for %s: %s", name, dns.RcodeToString[r.Rcode])
	}
	if len(r.Answer) == 0 {
		return nil, errNoAuthorityAddress
	}
	addresses := extractRRSet(r.Answer, dns.TypeA, name)
	if len(addresses) == 0 {
		return nil, errNoAuthorityAddress
	}
	return &rootNS{Name: name, Addr: addresses[mrand.Intn(len(addresses))].(*dns.A).A.String()}, nil // ewwww
}

func (rr *RecursiveResolver) pickAuthority(ctx context.Context, auths []dns.RR, extras []dns.RR) (*rootNS, error) {
	zones, _, nsToZone := splitAuthsByZone(auths, extras, rr.useIPv6)
	if len(zones) == 0 {
		if len(nsToZone) == 0 {
			return nil, errNoNSAuthorties
		}
		var ns, z string
		// abuse how ranging over maps works to select a 'random' element
		for ns, z = range nsToZone {
			break
		}
		a, err := rr.lookupNS(ctx, ns)
		if err != nil {
			return nil, err
		}
		a.Zone = z
		return a, nil
	}
	// abuse how ranging over maps works to select a 'random' element
	for ns, z := range nsToZone {
		if len(zones[z]) > 0 {
			return &rootNS{ns, zones[z][mrand.Intn(len(zones[z]))], z}, nil
		}
	}
	return nil, errNoNSAuthorties
}

func extractAnswer(m *dns.Msg, authenticated bool) *Answer {
	return &Answer{
		Answer:        m.Answer,
		Authority:     m.Ns,
		Additional:    m.Extra,
		Rcode:         m.Rcode,
		Authenticated: authenticated,
	}
}

// Lookup a miekg/dns.Question iteratively. All upstream responses are validated
// and a DNSSEC chain is built if the RecursiveResolver was initialized to do so.
// If responses are found in the underlying cache they will be used instead of
// sending messages to remote nameservers.
func (rr *RecursiveResolver) Lookup(ctx context.Context, q dns.Question) (*Answer, *LookupLog, error) {
	ll := &LookupLog{Query: &q, Started: time.Now()}

	authority := &rr.rootNameservers[mrand.Intn(len(rr.rootNameservers))]

	defer func() {
		ll.Latency = time.Since(ll.Started)
	}()

	var parentDSSet []dns.RR
	for i := 0; i < maxReferrals; i++ {
		r, log, err := rr.query(ctx, q, authority)
		ll.Composites = append(ll.Composites, log)
		if err != nil && err != dns.ErrTruncated { // if truncated still try...
			log.Error = err
			return nil, ll, err
		} else if err == dns.ErrTruncated {
			log.Truncated = true
		}

		// validate
		validated := false
		if log.CacheHit {
			validated = log.DNSSECValid
		}
		if (i == 0 || len(parentDSSet) > 0) && !log.CacheHit {
			dkLog, err := rr.checkDNSKEY(ctx, r, authority, parentDSSet)
			log.Composites = append(log.Composites, dkLog)
			if err != nil {
				log.Error = err
				return nil, ll, err
			}
			validated = true
		}
		log.DNSSECValid = validated
		ll.DNSSECValid = validated

		if r.Rcode != dns.RcodeSuccess {
			log.AnswerType = dns.RcodeToString[r.Rcode]
			return extractAnswer(r, validated), ll, nil
		}

		// good response
		if len(r.Answer) > 0 {
			// cache
			if !log.CacheHit {
				go rr.cache.Add(&q, r.Answer, r.Ns, r.Extra, validated, false)
			}

			log.AnswerType = "Success"
			// check for alias and chase or do that in RecursiveResolver.query?
			return extractAnswer(r, validated), ll, nil
		}

		// referral
		if len(r.Ns) > 0 {
			log.AnswerType = "Referral"
			authority, err = rr.pickAuthority(ctx, r.Ns, r.Extra)
			if err != nil {
				return nil, ll, err
			}
			if i == 0 || len(parentDSSet) > 0 {
				parentDSSet = extractRRSet(r.Ns, dns.TypeDS, authority.Zone)
			}
			// XXX: Need to verify referrals that include NSEC DS denial
			continue
		}
		return nil, ll, errors.New("No authority or additional records! IDK") // ???
	}
	return nil, ll, errTooManyReferrals
}

func extractRRSet(in []dns.RR, t uint16, name string) []dns.RR {
	out := []dns.RR{}
	for _, r := range in {
		if r.Header().Rrtype == t {
			if name != "" && name != r.Header().Name {
				continue
			}
			out = append(out, r)
		}
	}
	return out
}

func extractAndMapRRSet(in []dns.RR, name string, t ...uint16) map[uint16][]dns.RR {
	out := make(map[uint16][]dns.RR, len(t))
	for _, rt := range t {
		out[rt] = []dns.RR{}
	}
	for _, r := range in {
		rt := r.Header().Rrtype
		if _, present := out[rt]; !present {
			continue
		}
		if name != "" && name != r.Header().Name {
			continue
		}
		out[rt] = append(out[rt], r)
	}
	return out
}
