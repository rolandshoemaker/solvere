// Package solvere provides an implementation of a recursive, validating,
// DNSSEC aware DNS resolver. It also provides a basic question and answer
// cache implementation.
package solvere

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
	// Initialize math/rand with 8 bytes from crypto/rand so the randomness
	// isn't _super_ terrible
	b := [8]byte{}
	_, err := rand.Read(b[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read bytes for PSRNG initialization: %s\n", err)
		return
	}
	i, err := binary.ReadVarint(bytes.NewBuffer(b[:]))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read bytes for PSRNG initialization: %s\n", err)
		return
	}
	mrand.Seed(i)
}

var (
	// MaxReferrals is the maximum number of referral responses before failing
	MaxReferrals = 10

	dnsPort = "53"

	ErrTooManyReferrals   = errors.New("solvere: Too many referrals")
	ErrNoNSAuthorties     = errors.New("solvere: No NS authority records found")
	ErrNoAuthorityAddress = errors.New("solvere: No A/AAAA records found for the chosen authority")
)

// Question represents a DNS IN question
type Question struct {
	Name string
	Type uint16
}

// QueryLog describes a query to a upstream nameserver
type QueryLog struct {
	Query       *Question
	Rcode       int
	CacheHit    bool `json:",omitempty"`
	DNSSECValid bool
	Latency     time.Duration
	Error       string `json:",omitempty"`
	Truncated   bool   `json:",omitempty"`
	Referral    bool   `json:",omitempty"`

	// Only present if CacheHit == false
	NS *Nameserver `json:",omitempty"`

	Composites []*QueryLog `json:",omitempty"`
}

// LookupLog describes a iterative resolution
type LookupLog struct {
	Query       *Question
	DNSSECValid bool
	Started     time.Time
	Latency     time.Duration
	Rcode       uint16

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

// Nameserver describes a upstream authoritative nameserver
type Nameserver struct {
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
	rootNameservers []Nameserver
}

// NewRecursiveResolver returns an initialized RecursiveResolver. If cache is nil
// answers won't be cached.
func NewRecursiveResolver(useIPv6 bool, useDNSSEC bool, rootHints []dns.RR, rootKeys []dns.RR, cache QuestionAnswerCache) *RecursiveResolver {
	rr := &RecursiveResolver{
		useIPv6:   useIPv6,
		useDNSSEC: useDNSSEC,
		c:         new(dns.Client),
		cache:     cache,
	}
	// Initialize root nameservers
	addrs := extractRRSet(rootHints, "", dns.TypeA)
	if useIPv6 {
		addrs = append(addrs, extractRRSet(rootHints, "", dns.TypeAAAA)...)
	}
	for _, a := range addrs {
		switch r := a.(type) {
		case *dns.A:
			rr.rootNameservers = append(rr.rootNameservers, Nameserver{a.Header().Name, r.A.String(), "."})
		case *dns.AAAA:
			rr.rootNameservers = append(rr.rootNameservers, Nameserver{a.Header().Name, r.AAAA.String(), "."})
		}
	}
	// Add root DNSSEC keys to cache indefinitely
	if rr.cache != nil {
		rr.cache.Add(&Question{Name: ".", Type: dns.TypeDNSKEY}, &Answer{rootKeys, nil, nil, dns.RcodeSuccess, true}, true)
	}
	return rr
}

func (rr *RecursiveResolver) query(ctx context.Context, q *Question, auth *Nameserver) (*dns.Msg, *QueryLog, error) {
	ql := &QueryLog{Query: q, NS: auth}
	s := time.Now()
	defer func() { ql.Latency = time.Since(s) }()
	m := new(dns.Msg)
	m.SetEdns0(4096, rr.useDNSSEC)
	m.Question = []dns.Question{{Name: q.Name, Qtype: q.Type, Qclass: dns.ClassINET}}
	if rr.cache != nil {
		if answer := rr.cache.Get(q); answer != nil {
			m.Rcode = dns.RcodeSuccess
			m.Answer = answer.Answer
			m.Ns = answer.Authority
			m.Extra = answer.Additional
			ql.CacheHit = true
			ql.NS = nil
			ql.DNSSECValid = answer.Authenticated
			ql.Rcode = dns.RcodeSuccess
			return m, ql, nil
		}
	}
	r, _, err := rr.c.Exchange(m, net.JoinHostPort(auth.Addr, dnsPort))
	if err != nil {
		return nil, ql, err
	}
	ql.Rcode = r.Rcode

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

func (rr *RecursiveResolver) lookupNS(ctx context.Context, name string) (*Nameserver, error) {
	// BUG(roland): LookupLog for lookupNS calls isn't included in parent chain
	// BUG(roland): There is no maximum depth to Lookup -> lookupNS -> Lookup calls, looping is possible
	// BUG(roland): I'm not sure how the lookup of a NS addr should be taken into account in terms of the
	//              dnssec chain
	r, _, err := rr.Lookup(ctx, Question{Name: name, Type: dns.TypeA})
	if err != nil {
		return nil, err
	}
	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("Authority lookup failed for %s: %s", name, dns.RcodeToString[r.Rcode])
	}
	if len(r.Answer) == 0 {
		return nil, ErrNoAuthorityAddress
	}
	addresses := extractRRSet(r.Answer, name, dns.TypeA)
	if len(addresses) == 0 {
		return nil, ErrNoAuthorityAddress
	}
	return &Nameserver{Name: name, Addr: addresses[mrand.Intn(len(addresses))].(*dns.A).A.String()}, nil // ewwww
}

func (rr *RecursiveResolver) pickAuthority(ctx context.Context, auths []dns.RR, extras []dns.RR) (*Nameserver, error) {
	zones, _, nsToZone := splitAuthsByZone(auths, extras, rr.useIPv6)
	if len(zones) == 0 {
		if len(nsToZone) == 0 {
			return nil, ErrNoNSAuthorties
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
			return &Nameserver{ns, zones[z][mrand.Intn(len(zones[z]))], z}, nil
		}
	}
	return nil, ErrNoNSAuthorties
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

// Lookup a Question iteratively. All upstream responses are validated
// and a DNSSEC chain is built if the RecursiveResolver was initialized to do so.
// If responses are found in the underlying cache they will be used instead of
// sending messages to remote nameservers.
func (rr *RecursiveResolver) Lookup(ctx context.Context, q Question) (*Answer, *LookupLog, error) {
	ll := &LookupLog{Query: &q, Started: time.Now()}

	authority := &rr.rootNameservers[mrand.Intn(len(rr.rootNameservers))]

	defer func() {
		ll.Latency = time.Since(ll.Started)
	}()

	var parentDSSet []dns.RR
	for i := 0; i < MaxReferrals; i++ {
		r, log, err := rr.query(ctx, &q, authority)
		ll.Composites = append(ll.Composites, log)
		if err != nil && err != dns.ErrTruncated { // if truncated still try...
			log.Error = err.Error()
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
				log.Error = err.Error()
				return nil, ll, err
			}
			validated = true
		}
		log.DNSSECValid = validated
		ll.DNSSECValid = validated

		if r.Rcode != dns.RcodeSuccess {
			// BUG(roland): This should be moved into checkDNSKEY (which needs a better name...)
			if r.Rcode == dns.RcodeNameError {
				// checkNSEC3NXDOMAIN()
				denialSet := extractAndMapRRSet(r.Ns, "", dns.TypeNSEC, dns.TypeNSEC3)
				var nsecSet []dns.RR
				switch {
				case len(denialSet[dns.TypeNSEC]) > 0 && len(denialSet[dns.TypeNSEC3]) > 0:
					// weird?
					return nil, ll, errors.New("bad")
				case len(denialSet[dns.TypeNSEC]) > 0:
					nsecSet = denialSet[dns.TypeNSEC]
				case len(denialSet[dns.TypeNSEC3]) > 0:
					nsecSet = denialSet[dns.TypeNSEC3]
				}
				// ???
				if len(nsecSet) != 0 {
					err = verifyNODATA(&q, nsecSet)
					if err != nil {
						log.Error = err.Error()
						return nil, ll, err
					}
				}
			}
			return extractAnswer(r, validated), ll, nil
		}

		// good response
		if len(r.Answer) > 0 {
			// BUG(roland): if after stripping dnssec records the only remaining record is a CNAME and the
			//              question type wasn't CNAME then the alias should be chased
			if !log.CacheHit {
				if rr.cache != nil {
					go rr.cache.Add(&q, &Answer{r.Answer, r.Ns, r.Extra, r.Rcode, validated}, false)
				}
			}

			// check for alias and chase or do that in RecursiveResolver.query?
			return extractAnswer(r, validated), ll, nil
		}

		// NODATA validation
		// BUG(roland): This catches referrals :/
		if len(r.Answer) == 0 {
			// BUG(roland): This should be moved into checkDNSKEY maybe?
			if len(r.Ns) > 0 {
				denialSet := extractAndMapRRSet(r.Ns, "", dns.TypeNSEC, dns.TypeNSEC3)
				var nsecSet []dns.RR
				switch {
				case len(denialSet[dns.TypeNSEC]) > 0 && len(denialSet[dns.TypeNSEC3]) > 0:
					// weird?
					return nil, ll, errors.New("bad")
				case len(denialSet[dns.TypeNSEC]) > 0:
					nsecSet = denialSet[dns.TypeNSEC]
				case len(denialSet[dns.TypeNSEC3]) > 0:
					nsecSet = denialSet[dns.TypeNSEC3]
				}
				// ???
				if len(nsecSet) != 0 {
					err = verifyNODATA(&q, nsecSet)
					if err != nil {
						log.Error = err.Error()
						return nil, ll, err
					}
				}
			}
		}

		// referral response
		if len(r.Ns) > 0 {
			log.Referral = true
			// BUG(roland): NSEC DS delegation denials aren't checked
			authority, err = rr.pickAuthority(ctx, r.Ns, r.Extra)
			if err != nil {
				log.Error = err.Error()
				return nil, ll, err
			}
			if i == 0 || len(parentDSSet) > 0 {
				parentDSSet = extractRRSet(r.Ns, authority.Zone, dns.TypeDS)
			}
			continue
		}

		// useless response...
		return nil, ll, errors.New("No authority or additional records! IDK") // ???
	}
	return nil, ll, ErrTooManyReferrals
}

func extractRRSet(in []dns.RR, name string, t ...uint16) []dns.RR {
	out := []dns.RR{}
	tMap := make(map[uint16]struct{}, len(t))
	for _, t := range t {
		tMap[t] = struct{}{}
	}
	for _, r := range in {
		if _, present := tMap[r.Header().Rrtype]; present {
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

func rrsetContains(rrset []dns.RR, rrtype uint16) bool {
	for _, r := range rrset {
		if r.Header().Rrtype == rrtype {
			return true
		}
	}
	return false
}
