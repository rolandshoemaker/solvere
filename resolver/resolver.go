package resolver

import (
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	mrand "math/rand"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/context"
)

var (
	maxReferrals = 10

	dnsPort = "53"

	errTooManyReferrals   = errors.New("Too many referrals")
	errNoNSAuthorties     = errors.New("No NS authority records found")
	errNoAuthorityAddress = errors.New("No A/AAAA records found for the chosen authority")
)

type queryLog struct {
	Query       *dns.Question
	AnswerType  string
	CacheHit    bool `json:",omitempty"`
	DNSSECValid bool
	Latency     time.Duration
	Error       error `json:",omitempty"`
	Truncated   bool  `json:",omitempty"`

	// Only present if CacheHit == false
	NS *rootNS

	Composites []queryLog `json:",omitempty"`
}

type lookupLog struct {
	Query      *dns.Question
	Started    time.Time
	Latency    time.Duration
	Composites []queryLog
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

type Answer struct {
	Answer     []dns.RR
	Authority  []dns.RR
	Additional []dns.RR
	Rcode      int
}

type rootNS struct {
	Name string
	Addr string
	Zone string
}

type RecursiveResolver struct {
	useIPv6   bool
	useDNSSEC bool

	c *dns.Client

	qac             *qaCache
	rootNameservers []rootNS
}

func NewRecursiveResolver(useIPv6 bool, useDNSSEC bool, rootHints []dns.RR, rootKeys []dns.RR) *RecursiveResolver {
	rr := &RecursiveResolver{
		useIPv6:   useIPv6,
		useDNSSEC: useDNSSEC,
		c:         new(dns.Client),
		qac:       &qaCache{cache: make(map[[sha1.Size]byte]*cacheEntry)},
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
	rr.qac.add(&dns.Question{Name: ".", Qtype: dns.TypeDNSKEY, Qclass: dns.ClassINET}, rootKeys, nil, nil, true, true)
	return rr
}

func (rr *RecursiveResolver) query(ctx context.Context, q dns.Question, auth *rootNS) (*dns.Msg, queryLog, error) {
	ql := queryLog{Query: &q, NS: auth}
	s := time.Now()
	m := new(dns.Msg)
	m.SetEdns0(4096, rr.useDNSSEC)
	m.Question = []dns.Question{q}
	if answer, present := rr.qac.get(&q); present {
		m.Rcode = dns.RcodeSuccess
		m.Answer = answer
		ql.CacheHit = true
		ql.Latency = time.Since(s)
		return m, ql, nil
	}
	r, _, err := rr.c.Exchange(m, net.JoinHostPort(auth.Addr, dnsPort))
	if err != nil {
		ql.Latency = time.Since(s)
		return nil, ql, err
	}

	// check all returned records are in-bailiwick, ignore extra section?
	for _, section := range [][]dns.RR{r.Answer, r.Ns} {
		for _, record := range section {
			if record.Header().Rrtype != dns.TypeOPT && !strings.HasSuffix(record.Header().Name, auth.Zone) {
				ql.Latency = time.Since(s)
				return nil, ql, errors.New("Out of bailiwick record in message") // or just strip invalid records...?
			}
		}
	}

	ql.Latency = time.Since(s)
	return r, ql, nil
}

func (rr *RecursiveResolver) lookupHost(ctx context.Context, name string) (*rootNS, error) {
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
	// go func() {
	// 	for z, a := range zones {
	// 		if len(a) > 0 {
	// 			rr.ac.add(z, a, minTTLs[z])
	// 		}
	// 	}
	// }()
	if len(zones) == 0 {
		if len(nsToZone) == 0 {
			return nil, errNoNSAuthorties
		}
		var ns, z string
		for ns, z = range nsToZone {
			break
		}
		a, err := rr.lookupHost(ctx, ns)
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

func extractAnswer(m *dns.Msg) *Answer {
	return &Answer{
		Answer:     m.Answer,
		Authority:  m.Ns,
		Additional: m.Extra,
		Rcode:      m.Rcode,
	}
}

func (rr *RecursiveResolver) Lookup(ctx context.Context, q dns.Question) (*Answer, lookupLog, error) {
	ll := lookupLog{Query: &q, Started: time.Now()}

	authority := &rr.rootNameservers[mrand.Intn(len(rr.rootNameservers))]

	defer func() {
		ll.Latency = time.Since(ll.Started)
		j, err := json.Marshal(ll)
		if err != nil {
			fmt.Println("err encoding log message")
		}
		fmt.Println(string(j))
	}()

	var parentDSSet []dns.RR
	for i := 0; i < maxReferrals; i++ {
		r, log, err := rr.query(ctx, q, authority)
		defer func() { ll.Composites = append(ll.Composites, log) }()
		if err != nil && err != dns.ErrTruncated { // if truncated still try...
			log.Error = err
			return nil, ll, err
		} else if err == dns.ErrTruncated {
			log.Truncated = true
		}

		// validate
		validated := false
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

		if r.Rcode != dns.RcodeSuccess {
			log.AnswerType = dns.RcodeToString[r.Rcode]
			return extractAnswer(r), ll, nil
		}

		// good response
		if len(r.Answer) > 0 {
			// cache
			if !log.CacheHit {
				go rr.qac.add(&q, r.Answer, r.Ns, r.Extra, validated, false)
			}

			log.AnswerType = "Success"
			// check for alias and chase or do that in RecursiveResolver.query?
			return extractAnswer(r), ll, nil
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
