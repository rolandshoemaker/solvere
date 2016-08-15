package resolver

import (
	"errors"
	"fmt"
	mrand "math/rand"
	"net"

	"github.com/miekg/dns"
	"golang.org/x/net/context"
	"golang.org/x/net/trace"
)

var (
	// these should be parsed from a hints file!
	rootNames = []dns.RR{
		&dns.NS{Hdr: dns.RR_Header{Rrtype: dns.TypeNS}, Ns: "A.ROOT-SERVERS.NET"},
	}
	rootAddrs = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "A.ROOT-SERVERS.NET", Rrtype: dns.TypeA}, A: net.ParseIP("198.41.0.4")},
	}

	maxIterations = 10

	dnsPort = "53"

	errTooManyIterations  = errors.New("Too many iterations")
	errNoNSAuthorties     = errors.New("No NS authority records found")
	errNoAuthorityAddress = errors.New("No A/AAAA records found for the chosen authority")
)

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

type RecursiveResolver struct {
	useIPv6   bool
	useDNSSEC bool

	c *dns.Client
}

func NewRecursiveResolver(useIPv6 bool, useDNSSEC bool) *RecursiveResolver {
	return &RecursiveResolver{
		useIPv6:   useIPv6,
		useDNSSEC: useDNSSEC,
		c:         new(dns.Client),
	}
}

func (rr *RecursiveResolver) query(ctx context.Context, q dns.Question, auth string, dontVerifySig bool) (*dns.Msg, error) {
	tr := trace.New("resolver-query", fmt.Sprintf("%s -> %s", q.String(), auth))
	defer tr.Finish()
	fmt.Printf(
		"Request %s: sending '%s %s %s' to %s\n",
		ctx.Value("request-id"),
		q.Name,
		dns.ClassToString[q.Qclass],
		dns.TypeToString[q.Qtype],
		auth,
	)
	m := new(dns.Msg)
	m.SetEdns0(4096, rr.useDNSSEC)
	m.Question = []dns.Question{q}
	r, _, err := rr.c.Exchange(m, net.JoinHostPort(auth, dnsPort))
	if err != nil {
		tr.SetError()
		return nil, err
	}
	if !dontVerifySig && rr.useDNSSEC {
		for _, section := range [][]dns.RR{r.Answer, r.Ns, r.Extra} {
			km := make(map[uint16]*dns.DNSKEY)
			if err = rr.verifyRRSIG(ctx, q.Name, section, auth, km); err != nil {
				return nil, err
			}
		}
	}
	return r, nil
}

func (rr *RecursiveResolver) lookupHost(ctx context.Context, name string) (string, error) {
	// XXX: this should prob take into account the parent iterations...?
	// XXX: this should do parallel v4/v6 lookups if a v6 stack is supported
	r, err := rr.Lookup(ctx, dns.Question{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET})
	if err != nil {
		return "", err
	}
	if r.Rcode != dns.RcodeSuccess {
		return "", fmt.Errorf("Authority lookup failed for %s: %s", name, dns.RcodeToString[r.Rcode])
	}
	if len(r.Answer) == 0 {
		return "", errNoAuthorityAddress
	}
	addresses := []string{}
	for _, a := range r.Answer {
		if a.Header().Rrtype == dns.TypeA {
			addr := a.(*dns.A)
			addresses = append(addresses, addr.A.String())
		}
	}
	if len(addresses) == 0 {
		return "", errNoAuthorityAddress
	}
	return addresses[mrand.Intn(len(addresses))], nil
}

// this seems horribly inefficient, should be re-written..!
func (rr *RecursiveResolver) pickAuthority(ctx context.Context, auths []dns.RR, extras []dns.RR) (string, error) {
	nameservers := []string{}
	for _, a := range auths {
		if a.Header().Rrtype == dns.TypeNS {
			ns := a.(*dns.NS)
			nameservers = append(nameservers, ns.Ns)
		}
	}
	if len(nameservers) == 0 {
		return "", errNoNSAuthorties
	} else if len(extras) == 0 {
		return rr.lookupHost(ctx, nameservers[mrand.Intn(len(nameservers))])
	}
	// do a quick cache lookup first?
	for i := 0; i < len(nameservers); i++ {
		ra := nameservers[mrand.Intn(len(nameservers))]
		for _, addr := range extras {
			if addr.Header().Name == ra && (addr.Header().Rrtype == dns.TypeA || (rr.useIPv6 && addr.Header().Rrtype == dns.TypeAAAA)) {
				switch r := addr.(type) {
				case *dns.A:
					return r.A.String(), nil
				case *dns.AAAA:
					if rr.useIPv6 {
						return r.AAAA.String(), nil
					}
				}
			}
		}
	}
	// blergh
	return rr.lookupHost(ctx, nameservers[mrand.Intn(len(nameservers))])
}

func extractAnswer(m *dns.Msg) *Answer {
	return &Answer{
		Answer:     m.Answer,
		Authority:  m.Ns,
		Additional: m.Extra,
		Rcode:      m.Rcode,
	}
}

func (rr *RecursiveResolver) Lookup(ctx context.Context, q dns.Question) (*Answer, error) {
	authority, err := rr.pickAuthority(ctx, rootNames, rootAddrs)
	if err != nil {
		return nil, err
	}

	for i := 0; i < maxIterations; i++ {
		r, err := rr.query(ctx, q, authority, false)
		if err != nil && err != dns.ErrTruncated { // if truncated still try...
			return nil, err
		} else if err == dns.ErrTruncated {
			// log it
		}

		if r.Rcode != dns.RcodeSuccess {
			return extractAnswer(r), nil
		}

		// good response
		if len(r.Answer) > 0 {
			// if len(r.Answer) == 1 {
			// check for alias and chase?
			// }
			return extractAnswer(r), nil
		}

		// referral
		if len(r.Ns) > 0 { // XXX: if extra is 0 this should lookup the addr itself... (how?)
			// randomly pick a authority (or something more complicated) and repeat the query.
			authority, err = rr.pickAuthority(ctx, r.Ns, r.Extra)
			if err != nil {
				return nil, err
			}
			continue
		}
		return nil, errors.New("No authority or additional records! IDK") // ???
	}
	return nil, errTooManyIterations
}
