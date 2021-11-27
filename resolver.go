// Package solvere provides an implementation of a recursive, validating, DNSSEC aware DNS resolver, and
// a basic question and answer cache implementation.
package solvere

import (
	"bytes"
	"context"
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
)

func init() {
	// Initialize math/rand with 8 bytes from crypto/rand so the randomness
	// isn't _super_ terrible
	b := [8]byte{}
	_, err := rand.Read(b[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "solvere: Failed to read bytes for PSRNG initialization: %s\n", err)
		return
	}
	i, err := binary.ReadVarint(bytes.NewBuffer(b[:]))
	if err != nil {
		fmt.Fprintf(os.Stderr, "solvere: Failed to read bytes for PSRNG initialization: %s\n", err)
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
	ErrOutOfBailiwick     = errors.New("Out of bailiwick record in message")
)

// Question represents a DNS IN question
type Question struct {
	Name string
	Type uint16
}

// LookupLog describes how a resolution was performed
type LookupLog struct {
	Query       *Question
	Rcode       int
	CacheHit    bool `json:",omitempty"`
	DNSSECValid bool
	Latency     time.Duration
	Error       string `json:",omitempty"`
	Truncated   bool   `json:",omitempty"`
	Referral    bool   `json:",omitempty"`
	Started     time.Time

	NS *Nameserver `json:",omitempty"`

	Composites []*LookupLog `json:",omitempty"`
}

func newLookupLog(q *Question, ns *Nameserver) *LookupLog {
	return &LookupLog{
		Query:   q,
		NS:      ns,
		Started: time.Now(),
	}
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

// Nameserver describes an authoritative nameserver
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
	// XXX: if these keys are expired (how to tell?) should block on fetching
	//      new ones + verifying the roll-over
	if rr.cache != nil {
		rr.cache.Add(&Question{Name: ".", Type: dns.TypeDNSKEY}, &Answer{rootKeys, nil, nil, dns.RcodeSuccess, true}, true)
	}
	return rr
}

func (rr *RecursiveResolver) query(ctx context.Context, q *Question, auth *Nameserver) (*dns.Msg, *LookupLog, error) {
	ql := newLookupLog(q, auth)
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
	r, _, err := rr.c.ExchangeContext(ctx, m, net.JoinHostPort(auth.Addr, dnsPort))
	if err != nil {
		return nil, ql, err
	}
	ql.Rcode = r.Rcode

	// check all returned records are in-bailiwick, ignore extra section?
	for _, section := range [][]dns.RR{r.Answer, r.Ns} {
		for _, record := range section {
			if record.Header().Rrtype != dns.TypeOPT && !strings.HasSuffix(record.Header().Name, auth.Zone) {
				return nil, ql, ErrOutOfBailiwick // XXX: or just strip invalid records...?
			}
		}
	}
	return r, ql, nil
}

func (rr *RecursiveResolver) lookupNS(ctx context.Context, name string) (*Nameserver, *LookupLog, error) {
	// XXX: There is no maximum depth to Lookup -> lookupNS -> Lookup calls, looping is possible
	// XXX: I'm not sure how the lookup of a NS addr should be taken into account in terms of the
	//      dnssec chain (probably if not signed the chain cannot be considered authenticated?)
	r, log, err := rr.Lookup(ctx, Question{Name: name, Type: dns.TypeA})
	if err != nil {
		return nil, log, err
	}
	if r.Rcode != dns.RcodeSuccess {
		return nil, log, fmt.Errorf("Authority lookup failed for %s: %s", name, dns.RcodeToString[r.Rcode])
	}
	if len(r.Answer) == 0 {
		return nil, log, ErrNoAuthorityAddress
	}
	addresses := extractRRSet(r.Answer, name, dns.TypeA)
	if len(addresses) == 0 {
		return nil, log, ErrNoAuthorityAddress
	}
	return &Nameserver{Name: name, Addr: addresses[mrand.Intn(len(addresses))].(*dns.A).A.String()}, log, nil
}

func splitAuthsByZone(auths []dns.RR, extras []dns.RR, useIPv6 bool) (map[string][]string, map[string]string) {
	zones := make(map[string][]string)
	nsToZone := make(map[string]string)

	for _, rr := range auths {
		if rr.Header().Rrtype == dns.TypeNS {
			ns := rr.(*dns.NS)
			nsToZone[ns.Ns] = rr.Header().Name
		}
	}

	for _, rr := range extras {
		zone, present := nsToZone[rr.Header().Name]
		if present && (rr.Header().Rrtype == dns.TypeA || (useIPv6 && rr.Header().Rrtype == dns.TypeAAAA)) {
			switch a := rr.(type) {
			case *dns.A:
				zones[zone] = append(zones[zone], a.A.String())
			case *dns.AAAA:
				if useIPv6 {
					zones[zone] = append(zones[zone], a.AAAA.String())
				}
			}
		}
	}

	return zones, nsToZone
}

func (rr *RecursiveResolver) pickAuthority(ctx context.Context, auths []dns.RR, extras []dns.RR) (*Nameserver, *LookupLog, error) {
	// XXX: this ignores general concept of an 'infrastructure' cache which
	//      tracks authority performance and uses it as a metric to pick a
	//      authority. may want to get fancier at some point...
	zones, nsToZone := splitAuthsByZone(auths, extras, rr.useIPv6)
	if len(zones) == 0 {
		if len(nsToZone) == 0 {
			return nil, nil, ErrNoNSAuthorties
		}
		var ns, z string
		// abuse how ranging over maps works to select a 'random' element
		for ns, z = range nsToZone {
			break
		}
		a, log, err := rr.lookupNS(ctx, ns)
		if err != nil {
			return nil, log, err
		}
		a.Zone = z
		return a, log, nil
	}
	// abuse how ranging over maps works to select a 'random' element
	for ns, z := range nsToZone {
		if len(zones[z]) > 0 {
			return &Nameserver{ns, zones[z][mrand.Intn(len(zones[z]))], z}, nil, nil
		}
	}
	return nil, nil, ErrNoNSAuthorties
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

func allOfType(a []dns.RR, t uint16) bool {
	for _, rr := range a {
		if rr.Header().Rrtype != t {
			return false
		}
	}
	return true
}

func collapseCNAMEChain(qname string, in []dns.RR) (string, []dns.RR) {
	var chased []dns.RR
	cnameMap := make(map[string]*dns.CNAME, len(in))
	for _, rr := range in {
		cname := rr.(*dns.CNAME)
		cnameMap[cname.Hdr.Name] = cname
	}
	var canonical string
	for {
		c, ok := cnameMap[qname]
		if !ok {
			break
		}
		canonical = c.Target
		qname = canonical
		chased = append(chased, c)
	}
	return canonical, chased
}

const maxDomainLength = 256

var dnameTooLong = errors.New("DNAME substitution creates too long sname")

func isAlias(answer []dns.RR, q Question) (bool, string, []dns.RR, error) {
	filtered := filterRRSet(answer, dns.TypeRRSIG)
	if len(filtered) == 0 {
		return false, "", nil, nil
	}
	if len(filtered) > 1 {
		// check if answer is a CNAME chain that we can collapse
		if !allOfType(filtered, dns.TypeCNAME) || q.Type == dns.TypeCNAME {
			// Answer contains mixed records (malformed answer)
			// XXX: also possible this contains more than 1 DNAME, is
			//      that valid?
			// XXX: this breaks with a DNAME + synthesized CNAME...
			return false, "", nil, nil
		}
		sname, chased := collapseCNAMEChain(q.Name, filtered)
		return true, sname, chased, nil
	}
	switch alias := filtered[0].(type) {
	case *dns.CNAME:
		if q.Type == dns.TypeCNAME || q.Name != alias.Hdr.Name {
			return false, "", nil, nil
		}
		return true, alias.Target, []dns.RR{alias}, nil
	case *dns.DNAME:
		if q.Type == dns.TypeDNAME {
			return false, "", nil, nil
		}
		if !strings.HasSuffix(q.Name, alias.Hdr.Name) {
			return false, "", nil, nil
		}
		// XXX: check that substitution doesn't overflow legal length
		sname := strings.TrimSuffix(q.Name, alias.Hdr.Name) + alias.Target
		if len(sname) > maxDomainLength {
			return false, "", nil, dnameTooLong
		}
		return true, sname, []dns.RR{alias}, nil
	}
	return false, "", nil, nil
}

// Lookup a Question iteratively. All upstream responses are validated
// and a DNSSEC chain is built if the RecursiveResolver was initialized to do so.
// If responses are found in the question/answer cache they will be used instead
// of sending messages to remote nameservers.
func (rr *RecursiveResolver) Lookup(ctx context.Context, q Question) (*Answer, *LookupLog, error) {
	ll := newLookupLog(&q, nil)

	authority := &rr.rootNameservers[mrand.Intn(len(rr.rootNameservers))]

	defer func() {
		ll.Latency = time.Since(ll.Started)
	}()

	aliases := map[string]struct{}{}
	var chased []dns.RR
	var parentDSSet []dns.RR
	// XXX: This whole loop could be split off into its own function in order
	//      to pass through the i when we need to do things like lookupNS which
	//      are prone to infinitely looping
	for i := 0; i < MaxReferrals; i++ {
		r, log, err := rr.query(ctx, &q, authority)
		ll.Composites = append(ll.Composites, log)
		if err != nil { // if truncated still try...
			log.Error = err.Error()
			return nil, ll, err
		}

		if r.Truncated {
			log.Truncated = true
		}

		// validate
		validated := false
		if log.CacheHit {
			validated = log.DNSSECValid
		}
		if (i == 0 || len(parentDSSet) > 0) && !log.CacheHit {
			dkLog, err := rr.checkSignatures(ctx, r, authority, parentDSSet)
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
			// XXX: cache name error?
			if r.Rcode == dns.RcodeNameError {
				nsecSet := extractRRSet(r.Ns, "", dns.TypeNSEC3)
				if len(nsecSet) != 0 { // if the zone is signed and this is missing its a failure...
					err = verifyNameError(&q, nsecSet)
					if err != nil {
						log.Error = err.Error()
						log.DNSSECValid = false
						ll.DNSSECValid = false
						return nil, ll, err
					}
				}
			}
			return extractAnswer(r, validated), ll, nil
		}

		// good response
		if len(r.Answer) > 0 {
			if ok, canonicalName, chasedRR, err := isAlias(r.Answer, q); ok {
				if _, ok := aliases[canonicalName]; ok {
					err = errors.New("Alias loop detected, aborting")
					log.Error = err.Error()
					return nil, ll, err
				}
				aliases[canonicalName] = struct{}{}

				authority = &rr.rootNameservers[mrand.Intn(len(rr.rootNameservers))]
				q.Name = canonicalName
				chased = append(chased, chasedRR...)
				// XXX: cache alias answer
				continue
			} else if err != nil {
				log.Error = err.Error()
				return nil, ll, err
			}
			if !log.CacheHit && rr.cache != nil {
				go rr.cache.Add(&q, &Answer{r.Answer, r.Ns, r.Extra, r.Rcode, validated}, false)
			}

			if len(chased) > 0 {
				// put aliases at the front of the answer
				r.Answer = append(chased, r.Answer...)
			}
			return extractAnswer(r, validated), ll, nil
		}

		nsecSet := extractRRSet(r.Ns, "", dns.TypeNSEC3)

		// NODATA response
		if len(r.Ns) == 0 || len(nsecSet) == len(r.Ns) {
			if len(nsecSet) != 0 {
				// check for proper coverage
				err = verifyNODATA(&q, nsecSet)
				if err != nil {
					log.Error = err.Error()
					log.DNSSECValid = false
					ll.DNSSECValid = false
					return nil, ll, err
				}
			}
			// ignore anything in additional section (?)
			return &Answer{Rcode: dns.RcodeSuccess, Authenticated: validated}, ll, nil
		}

		// Referral response
		log.Referral = true
		var authLog *LookupLog
		authority, authLog, err = rr.pickAuthority(ctx, r.Ns, r.Extra)
		if authLog != nil {
			log.Composites = append(log.Composites, authLog)
		}
		if err != nil {
			log.Error = err.Error()
			return nil, ll, err
		}
		if len(nsecSet) != 0 {
			err = verifyDelegation(authority.Zone, nsecSet)
			if err != nil {
				log.Error = err.Error()
				log.DNSSECValid = false
				ll.DNSSECValid = false
				return nil, ll, err
			}
		} else if len(parentDSSet) > 0 {
			err := errors.New("unsigned delegation in signed zone without NSEC records")
			log.Error = err.Error()
			return nil, ll, err
		}
		if i == 0 || len(parentDSSet) > 0 {
			parentDSSet = extractRRSet(r.Ns, authority.Zone, dns.TypeDS)
		} else if i > 0 { // XXX: is this right?
			parentDSSet = nil
		}
	}
	return nil, ll, ErrTooManyReferrals
}

func filterRRSet(in []dns.RR, rrTypes ...uint16) []dns.RR {
	tMap := make(map[uint16]struct{}, len(rrTypes))
	for _, rrType := range rrTypes {
		tMap[rrType] = struct{}{}
	}
	out := []dns.RR{}
	for _, r := range in {
		if _, present := tMap[r.Header().Rrtype]; !present {
			out = append(out, r)
		}
	}
	return out
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
