package resolver

import (
	"errors"
	// "fmt"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/context"
)

var (
	errNoDNSKEY               = errors.New("No DNSKEY records found")
	errInvalidSignaturePeriod = errors.New("Incorrect signature validity period")
)

func (rr *RecursiveResolver) lookupDNSKEY(ctx context.Context, keyMap map[uint16]*dns.DNSKEY, name string, keytag uint16, auth string) error {
	r, err := rr.query(ctx, dns.Question{Name: name, Qtype: dns.TypeDNSKEY, Qclass: dns.ClassINET}, auth, true)
	if err != nil {
		return err
	}
	if len(r.Answer) == 0 {
		return errNoDNSKEY
	}
	// var ksk *dns.DNSKEY
	for _, a := range r.Answer {
		if a.Header().Rrtype == dns.TypeDNSKEY {
			dnskey := a.(*dns.DNSKEY)
			keyMap[dnskey.KeyTag()] = dnskey
			// if dnskey.Flags == 257 {
			// 	ksk = dnskey
			// }
		}
	}
	if len(keyMap) == 0 {
		return errNoDNSKEY
	}
	// if ksk == nil {
	// 	return nil, errNoDNSKEY // actually no ksk
	// }
	for _, section := range [][]dns.RR{r.Answer, r.Ns, r.Extra} {
		if err = rr.verifyRRSIG(ctx, name, section, auth, keyMap); err != nil {
			return err
		}
	}
	return nil
}

func (rr *RecursiveResolver) verifyRRSIG(ctx context.Context, name string, answer []dns.RR, auth string, keyMap map[uint16]*dns.DNSKEY) error {
	if len(answer) == 0 {
		return nil
	}
	sigs := extractRRSet(answer, dns.TypeRRSIG, "")
	if len(sigs) == 0 {
		return nil
	}
	for _, sigRR := range sigs {
		sig := sigRR.(*dns.RRSIG)
		rest := extractRRSet(answer, sig.TypeCovered, sig.Header().Name)
		if len(keyMap) == 0 {
			var err error
			err = rr.lookupDNSKEY(ctx, keyMap, sig.SignerName, sig.KeyTag, auth)
			if err != nil {
				return err
			}
		}
		k, present := keyMap[sig.KeyTag]
		if !present {
			return errNoDNSKEY
		}
		err := sig.Verify(k, rest)
		if err != nil {
			return err
		}
		if !sig.ValidityPeriod(time.Time{}) {
			return errInvalidSignaturePeriod
		}
	}
	return nil
}
