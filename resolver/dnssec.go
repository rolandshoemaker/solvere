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

func (rr *RecursiveResolver) lookupDNSKEY(ctx context.Context, name string, keytag uint16, auth string) (map[uint16]*dns.DNSKEY, error) {
	r, err := rr.query(ctx, dns.Question{Name: name, Qtype: dns.TypeDNSKEY, Qclass: dns.ClassINET}, auth, true)
	if err != nil {
		return nil, err
	}
	if len(r.Answer) == 0 {
		return nil, errNoDNSKEY
	}
	// var ksk *dns.DNSKEY
	keyMap := make(map[uint16]*dns.DNSKEY, len(r.Answer))
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
		return nil, errNoDNSKEY
	}
	// if ksk == nil {
	// 	return nil, errNoDNSKEY // actually no ksk
	// }
	// cannot check key has signed key it seems...
	// for _, k range := zskMap {
	//
	// }
	if err = rr.verifyRRSIG(ctx, name, r.Answer, auth, keyMap); err != nil {
		return nil, err
	}
	return keyMap, nil
}

func (rr *RecursiveResolver) verifyRRSIG(ctx context.Context, name string, answer []dns.RR, auth string, keyMap map[uint16]*dns.DNSKEY) error {
	var sig *dns.RRSIG
	var rest []dns.RR
	for _, r := range answer {
		if sig == nil && r.Header().Rrtype == dns.TypeRRSIG {
			sig = r.(*dns.RRSIG)
		} else {
			rest = append(rest, r)
		}
	}
	if sig == nil {
		return nil
	}
	if keyMap == nil {
		km, err := rr.lookupDNSKEY(ctx, name, sig.KeyTag, auth)
		if err != nil {
			return err
		}
		keyMap = km
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
	return nil
}
