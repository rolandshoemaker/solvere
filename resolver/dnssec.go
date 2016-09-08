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
	errMissingKSK             = errors.New("No KSK DNSKEY found for DS records")
	errFailedToConvertKSK     = errors.New("Failed to convert KSK DNSKEY record to DS record")
	errMismatchingDS          = errors.New("KSK DNSKEY record does not match DS record from parent zone")
	errNoSignatures           = errors.New("No RRSIG records for zone that should be signed")
	errMissingDNSKEY          = errors.New("No matching DNSKEY found for RRSIG records")
	errInvalidSignaturePeriod = errors.New("Incorrect signature validity period")
)

func (rr *RecursiveResolver) checkDNSKEY(ctx context.Context, m *dns.Msg, zone, auth string, parentDSSet []dns.RR) error {
	zskMap, kskMap := make(map[uint16]*dns.DNSKEY), make(map[uint16]*dns.DNSKEY)
	q := dns.Question{Name: zone, Qtype: dns.TypeDNSKEY, Qclass: dns.ClassINET}
	r, _, err := rr.query(ctx, q, auth, zone)
	if err != nil {
		return err
	}
	if len(r.Answer) == 0 {
		return errNoDNSKEY
	}
	for _, a := range r.Answer {
		if a.Header().Rrtype == dns.TypeDNSKEY {
			dnskey := a.(*dns.DNSKEY)
			tag := dnskey.KeyTag()
			if dnskey.Flags == 256 {
				zskMap[tag] = dnskey
			} else if dnskey.Flags == 257 {
				kskMap[tag] = dnskey
			}
		}
	}
	if len(kskMap) == 0 || len(zskMap) == 0 {
		return errNoDNSKEY
	}

	err = rr.verifyRRSIG(m, zskMap)
	if err != nil {
		return err
	}

	if len(parentDSSet) > 0 {
		err = rr.verifyRRSIG(r, kskMap)
		if err != nil {
			return err
		}
		err = rr.checkDS(kskMap, parentDSSet)
		if err != nil {
			return err
		}
	}
	go rr.qac.add(&q, r.Answer, r.Ns, r.Extra, true, false)

	return nil
}

func (rr *RecursiveResolver) checkDS(kskMap map[uint16]*dns.DNSKEY, parentDSSet []dns.RR) error {
	for _, r := range parentDSSet {
		parentDS := r.(*dns.DS)
		ksk, present := kskMap[parentDS.KeyTag]
		if !present {
			continue
		}
		ds := ksk.ToDS(parentDS.DigestType)
		if ds == nil {
			return errFailedToConvertKSK
		}
		if ds.Digest != parentDS.Digest {
			return errMismatchingDS
		}
		return nil
	}
	return errMissingKSK
}

func (rr *RecursiveResolver) verifyRRSIG(msg *dns.Msg, keyMap map[uint16]*dns.DNSKEY) error {
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns} {
		if len(section) == 0 {
			continue
		}
		sigs := extractRRSet(section, dns.TypeRRSIG, "")
		if len(sigs) == 0 {
			return errNoSignatures
		}
		for _, sigRR := range sigs {
			sig := sigRR.(*dns.RRSIG)
			rest := extractRRSet(section, sig.TypeCovered, sig.Header().Name)
			k, present := keyMap[sig.KeyTag]
			if !present {
				return errMissingDNSKEY
			}
			err := sig.Verify(k, rest)
			if err != nil {
				return err
			}
			if !sig.ValidityPeriod(time.Time{}) {
				return errInvalidSignaturePeriod
			}
		}
	}
	return nil
}
