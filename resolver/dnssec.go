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
	errBadAnswer              = errors.New("Query response returned a none Success (0) RCODE")
)

func (rr *RecursiveResolver) checkDNSKEY(ctx context.Context, m *dns.Msg, auth *rootNS, parentDSSet []dns.RR) (*QueryLog, error) {
	q := dns.Question{Name: auth.Zone, Qtype: dns.TypeDNSKEY, Qclass: dns.ClassINET}
	r, log, err := rr.query(ctx, q, auth)
	if err != nil {
		return log, err
	}

	if len(r.Answer) == 0 {
		log.AnswerType = "Failure"
		return log, errNoDNSKEY
	} else if r.Rcode != dns.RcodeSuccess {
		log.AnswerType = dns.RcodeToString[r.Rcode]
		return log, errBadAnswer
	}

	zskMap, kskMap := make(map[uint16]*dns.DNSKEY), make(map[uint16]*dns.DNSKEY)
	// Extract DNSKEYs based on type
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
	log.AnswerType = "Success"

	// To verify both the DNSKEY message and the passed in message
	// we need both KSK and ZSK keys
	if len(kskMap) == 0 || len(zskMap) == 0 {
		return log, errNoDNSKEY
	}

	// Verify DNSKEY RRSIG using the ZSK keys
	err = rr.verifyRRSIG(m, zskMap)
	if err != nil {
		return log, err
	}

	// The only time this should be false is if the zone == .
	if len(parentDSSet) > 0 {
		// Verify RRSIGs from the message passed in using the KSK keys
		err = rr.verifyRRSIG(r, kskMap)
		if err != nil {
			return log, err
		}
		// Make sure the parent DS record matches one of the KSK DNSKEYS
		err = rr.checkDS(kskMap, parentDSSet)
		if err != nil {
			return log, err
		}
	}

	log.DNSSECValid = true

	// Only add response to cache if it wasn't a cache hit
	if !log.CacheHit {
		go rr.cache.Add(&q, r.Answer, r.Ns, r.Extra, true, false)
	}

	return log, nil
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
