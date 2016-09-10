package resolver

import (
	"errors"
	// "fmt"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/context"
)

var (
	ErrNoDNSKEY               = errors.New("solvere/resolver: No DNSKEY records found")
	ErrMissingKSK             = errors.New("solvere/resolver: No KSK DNSKEY found for DS records")
	ErrFailedToConvertKSK     = errors.New("solvere/resolver: Failed to convert KSK DNSKEY record to DS record")
	ErrMismatchingDS          = errors.New("solvere/resolver: KSK DNSKEY record does not match DS record from parent zone")
	ErrNoSignatures           = errors.New("solvere/resolver: No RRSIG records for zone that should be signed")
	ErrMissingDNSKEY          = errors.New("solvere/resolver: No matching DNSKEY found for RRSIG records")
	ErrInvalidSignaturePeriod = errors.New("solvere/resolver: Incorrect signature validity period")
	ErrBadAnswer              = errors.New("solvere/resolver: Query response returned a none Success (0) RCODE")
)

func (rr *RecursiveResolver) checkDNSKEY(ctx context.Context, m *dns.Msg, auth *Nameserver, parentDSSet []dns.RR) (*QueryLog, error) {
	q := &Question{Name: auth.Zone, Type: dns.TypeDNSKEY}
	r, log, err := rr.query(ctx, q, auth)
	if err != nil {
		return log, err
	}

	if len(r.Answer) == 0 {
		return log, ErrNoDNSKEY
	} else if r.Rcode != dns.RcodeSuccess {
		return log, ErrBadAnswer
	}

	keyMap := make(map[uint16]*dns.DNSKEY)
	// Extract DNSKEYs based on type
	for _, a := range r.Answer {
		if a.Header().Rrtype == dns.TypeDNSKEY {
			dnskey := a.(*dns.DNSKEY)
			tag := dnskey.KeyTag()
			// FUN STORY: some people don't respect what key types are supposed to mean
			// and as such they sometimes use a KSK to sign the zone or a ZSK to sign
			// a key. This means we can't do the nice thing of splitting keys by type
			// and must just stick them all in one map.
			if dnskey.Flags == 256 || dnskey.Flags == 257 {
				keyMap[tag] = dnskey
			}
		}
	}

	if len(keyMap) == 0 {
		return log, ErrNoDNSKEY
	}

	// Verify DNSKEY RRSIG using the ZSK keys
	err = rr.verifyRRSIG(m, keyMap)
	if err != nil {
		return log, err
	}

	// The only time this should be false is if the zone == .
	if len(parentDSSet) > 0 {
		// Verify RRSIGs from the message passed in using the KSK keys
		err = rr.verifyRRSIG(r, keyMap)
		if err != nil {
			return log, err
		}
		// Make sure the parent DS record matches one of the KSK DNSKEYS
		err = rr.checkDS(keyMap, parentDSSet)
		if err != nil {
			return log, err
		}
	}

	log.DNSSECValid = true

	// Only add response to cache if it wasn't a cache hit
	if !log.CacheHit {
		if rr.cache != nil {
			go rr.cache.Add(q, &Answer{r.Answer, r.Ns, r.Extra, dns.RcodeSuccess, true}, false)
		}
	}

	return log, nil
}

func (rr *RecursiveResolver) checkDS(keyMap map[uint16]*dns.DNSKEY, parentDSSet []dns.RR) error {
	for _, r := range parentDSSet {
		parentDS := r.(*dns.DS)
		// This KSK may not actually be of the right type but that
		// doesn't really matter since it'll serve the same purpose
		// either way if we find it in the map.
		ksk, present := keyMap[parentDS.KeyTag]
		if !present {
			continue
		}
		ds := ksk.ToDS(parentDS.DigestType)
		if ds == nil {
			return ErrFailedToConvertKSK
		}
		if ds.Digest != parentDS.Digest {
			return ErrMismatchingDS
		}
		return nil
	}
	return ErrMissingKSK
}

func (rr *RecursiveResolver) verifyRRSIG(msg *dns.Msg, keyMap map[uint16]*dns.DNSKEY) error {
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns} {
		if len(section) == 0 {
			continue
		}
		sigs := extractRRSet(section, dns.TypeRRSIG, "")
		if len(sigs) == 0 {
			return ErrNoSignatures
		}
		for _, sigRR := range sigs {
			sig := sigRR.(*dns.RRSIG)
			rest := extractRRSet(section, sig.TypeCovered, sig.Header().Name)
			k, present := keyMap[sig.KeyTag]
			if !present {
				return ErrMissingDNSKEY
			}
			err := sig.Verify(k, rest)
			if err != nil {
				return err
			}
			if !sig.ValidityPeriod(time.Time{}) {
				return ErrInvalidSignaturePeriod
			}
		}
	}
	return nil
}
