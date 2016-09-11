package solvere

import (
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

var (
	ErrNSECMismatch         = errors.New("NSEC record doesn't match question")
	ErrNSECTypeExists       = errors.New("NSEC record shows question type exists")
	ErrNSECMultipleCoverage = errors.New("Multiple NSEC records cover next closer/source of synthesis")
	ErrNSECMissingCoverage  = errors.New("NSEC record missing for expected encloser")
	ErrNSECBadDelegation    = errors.New("DS or SOA bit set in NSEC type map")
	ErrNSECNSMissing        = errors.New("NS bit not set in NSEC type map")
)

func typesSet(set []uint16, types ...uint16) bool {
	tm := make(map[uint16]struct{}, len(types))
	for _, t := range types {
		tm[t] = struct{}{}
	}
	for _, t := range set {
		if _, present := tm[t]; present {
			return true
		}
	}
	return false
}

// findClosestEncloser finds the Closest Encloser and Next Encloser names for a name
// in a set of NSEC/NSEC3 records
func findClosestEncloser(name string, nsec []dns.RR) (string, string) {
	// RFC 5155 Section 8.3 (ish)
	labelIndices := dns.Split(name)
	ce, nc := "", ""
	for i := 0; i < len(labelIndices); i++ {
		z := name[labelIndices[i]:]
		for _, rr := range nsec {
			var n dns.Denialer
			switch ns := rr.(type) {
			case *dns.NSEC:
				n = dns.Denialer(ns)
			case *dns.NSEC3:
				n = dns.Denialer(ns)
			}
			if n.Match(z) {
				ce = z
				if i == 0 {
					nc = name
				} else {
					nc = name[labelIndices[i-1]:]
				}
				return ce, nc
			}
		}
	}
	return "", ""
}

func findMatching(name string, nsec []dns.RR) ([]uint16, error) {
	types := []uint16{}
	for _, rr := range nsec {
		var n dns.Denialer
		switch ns := rr.(type) {
		case *dns.NSEC:
			n = dns.Denialer(ns)
		case *dns.NSEC3:
			n = dns.Denialer(ns)
		}
		if n.Match(name) {
			if types != nil {
				return nil, ErrNSECMultipleCoverage
			}
			switch ns := rr.(type) {
			case *dns.NSEC:
				types = ns.TypeBitMap
			case *dns.NSEC3:
				types = ns.TypeBitMap
			}
		}
	}
	if types == nil {
		return nil, ErrNSECMissingCoverage
	}
	return types, nil
}

func findCoverer(name string, nsec []dns.RR) ([]uint16, error) {
	types := []uint16{}
	for _, rr := range nsec {
		var n dns.Denialer
		switch ns := rr.(type) {
		case *dns.NSEC:
			n = dns.Denialer(ns)
		case *dns.NSEC3:
			n = dns.Denialer(ns)
		}
		if n.Cover(name) {
			if types != nil {
				return nil, ErrNSECMultipleCoverage
			}
			switch ns := rr.(type) {
			case *dns.NSEC:
				types = ns.TypeBitMap
			case *dns.NSEC3:
				types = ns.TypeBitMap
			}
		}
	}
	if types == nil {
		return nil, ErrNSECMissingCoverage
	}
	return types, nil
}

// RFC 5155 Section 8.4
func verifyNameError(q *Question, nsec []dns.RR) error {
	ce, _ := findClosestEncloser(q.Name, nsec)
	if ce == "" {
		return ErrNSECMissingCoverage
	}
	_, err := findMatching(q.Name, nsec)
	if err != nil {
		return err
	}
	_, err = findCoverer(fmt.Sprintf("*.%s", ce), nsec)
	if err != nil {
		return err
	}
	return nil
}

// verifyNSECNODATA verifies NSEC/NSEC3 records from a answer with a NOERROR (0) RCODE
// and a empty Answer section
func verifyNODATA(q *Question, nsec []dns.RR) error {
	// RFC5155 Section 8.5
	types, err := findMatching(q.Name, nsec)
	if err == nil {
		if typesSet(types, q.Type, dns.TypeCNAME) {
			return ErrNSECTypeExists
		}
		if strings.HasPrefix(q.Name, "*.") {
			// RFC 5155 Section 8.7
			ce, _ := findClosestEncloser(q.Name, nsec)
			if ce == "" {
				return ErrNSECMissingCoverage
			}
			matchTypes, err := findMatching(fmt.Sprintf("*.%s", ce), nsec)
			if err != nil {
				return err
			}
			if typesSet(matchTypes, q.Type, dns.TypeCNAME) {
				return ErrNSECTypeExists
			}
		}
		return nil
	}

	if q.Type != dns.TypeDS {
		return err
	}

	// RFC5155 Section 8.6
	ce, nc := findClosestEncloser(q.Name, nsec)
	if ce == "" {
		return ErrNSECMissingCoverage
	}
	_, err = findCoverer(nc, nsec)
	if err != nil {
		return err
	}
	// BUG(roland): this needs to check the opt out bit
	return nil
}

// RFC 5155 Section 8.8
func verifyWildcardAnswer() {
}

// RFC 5155 Section 8.9
func verifyDelegation(delegation string, nsec []dns.RR) error {
	types, err := findMatching(delegation, nsec)
	if err != nil {
		ce, nc := findClosestEncloser(delegation, nsec)
		if ce == "" {
			return ErrNSECMissingCoverage
		}
		_, err = findCoverer(nc, nsec)
		if err != nil {
			return err
		}
		return nil
	}
	if !typesSet(types, dns.TypeNS) {
		return ErrNSECNSMissing
	}
	if typesSet(types, dns.TypeDS, dns.TypeSOA) {
		return ErrNSECBadDelegation
	}
	return nil
}
