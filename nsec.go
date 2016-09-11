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
	ErrNSECMissingCoverage  = errors.New("Next Closer and Source of Synthesis aren't both covered")
)

// verifyNSECNODATA verifies NSEC/NSEC3 records from a answer with a NOERROR (0) RCODE
// and a empty Answer section
func verifyNSECNODATA(q *Question, nsec []dns.RR) error {
	for _, rr := range nsec {
		var types []uint16
		var n dns.Denialer
		switch ns := rr.(type) {
		case *dns.NSEC:
			types = ns.TypeBitMap
			n = ns
		case *dns.NSEC3:
			types = ns.TypeBitMap
			n = ns
		}
		// fmt.Printf("%#v\n", n.(*dns.NSEC3))
		// debugMatch(rr.(*dns.NSEC3), "org.")
		if !n.Match(q.Name) {
			// return ErrNSECMismatch
			continue
		}
		for _, t := range types {
			if q.Type == t {
				return ErrNSECTypeExists
			}
			if t > q.Type {
				break
			}
		}
	}
	return nil
}

func verifyNSECProof(q *Question, nsec []dns.RR) error {
	labelIndices := dns.Split(q.Name)
	ce, nc, wc := "", "", ""
	for i := 0; i < len(labelIndices); i++ {
		z := q.Name[labelIndices[i]:]
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
				wc = "*." + z
				if i == 0 {
					nc = q.Name
				} else {
					nc = q.Name[labelIndices[i-1]:]
				}
				break
			}
		}
		if ce != "" {
			break
		}
	}
	if ce == "" {
		return nil
	}
	fmt.Println(ce, nc, wc)

	ncCovered, wcCovered := false, false
	for _, rr := range nsec {
		var n dns.Denialer
		switch ns := rr.(type) {
		case *dns.NSEC:
			n = dns.Denialer(ns)
		case *dns.NSEC3:
			n = dns.Denialer(ns)
		}
		if n.Cover(nc) {
			if ncCovered {
				return ErrNSECMultipleCoverage
			}
			ncCovered = true
		}
		if n.Cover(wc) {
			if wcCovered {
				return ErrNSECMultipleCoverage
			}
			wcCovered = true
		}
	}
	// if !(ncCovered && wcCovered) {
	// 	fmt.Println(ncCovered, wcCovered)
	// 	return ErrNSECMissingCoverage
	// }
	return nil
}

func debugMatch(rr *dns.NSEC3, name string) {
	hname := dns.HashName(name, rr.Hash, rr.Iterations, rr.Salt)
	labels := dns.Split(rr.Hdr.Name)
	if len(labels) < 2 {
		fmt.Println("WUT?")
		return
	}
	hash := strings.ToUpper(rr.Hdr.Name[labels[0] : labels[1]-1]) // -1 to remove the .
	fmt.Println(hname, hash)
}
