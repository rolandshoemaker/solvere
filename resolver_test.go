package solvere

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestAllType(t *testing.T) {
	for _, tc := range []struct {
		set      []dns.RR
		t        uint16
		expected bool
	}{
		{
			set:      []dns.RR{&dns.A{Hdr: dns.RR_Header{Rrtype: dns.TypeA}}},
			t:        dns.TypeA,
			expected: true,
		},
		{
			set:      []dns.RR{&dns.A{Hdr: dns.RR_Header{Rrtype: dns.TypeA}}, &dns.A{Hdr: dns.RR_Header{Rrtype: dns.TypeA}}},
			t:        dns.TypeA,
			expected: true,
		},
		{
			set:      []dns.RR{&dns.A{Hdr: dns.RR_Header{Rrtype: dns.TypeA}}, &dns.MX{Hdr: dns.RR_Header{Rrtype: dns.TypeMX}}},
			t:        dns.TypeA,
			expected: false,
		},
		{
			set:      []dns.RR{&dns.MX{Hdr: dns.RR_Header{Rrtype: dns.TypeMX}}, &dns.MX{Hdr: dns.RR_Header{Rrtype: dns.TypeMX}}},
			t:        dns.TypeA,
			expected: false,
		},
	} {
		got := allOfType(tc.set, tc.t)
		if got != tc.expected {
			t.Fatalf("allOfType failed: expected %t, got %t [record set: %s, type: %s]", tc.expected, got, tc.set, dns.TypeToString[tc.t])
		}
	}
}

func compareRRSet(a, b []dns.RR) bool {
	// assume ordering is same
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].String() != b[i].String() {
			return false
		}
	}
	return true
}

func TestCollapseCNAMEChain(t *testing.T) {
	for _, tc := range []struct {
		qname    string
		set      []dns.RR
		expected string
	}{
		{
			qname: "a.com",
			set: []dns.RR{
				&dns.CNAME{Hdr: dns.RR_Header{Name: "a.com"}, Target: "b.com"},
				&dns.CNAME{Hdr: dns.RR_Header{Name: "b.com"}, Target: "c.com"},
			},
			expected: "c.com",
		},
		{
			qname: "a.com",
			set: []dns.RR{
				&dns.CNAME{Hdr: dns.RR_Header{Name: "a.com"}, Target: "z.com"},
				&dns.CNAME{Hdr: dns.RR_Header{Name: "b.com"}, Target: "c.com"},
			},
			expected: "z.com",
		},
		{
			qname: "a.com",
			set: []dns.RR{
				&dns.CNAME{Hdr: dns.RR_Header{Name: "b.com"}, Target: "c.com"},
			},
			expected: "",
		},
	} {
		canonical, _ := collapseCNAMEChain(tc.qname, tc.set)
		if canonical != tc.expected {
			t.Fatalf(
				"collapseCNAMEChain returned unexpected name: expected %s, got %s [qname: %s, record set: %s]",
				tc.expected,
				canonical,
				tc.qname,
				tc.set,
			)
		}
	}
}

func TestIsAlias(t *testing.T) {
	for _, tc := range []struct {
		set           []dns.RR
		q             Question
		isAlias       bool
		expectedName  string
		expectedError error
		chased        []dns.RR
	}{
		// bad
		{
			set:     []dns.RR{},
			q:       Question{Type: dns.TypeA},
			isAlias: false,
		},
		{
			set:     []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "a.com", Rrtype: dns.TypeA}}},
			q:       Question{Type: dns.TypeA},
			isAlias: false,
		},
		{
			set:     []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: "a.com", Rrtype: dns.TypeCNAME}}},
			q:       Question{Type: dns.TypeCNAME},
			isAlias: false,
		},
		{
			set:     []dns.RR{&dns.DNAME{Hdr: dns.RR_Header{Name: "a.com", Rrtype: dns.TypeDNAME}}},
			q:       Question{Type: dns.TypeDNAME},
			isAlias: false,
		},
		{
			set:     []dns.RR{&dns.DNAME{Hdr: dns.RR_Header{Name: "a.com", Rrtype: dns.TypeDNAME}}},
			q:       Question{Type: dns.TypeA},
			isAlias: false,
		},
		{
			set:     []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: "a.com", Rrtype: dns.TypeCNAME}, Target: "b.com"}},
			q:       Question{Type: dns.TypeA},
			isAlias: false,
		},
		{
			set: []dns.RR{
				&dns.CNAME{Hdr: dns.RR_Header{Name: "a.com", Rrtype: dns.TypeCNAME}, Target: "b.com"},
				&dns.A{Hdr: dns.RR_Header{Name: "a.com", Rrtype: dns.TypeA}},
			},
			q:       Question{Name: "a.com", Type: dns.TypeA},
			isAlias: false,
		},
		{
			set: []dns.RR{
				&dns.RRSIG{Hdr: dns.RR_Header{Name: "a.com", Rrtype: dns.TypeRRSIG}},
			},
			q:       Question{Name: "a.com", Type: dns.TypeA},
			isAlias: false,
		},
		{
			set:           []dns.RR{&dns.DNAME{Hdr: dns.RR_Header{Name: "a.com", Rrtype: dns.TypeDNAME}, Target: strings.Repeat("a", 256)}},
			q:             Question{Name: "a.a.com", Type: dns.TypeA},
			isAlias:       false,
			expectedError: dnameTooLong,
		},
		// good
		{
			set:          []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: "a.com", Rrtype: dns.TypeCNAME}, Target: "b.com"}},
			q:            Question{Name: "a.com", Type: dns.TypeA},
			isAlias:      true,
			expectedName: "b.com",
			chased:       []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: "a.com", Rrtype: dns.TypeCNAME}, Target: "b.com"}},
		},
		{
			set: []dns.RR{
				&dns.CNAME{Hdr: dns.RR_Header{Name: "a.com", Rrtype: dns.TypeCNAME}, Target: "b.com"},
				&dns.RRSIG{Hdr: dns.RR_Header{Name: "a.com", Rrtype: dns.TypeRRSIG}},
			},
			q:            Question{Name: "a.com", Type: dns.TypeA},
			isAlias:      true,
			expectedName: "b.com",
			chased: []dns.RR{
				&dns.CNAME{Hdr: dns.RR_Header{Name: "a.com", Rrtype: dns.TypeCNAME}, Target: "b.com"},
			},
		},
		{
			set: []dns.RR{
				&dns.CNAME{Hdr: dns.RR_Header{Name: "a.com", Rrtype: dns.TypeCNAME}, Target: "b.com"},
				&dns.CNAME{Hdr: dns.RR_Header{Name: "b.com", Rrtype: dns.TypeCNAME}, Target: "c.com"},
			},
			q:            Question{Name: "a.com", Type: dns.TypeA},
			isAlias:      true,
			expectedName: "c.com",
			chased: []dns.RR{
				&dns.CNAME{Hdr: dns.RR_Header{Name: "a.com", Rrtype: dns.TypeCNAME}, Target: "b.com"},
				&dns.CNAME{Hdr: dns.RR_Header{Name: "b.com", Rrtype: dns.TypeCNAME}, Target: "c.com"},
			},
		},
		{
			set:          []dns.RR{&dns.DNAME{Hdr: dns.RR_Header{Name: "a.com", Rrtype: dns.TypeDNAME}, Target: "b.com"}},
			q:            Question{Name: "a.a.com", Type: dns.TypeA},
			isAlias:      true,
			expectedName: "a.b.com",
			chased:       []dns.RR{&dns.DNAME{Hdr: dns.RR_Header{Name: "a.com", Rrtype: dns.TypeDNAME}, Target: "b.com"}},
		},
	} {
		alias, name, chased, err := isAlias(tc.set, tc.q)
		if err != nil {
			if tc.expectedError != nil {
				if tc.expectedError != err {
					t.Fatalf("isAlias failed: expected %q, got %q", tc.expectedError, err)
				}
			} else {
				t.Fatalf("isAlias failed: %s", err)
			}
		}
		if alias != tc.isAlias || name != tc.expectedName {
			t.Fatalf("isAlias failed: expected %t, %q got %t, %q", tc.isAlias, tc.expectedName, alias, name)
		}
		if !compareRRSet(tc.chased, chased) {
			t.Fatalf("isAlias returned unexpected chased aliases: expected %s, got %s", tc.chased, chased)
		}
	}
}
