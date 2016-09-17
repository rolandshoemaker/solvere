package solvere

import (
	"strings"
	"testing"

	"github.com/rolandshoemaker/dns" // revert to miekg when tokenUpper PR lands
)

func makeNSEC3(name, next string, optOut bool, types []uint16) *dns.NSEC3 {
	salt := "FFFF"
	flags := uint8(0)
	if optOut {
		flags = flags | 0x01
	}
	return &dns.NSEC3{
		Hdr: dns.RR_Header{
			Name:  dns.HashName(name, dns.SHA1, 2, salt) + ".com",
			Class: dns.ClassINET,
		},
		Hash:       dns.SHA1,
		Flags:      flags,
		Iterations: 2,
		SaltLength: 2,
		Salt:       salt,
		HashLength: 20,
		NextDomain: dns.HashName(next, dns.SHA1, 2, salt),
		TypeBitMap: types,
	}
}

func zoneToRecords(z string) ([]dns.RR, error) {
	records := []dns.RR{}
	tokens := dns.ParseZone(strings.NewReader(z), "", "")
	for x := range tokens {
		if x.Error != nil {
			return nil, x.Error
		}
		records = append(records, x.RR)
	}
	return records, nil
}

// BUG(roland): Currently all these NSEC3 records are taken from real life queries, instead
//              they should really be strictly generated... mainly cuz I can't find many
//              zones implementing half of this trash

func TestVerifyNameError(t *testing.T) {
	err := verifyNameError(&Question{Name: "easdasdd1q2e2d2w.org.", Type: dns.TypeA}, []dns.RR{})
	if err == nil {
		t.Fatalf("NSEC3 verification didn't fail with an empty NSEC3 set")
	}

	records, err := zoneToRecords(`h9p7u7tr2u91d0v0ljs9l1gidnp90u3h.org. 86400 IN NSEC3 1 1 1 D399EAAB H9PARR669T6U8O1GSG9E1LMITK4DEM0T NS SOA RRSIG DNSKEY NSEC3PARAM
7787tb18r44mr7o4pqc3n8ur0h2043tl.org. 86400 IN NSEC3 1 1 1 D399EAAB 778KI18543GPI8BANNL5TLE6A49ALNT4 NS DS RRSIG
vaittv1g2ies9s3920soaumh73klnhs5.org. 86400 IN NSEC3 1 1 1 D399EAAB VAJSHJ9G9U88NEFMNIS1LOG48CM6L9LO NS DS RRSIG`)
	if err != nil {
		t.Fatalf("Failed to parse NSEC3 test records: %s", err)
	}

	err = verifyNameError(&Question{Name: "easdasdd1q2e2d2w.org.", Type: dns.TypeA}, records)
	if err != nil {
		t.Fatalf("NSEC3 verification failed: %s", err)
	}

	records, err = zoneToRecords(`h9p7u7tr2u91d0v0ljs9l1gidnp90u3h.org. 86400 IN NSEC3 1 1 1 D399EAAB H9PARR669T6U8O1GSG9E1LMITK4DEM0T NS SOA RRSIG DNSKEY NSEC3PARAM
7787tb18r44mr7o4pqc3n8ur0h2043tl.org. 86400 IN NSEC3 1 1 1 D399EAAB 778KI18543GPI8BANNL5TLE6A49ALNT4 NS DS RRSIG`)
	if err != nil {
		t.Fatalf("Failed to parse NSEC3 test records: %s", err)
	}

	err = verifyNameError(&Question{Name: "easdasdd1q2e2d2w.org.", Type: dns.TypeA}, records)
	if err == nil {
		t.Fatal("NSEC3 verification did not fail")
	}

	err = verifyNameError(&Question{Name: "xxxx.org.", Type: dns.TypeA}, records)
	if err == nil {
		t.Fatal("NSEC3 verification didn't fail")
	}

	err = verifyNameError(&Question{Name: "different-parent.com.", Type: dns.TypeA}, records)
	if err == nil {
		t.Fatal("NSEC3 verification didn't fail")
	}
}

func TestVerifyNODATA(t *testing.T) {
	records, err := zoneToRecords(`lg1c6bf6hv6ooib05ir8kolkofua0upg.whitehouse.gov. 3600 IN NSEC3 1 0 1 67C6697351FF4AEC LK8T7NFS811HQPP3UDU7A6KQ12IIOTKF A NS SOA MX TXT AAAA RRSIG DNSKEY NSEC3PARAM`)
	if err != nil {
		t.Fatalf("Failed to parse NSEC3 test records: %s", err)
	}

	err = verifyNODATA(&Question{Name: "whitehouse.gov.", Type: dns.TypeCAA}, records)
	if err != nil {
		t.Fatalf("NSEC3 verification failed: %s", err)
	}

	err = verifyNODATA(&Question{Name: "mighthouse.gov.", Type: dns.TypeCAA}, records)
	if err == nil {
		t.Fatal("NSEC3 verification didn't fail")
	}

	records, err = zoneToRecords(`lg1c6bf6hv6ooib05ir8kolkofua0upg.whitehouse.gov. 3600 IN NSEC3 1 0 1 67C6697351FF4AEC LK8T7NFS811HQPP3UDU7A6KQ12IIOTKF A NS SOA MX TXT AAAA RRSIG DNSKEY NSEC3PARAM CAA`)
	if err != nil {
		t.Fatalf("Failed to parse NSEC3 test records: %s", err)
	}

	err = verifyNODATA(&Question{Name: "whitehouse.gov.", Type: dns.TypeCAA}, records)
	if err == nil {
		t.Fatal("NSEC3 verification didn't fail")
	}

	records, err = zoneToRecords(`lg1c6bf6hv6ooib05ir8kolkofua0upg.whitehouse.gov. 3600 IN NSEC3 1 0 1 67C6697351FF4AEC LK8T7NFS811HQPP3UDU7A6KQ12IIOTKF A NS SOA MX TXT AAAA RRSIG DNSKEY NSEC3PARAM`)
	if err != nil {
		t.Fatalf("Failed to parse NSEC3 test records: %s", err)
	}

	err = verifyNODATA(&Question{Name: "whitehouse.gov.", Type: dns.TypeDS}, records)
	if err != nil {
		t.Fatalf("verifyNODATA failed: %s", err)
	}
}

func TestVerifyWildcardAnswer(t *testing.T) {

}

func TestVerifyDelegation(t *testing.T) {
	// Valid direct delegation
	records := []dns.RR{
		makeNSEC3("a.b.com.", "b.b.com.", false, []uint16{dns.TypeNS}),
	}
	err := verifyDelegation("a.b.com.", records)
	if err != nil {
		t.Fatalf("verifyDelegation failed for a direct delegation match: %s", err)
	}

	// Invalid direct delegation, NS bit not set
	records = []dns.RR{
		makeNSEC3("a.b.com.", "b.b.com.", false, nil),
	}
	err = verifyDelegation("a.b.com.", records)
	if err == nil {
		t.Fatal("verifyDelegation didn't fail for a direct delegation with NS bit not set")
	}

	// Invalid direct delegation, DS bit set
	records = []dns.RR{
		makeNSEC3("a.b.com.", "b.b.com.", false, []uint16{dns.TypeNS, dns.TypeDS}),
	}
	err = verifyDelegation("a.b.com.", records)
	if err == nil {
		t.Fatal("verifyDelegation didn't fail for a direct delegation with DS bit set")
	}

	// Invalid direct delegation, SOA bit set
	records = []dns.RR{
		makeNSEC3("a.b.com.", "b.b.com.", false, []uint16{dns.TypeNS, dns.TypeSOA}),
	}
	err = verifyDelegation("a.b.com.", records)
	if err == nil {
		t.Fatal("verifyDelegation didn't fail for a direct delegation with SOA bit set")
	}

	// Valid Opt-Out delegation
	records = []dns.RR{
		makeNSEC3("com.", "a.com.", false, []uint16{dns.TypeNS}),  // CE
		makeNSEC3("a.com.", "e.com.", true, []uint16{dns.TypeNS}), // NC coverer
	}
	err = verifyDelegation("b.com.", records)
	if err != nil {
		t.Fatalf("verifyDelegation failed for a opt-out delegation match: %s", err)
	}

	// Invalid Opt-Out delegation, no NC
	records = []dns.RR{
		makeNSEC3("com.", "a.com.", false, []uint16{dns.TypeNS}), // CE
	}
	err = verifyDelegation("b.com.", records)
	if err == nil {
		t.Fatal("verifyDelegation didn't fail for a direct delegation with no Next Closer")
	}

	// Invalid Opt-Out delegation, opt-out bit not set on NC
	records = []dns.RR{
		makeNSEC3("com.", "a.com.", false, []uint16{dns.TypeNS}),   // CE
		makeNSEC3("a.com.", "e.com.", false, []uint16{dns.TypeNS}), // NC coverer
	}
	err = verifyDelegation("b.com.", records)
	if err == nil {
		t.Fatal("verifyDelegation didn't fail for a direct delegation with Opt-Out bit not set on NC")
	}

	// RFC5155 Appendix B.3
	records, err = zoneToRecords(`35mthgpgcu1qg68fab165klnsnk3dpvl.example. 3600 IN NSEC3 1 1 12 aabbccdd b4um86eghhds6nea196smvmlo4ors995 NS DS RRSIG
0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example. 3600 IN NSEC3 1 1 12 aabbccdd 2t7b4g4vsa5smi47k61mv5bv1a22bojr MX DNSKEY NS SOA NSEC3PARAM RRSIG`)
	if err != nil {
		t.Fatalf("Failed to parse NSEC3 test records: %s", err)
	}
	err = verifyDelegation("c.example.", records)
	if err != nil {
		t.Fatalf("verifyDelegation failed wtih opt out delegation example from RFC5155: %s", err)
	}
}
