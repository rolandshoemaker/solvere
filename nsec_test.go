package solvere

import (
	// "fmt"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

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
	records, err := zoneToRecords(`h9p7u7tr2u91d0v0ljs9l1gidnp90u3h.org. 86400 IN NSEC3 1 1 1 D399EAAB H9PARR669T6U8O1GSG9E1LMITK4DEM0T NS SOA RRSIG DNSKEY NSEC3PARAM
6tudcfrknr572i5c0uc4sacr7a29acu9.org. 86400 IN NSEC3 1 1 1 D399EAAB 6TV23NTQ2DDES3UTPMI2JLUCK6G3DPH6 NS DS RRSIG`)
	if err != nil {
		t.Fatalf("Failed to parse NSEC3 test records: %s", err)
	}

	err = verifyDelegation("helloworld.letsencrypt.org.", records)
	if err != nil {
		t.Fatalf("NSEC3 verification failed: %s", err)
	}
}
