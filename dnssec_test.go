package solvere

import (
	"crypto/rsa"
	"net"
	"testing"
	"time"

	"github.com/rolandshoemaker/dns" // revert to miekg when tokenUpper PR lands
)

func TestCheckDNSKEY(t *testing.T) {

}

func TestCheckDS(t *testing.T) {
	k := &dns.DNSKEY{Algorithm: dns.RSASHA256}
	_, err := k.Generate(512)
	if err != nil {
		t.Fatalf("Failed to generate DNSKEY: %s", err)
	}
	keyMap := map[uint16]*dns.DNSKEY{}
	dsSet := []dns.RR{k.ToDS(dns.SHA256)}

	err = checkDS(keyMap, dsSet)
	if err == nil {
		t.Fatal("checkDS did not fail with an empty key map")
	}

	keyMap[k.KeyTag()] = k
	err = checkDS(keyMap, dsSet)
	if err != nil {
		t.Fatalf("checkDS failed to verify a valid key and DS combination: %s", err)
	}

	newDS := k.ToDS(dns.SHA256)
	newDS.DigestType = dns.SHA1
	dsSet = []dns.RR{newDS}
	err = checkDS(keyMap, dsSet)
	if err == nil {
		t.Fatal("checkDS didn't fail with mismatching DS record")
	}

	k.PublicKey = "broken"
	err = checkDS(keyMap, dsSet)
	if err == nil {
		t.Fatal("checkDS didn't fail with malformed KSK record")
	}
}

func TestVerifyRRSIG(t *testing.T) {
	k := &dns.DNSKEY{Hdr: dns.RR_Header{Name: "org."}, Algorithm: dns.RSASHA256, Protocol: 3}
	pk, err := k.Generate(512)
	if err != nil {
		t.Fatalf("Failed to generate DNSKEY: %s", err)
	}
	rk := pk.(*rsa.PrivateKey)

	keyMap := map[uint16]*dns.DNSKEY{}
	keyMap[k.KeyTag()] = k

	year68 := int64(1 << 31)
	n := time.Now().UTC().Unix()
	mod := (n / year68) - 1
	if mod < 0 {
		mod = 0
	}
	inception := uint32(n - (mod * year68))
	n = time.Now().Add(time.Hour).UTC().Unix()
	mod = (n / year68) - 1
	if mod < 0 {
		mod = 0
	}
	expiration := uint32(n - (mod * year68))

	sigA := &dns.RRSIG{
		Inception:  inception,
		Expiration: expiration,
		KeyTag:     k.KeyTag(),
		SignerName: "org.",
		Algorithm:  dns.RSASHA256,
	}
	sigB := &dns.RRSIG{
		Inception:  inception,
		Expiration: expiration,
		KeyTag:     k.KeyTag(),
		SignerName: "org.",
		Algorithm:  dns.RSASHA256,
	}

	aSet := []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "a.com."}, A: net.IP{1, 2, 3, 4}},
		&dns.A{Hdr: dns.RR_Header{Name: "a.com."}, A: net.IP{1, 2, 3, 5}},
	}
	nsSet := []dns.RR{
		&dns.NS{Hdr: dns.RR_Header{Name: "c.com."}, Ns: "a.com."},
	}

	err = sigA.Sign(rk, aSet)
	if err != nil {
		t.Fatalf("Failed to sign aSet: %s", err)
	}
	err = sigB.Sign(rk, nsSet)
	if err != nil {
		t.Fatalf("Failed to sign aSet: %s", err)
	}

	m := &dns.Msg{Answer: append(nsSet, sigB), Ns: append(aSet, sigA)}

	err = verifyRRSIG(m, keyMap)
	if err != nil {
		t.Fatalf("Failed to verify valid RRSIGs: %s", err)
	}
}
