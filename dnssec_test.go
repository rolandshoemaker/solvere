package solvere

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/rolandshoemaker/dns" // revert to miekg when tokenUpper PR lands

	"golang.org/x/net/context"
)

var exampleKey = dns.DNSKEY{
	Hdr:       dns.RR_Header{Name: "example.", Rrtype: dns.TypeDNSKEY},
	Algorithm: dns.RSASHA256,
	Flags:     256,
	Protocol:  3,
}
var examplePrivateKey = new(crypto.PrivateKey)
var exampleKeySig = &dns.RRSIG{}

func init() {
	epk, err := exampleKey.Generate(512)
	if err != nil {
		panic(err)
	}
	examplePrivateKey = &epk

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

	exampleKeySig = &dns.RRSIG{
		Inception:  inception,
		Expiration: expiration,
		KeyTag:     exampleKey.KeyTag(),
		SignerName: "example.",
		Algorithm:  dns.RSASHA256,
	}
	rk := epk.(*rsa.PrivateKey)
	err = exampleKeySig.Sign(rk, []dns.RR{&exampleKey})
	if err != nil {
		panic(err)
	}
}

func mockDNSKEYServer(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Rcode = dns.RcodeSuccess

	if len(r.Question) != 1 {
		m.Rcode = dns.RcodeServerFailure
		w.WriteMsg(m)
		return
	}
	switch r.Question[0].Name {
	case "example.":
		m.Answer = append(m.Answer, &exampleKey, exampleKeySig)
	case "bad.":
		m.Rcode = dns.RcodeServerFailure
		w.WriteMsg(m)
		return
	case "no-keys-weird.":
		m.Answer = append(m.Answer, &dns.SOA{
			Hdr:     dns.RR_Header{Name: "no-keys-weird.", Rrtype: dns.TypeSOA},
			Ns:      "ns.no-keys-weird.",
			Mbox:    "master.no-keys-weird.",
			Serial:  1,
			Refresh: 1,
			Retry:   1,
			Expire:  1,
			Minttl:  1,
		})
	case "out-of-bailiwick.":
		m.Answer = append(m.Answer, &exampleKey, exampleKeySig)
	case "bad-sig.":
		badSigRR := dns.Copy(exampleKeySig)
		badSig := badSigRR.(*dns.RRSIG)
		badSig.Hdr.Name = "bad-sig."
		badSig.Signature = ""
		keyRR := dns.Copy(&exampleKey)
		key := keyRR.(*dns.DNSKEY)
		key.Hdr.Name = "bad-sig."
		m.Answer = append(m.Answer, key, badSig)
	}

	w.WriteMsg(m)
	return
}

func TestLookupDNSKEY(t *testing.T) {
	dnsPort = "9053"
	dns.HandleFunc(".", mockDNSKEYServer)
	server := &dns.Server{Addr: "127.0.0.1:9053", Net: "udp", ReadTimeout: time.Second, WriteTimeout: time.Second}
	go func() {
		err := server.ListenAndServe()
		if err != nil {
			fmt.Printf("DNS test server failed: %s\n", err)
			return
		}
	}()
	// wait for things to warm up :/
	time.Sleep(time.Millisecond * 500)
	stop := make(chan struct{}, 1)
	defer func() { stop <- struct{}{} }()
	go func() {
		<-stop
		err := server.Shutdown()
		if err != nil {
			fmt.Printf("Failed to shutdown DNS test server: %s\n", err)
			return
		}
	}()

	rr := RecursiveResolver{useDNSSEC: true, c: new(dns.Client)}
	auth := &Nameserver{Zone: "example.", Addr: "127.0.0.1"}

	// Valid response
	keyMap, _, _, err := rr.lookupDNSKEY(context.Background(), auth)
	if err != nil {
		t.Fatalf("lookupDNSKEY failed with a valid response with no DS set: %s", err)
	}
	if len(keyMap) != 1 {
		t.Fatal("lookupDNSKEY returned incorrect size keyMap for 'example.'")
	}
	if k, present := keyMap[exampleKey.KeyTag()]; !present {
		t.Fatal("lookupDNSKEY returned keyMap missing expected key for 'example.'")
	} else if *k != exampleKey {
		t.Fatal("lookupDNSKEY returned keyMap containing wrong key with right key tag for 'example.'")
	}

	// Invalid response, empty answer
	_, _, _, err = rr.lookupDNSKEY(context.Background(), &Nameserver{Zone: ".", Addr: "127.0.0.1"})
	if err == nil {
		t.Fatalf("lookupDNSKEY didn't fail with a empty answer")
	}

	// Invalid response, bad rcode
	_, _, _, err = rr.lookupDNSKEY(context.Background(), &Nameserver{Zone: "bad.", Addr: "127.0.0.1"})
	if err == nil {
		t.Fatalf("lookupDNSKEY didn't fail with a bad rcode")
	}

	// Invalid response, wrong types returned
	_, _, _, err = rr.lookupDNSKEY(context.Background(), &Nameserver{Zone: "no-keys-weird.", Addr: "127.0.0.1"})
	if err == nil {
		t.Fatalf("lookupDNSKEY didn't fail with a no keys")
	}

	// Invalid response, bad rcode
	_, _, _, err = rr.lookupDNSKEY(context.Background(), &Nameserver{Zone: "no-keys-weird.", Addr: "127.0.0.1"})
	if err == nil {
		t.Fatalf("lookupDNSKEY didn't fail with a no keys")
	}

	// Invalid response, out of bailiwick records
	_, _, _, err = rr.lookupDNSKEY(context.Background(), &Nameserver{Zone: "out-of-bailiwick.", Addr: "127.0.0.1"})
	if err == nil {
		t.Fatalf("lookupDNSKEY didn't fail with out of bailiwick records")
	}

	// Invalid response, invalid signature
	_, _, _, err = rr.lookupDNSKEY(context.Background(), &Nameserver{Zone: "bad-sig.", Addr: "127.0.0.1"})
	if err == nil {
		t.Fatalf("lookupDNSKEY didn't fail with bad signature")
	}
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

	// Valid signatures
	m := &dns.Msg{Answer: append(nsSet, sigB)}
	err = verifyRRSIG(m, keyMap)
	if err != nil {
		t.Fatalf("Failed to verify valid RRSIGs: %s", err)
	}

	// Missing signatures
	m = &dns.Msg{Answer: aSet}
	err = verifyRRSIG(m, keyMap)
	if err == nil {
		t.Fatal("verifyRRSIG didn't fail with missing signatures")
	}

	// Missing signed records
	m = &dns.Msg{Answer: []dns.RR{sigA}}
	err = verifyRRSIG(m, keyMap)
	if err == nil {
		t.Fatal("verifyRRSIG didn't fail with missing signed records")
	}

	// Missing key
	m = &dns.Msg{Answer: append(aSet, sigA)}
	err = verifyRRSIG(m, make(map[uint16]*dns.DNSKEY))
	if err == nil {
		t.Fatal("verifyRRSIG didn't fail with missing DNSKEY")
	}

	// Invalid signature
	sigA.Signature = ""
	m = &dns.Msg{Answer: append(aSet, sigA)}
	err = verifyRRSIG(m, keyMap)
	if err == nil {
		t.Fatal("verifyRRSIG didn't fail with invalid signature")
	}

	// Invalid validity period
	sigA.Expiration = inception - 10
	err = sigA.Sign(rk, aSet)
	if err != nil {
		t.Fatalf("Failed to sign aSet: %s", err)
	}
	m = &dns.Msg{Answer: append(aSet, sigA)}
	err = verifyRRSIG(m, keyMap)
	if err == nil {
		t.Fatal("verifyRRSIG didn't fail with invalid validity period")
	}
}

func TestCheckSignatures(t *testing.T) {

}
