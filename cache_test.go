package solvere

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestMinTTL(t *testing.T) {
	rrSet := []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Ttl: 2}},
		&dns.A{Hdr: dns.RR_Header{Ttl: 5}},
		&dns.A{Hdr: dns.RR_Header{Ttl: 1}},
	}
	min := minTTL(rrSet)
	if min != 1 {
		t.Fatalf("minTTL produced the wrong TTL: expected %d, got %d", 1, min)
	}
	if minTTL([]dns.RR{}) != 0 {
		t.Fatalf("minTTL produced a non-zero TTL with a empty RR set")
	}
}

func TestCache(t *testing.T) {
	cache := NewBasicCache()

	q := Question{Name: "testing", Type: dns.TypeA}
	ca := cache.Get(&q)
	if ca != nil {
		t.Fatalf("Empty answer returned non-nil Answer: %#v", ca)
	}

	a := Answer{Answer: []dns.RR{&dns.A{Hdr: dns.RR_Header{Ttl: 1}, A: net.IP{1, 2, 3, 4}}}}
	cache.Add(&q, &a, true)
	ca = cache.Get(&q)
	if ca != &a {
		t.Fatalf("Cache returned incorrect answer: expected %#v, got %#v", a, ca)
	}
	time.Sleep(time.Second)
	ca = cache.Get(&q)
	if ca == nil {
		t.Fatal("Cache pruned q/a that should've been kept forever")
	}

	q = Question{Name: "testing-2", Type: dns.TypeA}
	cache.Add(&q, &a, false)
	ca = cache.Get(&q)
	if ca != &a {
		t.Fatalf("Cache returned incorrect answer: expected %#v, got %#v", a, ca)
	}
	time.Sleep(time.Second * 2)
	ca = cache.Get(&q)
	if ca != nil {
		t.Fatal("Cache didn't prune q/a that had a minimum TTL of 1 second")
	}

	// BUG(roland): Update test is super flaky...
	na := Answer{Answer: []dns.RR{&dns.A{Hdr: dns.RR_Header{Ttl: 2}, A: net.IP{1, 2, 3, 5}}}}
	cache.Add(&q, &na, false)
	time.Sleep(time.Second)
	cache.Add(&q, &a, false)
	time.Sleep(time.Second * 2)
	ca = cache.Get(&q)
	if ca != nil {
		t.Fatal("Cache didn't prune q/a that had a minimum TTL of 1 second")
	}

	a = Answer{Answer: []dns.RR{&dns.A{Hdr: dns.RR_Header{}, A: net.IP{1, 2, 3, 4}}}}
	cache.Add(&q, &a, false)
	if ca != nil {
		t.Fatalf("Empty answer returned non-nil Answer: %#v", ca)
	}
}
