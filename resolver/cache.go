package resolver

import (
	"crypto/sha256"
	"fmt"
	mrand "math/rand"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

func hashQuestion(q *dns.Question) [32]byte {
	inp := append([]byte{uint8(q.Qtype & 0xff), uint8(q.Qtype >> 8), uint8(q.Qclass & 0xff), uint8(q.Qclass >> 8)}, []byte(q.Name)...)
	return sha256.Sum256(inp)
}

func minTTL(a []dns.RR) int {
	var min *uint32
	for _, r := range a {
		if min == nil {
			min = &r.Header().Ttl
			continue
		}
		if r.Header().Ttl < *min {
			min = &r.Header().Ttl
		}
	}
	if min == nil {
		return 0
	}
	return int(*min)
}

type cacheEntry struct {
	answer   []dns.RR
	ttl      int
	modified time.Time
	removed  bool
	mu       sync.Mutex
}

func (ca *cacheEntry) update(entry *cacheEntry, answer []dns.RR, ttl int) {
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.removed {
		return
	}
	// just overwrite the previous one...
	entry.ttl = ttl
	entry.answer = answer
	entry.modified = time.Now()
}

type qaCache struct {
	mu    sync.RWMutex
	cache map[[32]byte]*cacheEntry
}

func (qac *qaCache) del(entry *cacheEntry, id [32]byte) {
	qac.mu.Lock()
	defer qac.mu.Unlock()
	delete(qac.cache, id)
	entry.removed = true
}

func (qac *qaCache) prune(q *dns.Question, id [32]byte, ttl int) {
	sleep := time.Second * time.Duration(ttl)
	for {
		time.Sleep(sleep)
		entry, present := qac.getEntry(q)
		if !present {
			return
		}
		entry.mu.Lock()
		new := entry.modified.Add(time.Second * time.Duration(entry.ttl)).Sub(time.Now())
		if new < 0 {
			qac.del(entry, id)
			entry.mu.Unlock()
			return
		}
		entry.mu.Unlock()
		sleep = new
	}
}

func (qac *qaCache) add(q *dns.Question, a []dns.RR) {
	id := hashQuestion(q)
	ttl := minTTL(a)
	qac.mu.Lock()
	defer qac.mu.Unlock()
	if entry, present := qac.cache[id]; present {
		qac.cache[id].update(entry, a, ttl)
		return
	}
	qac.cache[id] = &cacheEntry{a, ttl, time.Now(), false, sync.Mutex{}}
	go qac.prune(q, id, ttl)
}

func (qac *qaCache) getEntry(q *dns.Question) (*cacheEntry, bool) {
	id := hashQuestion(q)
	qac.mu.RLock()
	defer qac.mu.RUnlock()
	entry, present := qac.cache[id]
	return entry, present
}

func (qac *qaCache) get(q *dns.Question) ([]dns.RR, bool) {
	if entry, present := qac.getEntry(q); present {
		entry.mu.Lock()
		defer entry.mu.Unlock()
		if entry.removed {
			return nil, false
		}
		return entry.answer, true
	}
	return nil, false
}

type authEntry struct {
	addrs    []string
	ttl      int
	modified time.Time
	removed  bool
	mu       sync.Mutex
}

type authCache struct {
	cache map[string]*authEntry
	mu    sync.RWMutex
}

func (ac *authCache) del(zone string, entry *authEntry) {
	entry.mu.Lock()
	defer entry.mu.Unlock()
	delete(ac.cache, zone)
	entry.removed = true
}

func (ac *authCache) get(zone string) (*authEntry, bool) {
	ac.mu.RLock()
	defer ac.mu.RUnlock()
	if entry, present := ac.cache[zone]; present {
		entry.mu.Lock()
		defer entry.mu.Unlock()
		if entry.removed {
			return nil, false
		}
		return entry, true
	}
	return nil, false
}

func (ac *authCache) prune(zone string, ttl int) {
	sleep := time.Second * time.Duration(ttl)
	for {
		time.Sleep(sleep)
		entry, present := ac.get(zone)
		if !present {
			return
		}
		entry.mu.Lock()
		new := entry.modified.Add(time.Second * time.Duration(entry.ttl)).Sub(time.Now())
		if new < 0 {
			ac.del(zone, entry)
			entry.mu.Unlock()
			return
		}
		entry.mu.Unlock()
		sleep = new
	}
}

func (ac *authCache) update(entry *authEntry, addrs []string, ttl int) {
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.removed {
		return
	}
	entry.addrs = addrs
	entry.ttl = ttl
	entry.modified = time.Now()
}

func (ac *authCache) add(zone string, addrs []string, ttl int) {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	if entry, present := ac.cache[zone]; present {
		ac.update(entry, addrs, ttl)
		return
	}
	ac.cache[zone] = &authEntry{addrs, ttl, time.Now(), false, sync.Mutex{}}
	if ttl > 0 { // so root hints stick around forever...
		go ac.prune(zone, ttl)
	}
}

func (ac *authCache) authorityFor(name string) (string, error) {
	ac.mu.RLock()
	defer ac.mu.RUnlock()

	labels := strings.Split(name, ".")
	for i := range labels {
		zone := strings.Join(labels[i:], ".")
		if zone == "" {
			zone = "."
		}
		fmt.Println(zone)
		if entry, present := ac.cache[zone]; present {
			return entry.addrs[mrand.Intn(len(entry.addrs))], nil
		}
	}
	// if cache has been primed using root hints this should never
	// happen...
	return "", errNoNSAuthorties
}

func splitAuthsByZone(auths []dns.RR, extras []dns.RR, useIPv6 bool) (map[string][]string, map[string]int) {
	zones := make(map[string][]string)
	minTTLs := make(map[string]int)
	nsToZone := make(map[string]string, len(auths))

	for _, rr := range auths {
		if rr.Header().Rrtype == dns.TypeNS {
			ns := rr.(*dns.NS)
			nsToZone[ns.Ns] = rr.Header().Name
		}
	}

	for _, rr := range extras {
		zone, present := nsToZone[rr.Header().Name]
		if present && (rr.Header().Rrtype == dns.TypeA || (useIPv6 && rr.Header().Rrtype == dns.TypeAAAA)) {
			switch a := rr.(type) {
			case *dns.A:
				zones[zone] = append(zones[zone], a.A.String())
			case *dns.AAAA:
				if useIPv6 {
					zones[zone] = append(zones[zone], a.AAAA.String())
				}
			}
			if minTTLs[zone] == 0 || int(rr.Header().Ttl) < minTTLs[zone] {
				minTTLs[zone] = int(rr.Header().Ttl)
			}
		}
	}

	return zones, minTTLs
}
