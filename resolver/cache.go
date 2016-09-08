package resolver

import (
	"crypto/sha1"
	// "fmt"
	// mrand "math/rand"
	// "strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

func hashQuestion(q *dns.Question) [sha1.Size]byte {
	inp := append([]byte{uint8(q.Qtype & 0xff), uint8(q.Qtype >> 8), uint8(q.Qclass & 0xff), uint8(q.Qclass >> 8)}, []byte(q.Name)...)
	return sha1.Sum(inp)
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
	answer        []dns.RR
	auth          []dns.RR
	extra         []dns.RR
	authenticated bool
	ttl           int
	modified      time.Time
	removed       bool
	mu            sync.Mutex
}

func (ca *cacheEntry) update(entry *cacheEntry, answer, auth, extra []dns.RR, ttl int, authenticated bool) {
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.removed {
		return
	}
	// just overwrite the previous one...
	entry.answer = answer
	entry.auth = auth
	entry.extra = extra
	entry.authenticated = authenticated
	entry.ttl = ttl
	entry.modified = time.Now()
}

type qaCache struct {
	mu sync.RWMutex
	// XXX: May want a secondary index of sha256(q.Name, q.Class) for NSEC denial checks...
	cache map[[sha1.Size]byte]*cacheEntry
}

func (qac *qaCache) del(entry *cacheEntry, id [sha1.Size]byte) {
	qac.mu.Lock()
	defer qac.mu.Unlock()
	delete(qac.cache, id)
	entry.removed = true
}

func (qac *qaCache) prune(q *dns.Question, id [sha1.Size]byte, ttl int) {
	sleep := time.Second * time.Duration(ttl)
	for {
		time.Sleep(sleep)
		entry, present := qac.getEntry(q)
		if !present {
			return
		}
		entry.mu.Lock()
		if entry.removed {
			entry.mu.Unlock()
			return
		}
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

func (qac *qaCache) add(q *dns.Question, answer, auth, extra []dns.RR, authenticated, forever bool) {
	id := hashQuestion(q)
	var ttl int
	if !forever {
		ttl = minTTL(append(answer, append(auth, extra...)...))
	}
	// should filter out OPT records here
	qac.mu.Lock()
	defer qac.mu.Unlock()
	if entry, present := qac.cache[id]; present {
		qac.cache[id].update(entry, answer, auth, extra, ttl, authenticated)
		return
	}
	qac.cache[id] = &cacheEntry{answer, auth, extra, authenticated, ttl, time.Now(), false, sync.Mutex{}}
	if ttl > 0 {
		go qac.prune(q, id, ttl)
	}
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

func splitAuthsByZone(auths []dns.RR, extras []dns.RR, useIPv6 bool) (map[string][]string, map[string]int, map[string]string) {
	zones := make(map[string][]string)
	minTTLs := make(map[string]int)
	nsToZone := make(map[string]string)

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

	return zones, minTTLs, nsToZone
}
