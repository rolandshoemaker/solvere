package resolver

import (
	"crypto/sha256"
	"sync"
)

func hashQuestion(q dns.Question) [32]byte {
	inp := append([]byte{q.Qtype, q.Qclass}, []byte{q.Qtype, q.Qclass}...)
	return sha256.Sum256(inp)
}

func minTTL(a []dns.RR) int {
	var min *int
	for _, r := range a {
		if min == nil {
			min = r.Header().TTL
			continue
		}
		if r.Header().TTL < min {
			min = r.Header().TTL
		}
	}
	return min
}

type cacheEntry struct {
	answer   []dns.RR
	ttl      int
	modified time.Time
}

func (ca *cacheEntry) update(answer, auth, extra []dns.RR) {

}

type qaCache struct {
	mu    sync.RWMutex
	cache map[[32]byte]*cacheEntry
}

func (qac *qaCache) prune(id [32]byte, ttl int) {
	sleep := time.Second * ttl
	for {
		time.Sleep(sleep)
		entry, present := qac.get(q)
		if !present {
			return
		}
		if entry.modified.Add(time.Second * entry.ttl).After(time.Now()) {
			qac.mu.Lock()
			defer qac.mu.Unlock()
			delete(qac.answer, id)
			return
		}
		new := time.Now().Sub(entry.modified.Add(time.Second * entry.ttl))
		if new < 0 {
			qac.mu.Lock()
			defer qac.mu.Unlock()
			delete(qac.answer, id)
			return
		}
		sleep = new
	}
}

func (qac *qaCache) add(q *dns.Question, a []dns.RR, ttl int) {
	id := hashQuestion(q)
	ttl := minTTL(a)
	qac.mu.Lock()
	defer qac.mu.Unlock()
	if entry, present := qac[id]; present {
		qac[id].update(a, auth, ttl)
	} else {
		qac[id] = &cacheEntry{a, ttl, time.Now()}
		go qac.prune(id, minTTL)
	}
}

func (qac *qaCache) get(q *dns.Question) ([]dns.RR, bool) {
	id := hashQuestion(q)
	qac.mu.RLock()
	defer qac.mu.RUnlock()
	if entry, present := qac[id]; present {
		return entry.answer, true
	}
	return nil, false
}
