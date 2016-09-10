package resolver

import (
	"crypto/sha1"
	"sync"
	"time"

	"github.com/miekg/dns"
)

func hashQuestion(q *Question) [sha1.Size]byte {
	inp := append([]byte{uint8(q.Type & 0xff), uint8(q.Type >> 8)}, []byte(q.Name)...)
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
	answer   *Answer
	ttl      int
	modified time.Time
	removed  bool
	mu       sync.Mutex
}

func (ca *cacheEntry) update(entry *cacheEntry, answer *Answer, ttl int) {
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.removed {
		return
	}
	// just overwrite the previous one...
	entry.answer = answer
	entry.ttl = ttl
	entry.modified = time.Now()
}

// QuestionAnswerCache is used to cache responses to queries. The internal implementation
// can be bypassed using this interface.
type QuestionAnswerCache interface {
	Get(q *Question) *Answer
	Add(q *Question, answer *Answer, forever bool)
}

// BasicCache is a basic implementation of the QuestionAnswerCache interface
type BasicCache struct {
	mu sync.RWMutex
	// XXX: May want a secondary index of sha256(q.Name, q.Class) for NSEC denial checks...
	cache map[[sha1.Size]byte]*cacheEntry
}

// NewBasicCache returns an initialized BasicCache
func NewBasicCache() *BasicCache {
	return &BasicCache{cache: make(map[[sha1.Size]byte]*cacheEntry)}
}

func (bc *BasicCache) del(entry *cacheEntry, id [sha1.Size]byte) {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	delete(bc.cache, id)
	entry.removed = true
}

func (bc *BasicCache) prune(q *Question, id [sha1.Size]byte, ttl int) {
	sleep := time.Second * time.Duration(ttl)
	for {
		time.Sleep(sleep)
		entry, present := bc.getEntry(q)
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
			bc.del(entry, id)
			entry.mu.Unlock()
			return
		}
		entry.mu.Unlock()
		sleep = new
	}
}

// Add adds a response to the cache using a index based on the question
func (bc *BasicCache) Add(q *Question, answer *Answer, forever bool) {
	id := hashQuestion(q)
	var ttl int
	if !forever {
		ttl = minTTL(append(answer.Answer, append(answer.Additional, answer.Authority...)...))
		if ttl == 0 {
			return
		}
	}
	// should filter out OPT records here
	bc.mu.Lock()
	defer bc.mu.Unlock()
	if entry, present := bc.cache[id]; present {
		bc.cache[id].update(entry, answer, ttl)
		return
	}
	bc.cache[id] = &cacheEntry{
		answer,
		ttl,
		time.Now(),
		false,
		sync.Mutex{},
	}
	if forever {
		return
	}
	go bc.prune(q, id, ttl)
}

func (bc *BasicCache) getEntry(q *Question) (*cacheEntry, bool) {
	id := hashQuestion(q)
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	entry, present := bc.cache[id]
	return entry, present
}

// Get returns the response for a question if it exists in the cache
func (bc *BasicCache) Get(q *Question) *Answer {
	if entry, present := bc.getEntry(q); present {
		entry.mu.Lock()
		defer entry.mu.Unlock()
		if entry.removed {
			return nil
		}
		return entry.answer
	}
	return nil
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
