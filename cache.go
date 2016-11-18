package solvere

import (
	"crypto/sha1"
	"math"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/jmhodges/clock"
)

func hashQuestion(q *Question) [sha1.Size]byte {
	inp := append([]byte{uint8(q.Type & 0xff), uint8(q.Type >> 8)}, []byte(q.Name)...)
	return sha1.Sum(inp)
}

const (
	year68 = int64(1 << 31)
)

func minTTL(a []dns.RR, clk clock.Clock) int {
	var min *uint32
	for _, r := range a {
		if min == nil {
			min = &r.Header().Ttl
			continue
		}
		if r.Header().Ttl < *min {
			min = &r.Header().Ttl
		}
		if r.Header().Rrtype == dns.TypeRRSIG {
			// if expiration is lower than Ttl then use that instead so we always
			// use fresh signatures
			rr := r.(*dns.RRSIG)
			n := clk.Now().UTC().Unix()
			mod := (int64(rr.Expiration) - n) / year68
			t := int64(rr.Expiration) + (mod * year68)
			expiresIn := (t - n) / 1000000000 // convert to seconds
			if expiresIn > 0 && expiresIn < math.MaxUint32 && uint32(expiresIn) < *min {
				uei := uint32(expiresIn)
				min = &uei
			}
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
	forever  bool
	mu       sync.Mutex
}

func (ce *cacheEntry) update(answer *Answer, ttl int, clk clock.Clock) {
	ce.mu.Lock()
	defer ce.mu.Unlock()
	// just overwrite the previous one...
	ce.answer = answer
	ce.ttl = ttl
	ce.modified = clk.Now()
}

func (ce *cacheEntry) expired(clk clock.Clock) bool {
	ce.mu.Lock()
	defer ce.mu.Unlock()
	if ce.forever {
		return false
	}
	return clk.Now().After(ce.modified.Add(time.Second * time.Duration(ce.ttl)))
}

// QuestionAnswerCache is used to cache responses to queries. The internal implementation
// can be bypassed using this interface.
type QuestionAnswerCache interface {
	Get(q *Question) *Answer
	Add(q *Question, answer *Answer, forever bool)
}

// BasicCache is a basic implementation of the QuestionAnswerCache interface
type BasicCache struct {
	mu    sync.RWMutex
	cache map[[sha1.Size]byte]*cacheEntry
	clk   clock.Clock
}

var defaultPruneInterval = time.Minute

// NewBasicCache returns an initialized BasicCache
func NewBasicCache() *BasicCache {
	bc := &BasicCache{cache: make(map[[sha1.Size]byte]*cacheEntry), clk: clock.Default()}
	go func() {
		t := time.NewTicker(defaultPruneInterval)
		for range t.C {
			bc.fullPrune()
		}
	}()
	return bc
}

func (bc *BasicCache) del(id [sha1.Size]byte) {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	delete(bc.cache, id)
}

func (bc *BasicCache) fullPrune() {
	ids := [][sha1.Size]byte{}
	bc.mu.RLock()
	for id, a := range bc.cache {
		if a.expired(bc.clk) {
			ids = append(ids, id)
		}
	}
	bc.mu.RUnlock()
	for _, id := range ids {
		bc.del(id)
	}
}

// Add adds a response to the cache using a index based on the question
func (bc *BasicCache) Add(q *Question, answer *Answer, forever bool) {
	id := hashQuestion(q)
	var ttl int
	if !forever {
		ttl = minTTL(append(answer.Answer, append(answer.Additional, answer.Authority...)...), bc.clk)
		if ttl == 0 {
			return
		}
	}
	// should filter out OPT records here
	bc.mu.Lock()
	defer bc.mu.Unlock()
	if _, present := bc.cache[id]; present {
		bc.cache[id].update(answer, ttl, bc.clk)
		return
	}
	bc.cache[id] = &cacheEntry{
		answer,
		ttl,
		bc.clk.Now(),
		forever,
		sync.Mutex{},
	}
	if forever {
		return
	}
	// go bc.prune(q, id, ttl)
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
		return entry.answer
	}
	return nil
}
