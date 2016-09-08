package resolver

import (
	"fmt"
	"time"

	"github.com/miekg/dns"
)

type queryLog struct {
	Query       *dns.Question
	AnswerType  string
	CacheHit    bool
	DNSSECValid bool
	RTT         time.Duration
	Error       error

	// Only present if CacheHit == false
	NS     string
	NSAddr string

	// CompositeQueries []queryLog
}

type lookupLog struct {
	Query            *dns.Question
	Started          time.Time
	Latency          time.Duration
	CompositeQueries []queryLog
}

func (ll *lookupLog) sumLatency() {
	sum := time.Duration(0)
	for _, l := range ll.CompositeQueries {
		sum += l.RTT
	}
	ll.Latency = sum
}

func (ll *lookupLog) String() string {
	composite := ""
	for _, l := range ll.CompositeQueries {
		source := ""
		if l.CacheHit {
			source = "cache"
		} else {
			source = fmt.Sprintf("%s (%s)", l.NSAddr, l.NS)
		}
		err := ""
		if l.Error != nil {
			err = fmt.Sprintf(" Error='%s'", l.Error.Error())
		}
		if composite != "" {
			composite = fmt.Sprintf("%s->", composite)
		}
		composite = fmt.Sprintf(
			"%s[Query='%s IN %s' Source='%s' AnswerType='%s' DNSSECValid=%t RTT=%d%s]",
			composite,
			l.Query.Name,
			dns.TypeToString[l.Query.Qtype],
			source,
			l.AnswerType,
			l.DNSSECValid,
			l.RTT.Nanoseconds(),
			err,
		)
	}
	return fmt.Sprintf(
		"Query='%s IN %s' Started=%d Latency=%d %s",
		ll.Query.Name,
		dns.TypeToString[ll.Query.Qtype],
		ll.Started.UnixNano(),
		ll.Latency,
		composite,
	)
}

// Format: {"query"":{}, "latency": ..., "upstream-queries": [{}]}
