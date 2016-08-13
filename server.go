package main

import (
	"encoding/binary"
	"fmt"
	mrand "math/rand"

	"github.com/miekg/dns"
	"golang.org/x/net/context"
	"golang.org/x/net/trace"
)

func genID() string {
	i32 := mrand.Uint32()
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, i32)
	return fmt.Sprintf("%x", b)
}

func handler(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.RecursionAvailable = true
	// m.Compress = true

	if len(r.Question) == 0 || len(r.Question) > 1 {
		m.Rcode = dns.RcodeNotImplemented
		w.WriteMsg(m)
		return
	}

	tr := trace.New("resolver-request", r.Question[0].String())
	defer tr.Finish()
	ctx := trace.NewContext(context.WithValue(context.Background(), "request-id", genID()), tr)

	a, err := recursiveResolve(ctx, r.Question[0], "", 0)
	if err != nil {
		fmt.Printf(
			"Request %s: error resolving '%s %s %s': %s\n", ctx.Value("request-id"),
			r.Question[0].Name,
			dns.ClassToString[r.Question[0].Qclass],
			dns.TypeToString[r.Question[0].Qtype],
			err,
		)
		m.Rcode = dns.RcodeServerFailure
		w.WriteMsg(m)
		tr.SetError()
		return
	}
	m.Rcode = a.rcode
	m.Answer = a.answer
	m.Ns = a.authority
	m.Extra = a.additional
	w.WriteMsg(m)
	return
}
