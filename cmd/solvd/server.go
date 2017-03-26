package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/miekg/dns"

	"github.com/rolandshoemaker/solvere"
)

type server struct {
	rr *solvere.RecursiveResolver
}

func (s *server) handler(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.RecursionAvailable = true
	// m.Compress = true

	if len(r.Question) == 0 || len(r.Question) > 1 {
		m.Rcode = dns.RcodeNotImplemented
		w.WriteMsg(m)
		return
	}

	q := solvere.Question{r.Question[0].Name, r.Question[0].Qtype}
	ctx := context.TODO()

	a, log, err := s.rr.Lookup(ctx, q)
	if err != nil {
		fmt.Println("Query failed:", err)
	}
	j, jerr := json.Marshal(log)
	if jerr != nil {
		fmt.Println("err encoding log message")
		return
	}
	fmt.Println(string(j))

	if err != nil {
		// fmt.Printf(
		// 	"Request failed: error resolving '%s IN %s': %s\n",
		// 	q.Name,
		// 	dns.TypeToString[q.Type],
		// 	err,
		// )
		m.Rcode = dns.RcodeServerFailure
		w.WriteMsg(m)
		return
	}
	m.Rcode = a.Rcode
	m.AuthenticatedData = a.Authenticated
	m.Answer = a.Answer
	m.Ns = a.Authority
	m.Extra = a.Additional
	w.WriteMsg(m)
	return
}
