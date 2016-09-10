package main

import (
	"fmt"
	"time"

	"github.com/miekg/dns"

	"github.com/rolandshoemaker/solvere"
	"github.com/rolandshoemaker/solvere/hints"
)

func main() {
	s := &server{solvere.NewRecursiveResolver(false, true, hints.RootNameservers, hints.RootKeys, solvere.NewBasicCache())}
	dns.HandleFunc(".", s.handler)
	dnsServer := &dns.Server{
		Addr:         "0.0.0.0:53",
		Net:          "udp",
		ReadTimeout:  time.Millisecond,
		WriteTimeout: time.Millisecond,
	}
	err := dnsServer.ListenAndServe()
	if err != nil {
		fmt.Println(err)
		return
	}
}
