package main

import (
	"fmt"
	"time"

	"github.com/miekg/dns"

	"github.com/rolandshoemaker/solvere/hints"
	"github.com/rolandshoemaker/solvere/resolver"
)

func main() {
	s := &server{resolver.NewRecursiveResolver(false, true, hints.RootNameservers, hints.RootKeys, resolver.NewBasicCache())}
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
