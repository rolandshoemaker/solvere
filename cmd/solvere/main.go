package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/miekg/dns"

	"github.com/rolandshoemaker/solvere"
	"github.com/rolandshoemaker/solvere/hints"
)

func main() {
	listenAddr := flag.String("listen", "127.0.0.1:53", "")
	flag.Parse()

	s := &server{solvere.NewRecursiveResolver(false, true, hints.RootNameservers, hints.RootKeys, solvere.NewBasicCache())}
	dns.HandleFunc(".", s.handler)
	dnsServer := &dns.Server{
		Addr:         *listenAddr,
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
