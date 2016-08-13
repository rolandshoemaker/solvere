package main

import (
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
	"time"

	"github.com/miekg/dns"
)

func main() {
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()
	dns.HandleFunc(".", handler)
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
