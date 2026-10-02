package main

import (
	"flag"
	"log"
	"net/http"
	"os"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/api"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/store"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	flag.Parse()
	token := os.Getenv("SCRUBLINE_API_TOKEN")
	if token == "" {
		log.Fatal("SCRUBLINE_API_TOKEN is required")
	}
	srv := &api.Server{Token: token, Store: store.New()}
	log.Printf("scrubline cloud api listening on %s (asic/tcam + fpga + pf_ring zc)", *addr)
	log.Fatal(http.ListenAndServe(*addr, srv.Handler()))
}
