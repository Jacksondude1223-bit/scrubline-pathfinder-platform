package main

import (
	"context"
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

	// Keep the fabric compiled against the live node set: a node that joins or
	// recovers between deploys would otherwise hold no program at all.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.StartReconciler(ctx, api.ReconcileInterval)

	log.Printf("scrubline cloud api listening on %s (asic/tcam + fpga + pf_ring zc)", *addr)
	log.Fatal(http.ListenAndServe(*addr, srv.Handler()))
}
