package main

import (
	"context"
	"flag"
	"log"
	"os"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/api"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/store"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/transport"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	certFile := flag.String("tls-cert", "", "TLS certificate for the control plane")
	keyFile := flag.String("tls-key", "", "TLS key for the control plane")
	insecure := flag.Bool("insecure", false, "serve a routable address without TLS; credentials then cross the network in the clear")
	flag.Parse()
	token := os.Getenv("SCRUBLINE_API_TOKEN")
	if token == "" {
		log.Fatal("SCRUBLINE_API_TOKEN is required (the operator credential)")
	}
	enrollToken := os.Getenv("SCRUBLINE_ENROLL_TOKEN")
	if enrollToken == "" {
		log.Fatal("SCRUBLINE_ENROLL_TOKEN is required (the credential nodes enroll with)")
	}
	if enrollToken == token {
		// Sharing them gives every scrubber operator access, which is the
		// thing per-node credentials exist to prevent.
		log.Fatal("SCRUBLINE_ENROLL_TOKEN must differ from SCRUBLINE_API_TOKEN")
	}
	srv := &api.Server{Token: token, EnrollToken: enrollToken, Store: store.New()}

	// Keep the fabric compiled against the live node set: a node that joins or
	// recovers between deploys would otherwise hold no program at all.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.StartReconciler(ctx, api.ReconcileInterval)

	scheme := "http"
	if *certFile != "" {
		scheme = "https"
	}
	log.Printf("scrubline cloud api listening on %s://%s (asic/tcam + fpga + pf_ring zc)", scheme, *addr)
	log.Fatal(transport.Serve(transport.Config{
		Addr: *addr, CertFile: *certFile, KeyFile: *keyFile, Insecure: *insecure,
	}, srv.Handler()))
}
