package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/api"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/store"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/transport"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	certFile := flag.String("tls-cert", "", "TLS certificate for the control plane")
	keyFile := flag.String("tls-key", "", "TLS key for the control plane")
	insecure := flag.Bool("insecure", false, "serve a routable address without TLS; credentials then cross the network in the clear")
	statePath := flag.String("state", "", "file to keep control-plane state in; empty runs without persistence and loses everything on restart")
	role := flag.String("role", "primary", "primary or replica")
	primaryURL := flag.String("primary", "", "primary control plane a replica follows")
	caFile := flag.String("ca", "", "PEM bundle to verify the primary against; empty uses the system roots")
	followEvery := flag.Duration("follow-interval", 10*time.Second, "how often a replica pulls the primary's state")
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
	mode := api.Mode(*role)
	switch mode {
	case api.ModePrimary:
		if *primaryURL != "" {
			log.Fatal("-primary only applies to -role replica")
		}
	case api.ModeReplica:
		if *primaryURL == "" {
			log.Fatal("-role replica needs -primary")
		}
	default:
		log.Fatalf("-role must be %q or %q, got %q", api.ModePrimary, api.ModeReplica, *role)
	}

	if *statePath == "" {
		log.Printf("warning: no -state file, so policies, credentials and the model are lost on restart")
	}
	st, err := store.Open(*statePath)
	if err != nil {
		log.Fatalf("opening the control-plane state: %v", err)
	}
	srv := &api.Server{Token: token, EnrollToken: enrollToken, Store: st}
	srv.SetMode(mode)

	// Keep the fabric compiled against the live node set: a node that joins or
	// recovers between deploys would otherwise hold no program at all.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.StartReconciler(ctx, api.ReconcileInterval)

	if mode == api.ModeReplica {
		client, err := transport.Client(transport.ClientConfig{CAFile: *caFile, Timeout: 30 * time.Second})
		if err != nil {
			log.Fatalf("configuring the client for the primary: %v", err)
		}
		go follow(ctx, client, srv, *primaryURL, token, *followEvery)
	}

	scheme := "http"
	if *certFile != "" {
		scheme = "https"
	}
	log.Printf("scrubline cloud %s listening on %s://%s (asic/tcam + fpga + pf_ring zc)", mode, scheme, *addr)
	log.Fatal(transport.Serve(transport.Config{
		Addr: *addr, CertFile: *certFile, KeyFile: *keyFile, Insecure: *insecure,
	}, srv.Handler()))
}

// follow keeps a replica's state current with its primary. It pulls rather
// than being pushed, so a replica that was down catches up on its own without
// the primary having to track who is behind.
//
// A replica that cannot reach its primary keeps serving the state it has. It
// does not promote itself: nothing reachable from here can tell a dead
// primary from an unreachable one, and two primaries would compile
// conflicting announcement plans.
func follow(ctx context.Context, client *http.Client, srv *api.Server, primary, token string, every time.Duration) {
	if every <= 0 {
		every = 10 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	var lastSaved time.Time
	for {
		if srv.Mode() != api.ModeReplica {
			log.Printf("replica: promoted, no longer following %s", primary)
			return
		}
		snap, err := fetchState(ctx, client, primary, token)
		if err != nil {
			log.Printf("replica: pulling state from %s: %v", primary, err)
		} else if !snap.SavedAt.Equal(lastSaved) {
			if err := srv.Store.Load(snap); err != nil {
				log.Printf("replica: applying state from %s: %v", primary, err)
			} else {
				lastSaved = snap.SavedAt
				log.Printf("replica: following %s, state as of %s (%d nodes, %d policies)",
					primary, snap.SavedAt.Format(time.RFC3339), len(snap.Nodes), len(snap.Policies))
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func fetchState(ctx context.Context, client *http.Client, primary, token string) (store.Snapshot, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(primary, "/")+"/v1/state", nil)
	if err != nil {
		return store.Snapshot{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return store.Snapshot{}, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return store.Snapshot{}, fmt.Errorf("%s returned %s", primary, resp.Status)
	}
	var snap store.Snapshot
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256<<20)).Decode(&snap); err != nil {
		return store.Snapshot{}, fmt.Errorf("decoding state: %w", err)
	}
	return snap, nil
}
