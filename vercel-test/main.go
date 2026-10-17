package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/api"
	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/store"
)

func newHandler(token, enroll string) (http.Handler, error) {
	if token == "" || enroll == "" {
		return nil, fmt.Errorf("SCRUBLINE_API_TOKEN and SCRUBLINE_ENROLL_TOKEN are required")
	}
	if token == enroll {
		return nil, fmt.Errorf("SCRUBLINE_API_TOKEN and SCRUBLINE_ENROLL_TOKEN must differ")
	}
	srv := &api.Server{Token: token, EnrollToken: enroll, Store: store.New()}
	srv.SetMode(api.ModePrimary)
	control := srv.Handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Scrubline-Test-Mode", "ephemeral-memory")
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"service": "scrubline-control-plane-test", "health": "/health",
				"storage": "ephemeral-memory", "scope": "control-plane-only",
			})
			return
		}
		control.ServeHTTP(w, r)
	}), nil
}

func main() {
	handler, err := newHandler(os.Getenv("SCRUBLINE_API_TOKEN"), os.Getenv("SCRUBLINE_ENROLL_TOKEN"))
	if err != nil {
		log.Fatal(err)
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	log.Printf("temporary control-plane API listening on port %s; state resets between instances", port)
	srv := &http.Server{Addr: ":" + port, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
