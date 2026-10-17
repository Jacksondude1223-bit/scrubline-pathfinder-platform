// Package transport builds the HTTP servers and clients both binaries use.
//
// It exists so that the TLS posture, the listener timeouts, and the refusal to
// serve a routable address in the clear are decided once rather than twice.
package transport

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

const (
	// readHeaderTimeout bounds how long a peer may take to send its request
	// headers. Without it a handful of idle connections hold a listener open
	// indefinitely, which is a poor look on a DDoS appliance.
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 30 * time.Second
	writeTimeout      = 60 * time.Second
	idleTimeout       = 120 * time.Second
	maxHeaderBytes    = 1 << 16
)

// Config describes how a listener should be served.
type Config struct {
	Addr string
	// CertFile and KeyFile turn on TLS. Both or neither.
	CertFile string
	KeyFile  string
	// Insecure allows serving a routable address without TLS. It has to be
	// asked for: the default refuses, because the alternative is shipping
	// credentials across a network in the clear by omission.
	Insecure bool
}

// Serve runs h on cfg.Addr until it fails. A routable address without TLS is
// refused unless Insecure is set.
func Serve(cfg Config, h http.Handler) error {
	if (cfg.CertFile == "") != (cfg.KeyFile == "") {
		return errors.New("TLS needs both a certificate and a key, or neither")
	}
	tlsOn := cfg.CertFile != ""
	if !tlsOn && !cfg.Insecure && !isLoopback(cfg.Addr) {
		return fmt.Errorf("refusing to serve %s without TLS: pass a certificate and key, "+
			"or -insecure if this listener is already on a trusted network", cfg.Addr)
	}

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           h,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}
	if !tlsOn {
		return srv.ListenAndServe()
	}
	srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return srv.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile)
}

// isLoopback reports whether an address is reachable only from this host. A
// hostname that is not plainly a loopback literal counts as routable: guessing
// wrong in that direction only costs a flag.
func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	switch host {
	case "localhost":
		return true
	case "", "0.0.0.0", "::", "[::]":
		// A wildcard bind is reachable from anywhere the host is.
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ClientConfig describes how to reach a peer.
type ClientConfig struct {
	// CAFile is a PEM bundle to verify the peer against, for a private CA.
	// Empty uses the system roots.
	CAFile string
	// Timeout bounds a whole request.
	Timeout time.Duration
}

// Client builds an HTTP client. Certificate verification is never disabled:
// an unverified TLS connection is a plaintext connection that looks safe.
func Client(cfg ClientConfig) (*http.Client, error) {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("reading CA bundle: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CA bundle %s contains no certificates", cfg.CAFile)
		}
		tlsCfg.RootCAs = pool
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}, nil
}
