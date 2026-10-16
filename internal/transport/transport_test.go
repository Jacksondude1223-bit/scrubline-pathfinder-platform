package transport

import (
	"crypto/tls"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Serving a routable address in the clear ships credentials across a network
// by omission, so it has to be asked for rather than defaulted into.
func TestRoutableAddressWithoutTLSIsRefused(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:8080", "198.51.100.7:8080", "api.example:8080", ":8080", "[::]:8080"} {
		err := Serve(Config{Addr: addr}, nil)
		if err == nil {
			t.Fatalf("serving %s without TLS should be refused", addr)
		}
		if !strings.Contains(err.Error(), "without TLS") {
			t.Fatalf("addr %s: expected a TLS refusal, got %v", addr, err)
		}
	}
}

// Loopback is reachable only from this host, so the demo path stays simple.
func TestLoopbackIsAllowedWithoutTLS(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:0", "localhost:0", "[::1]:0"} {
		if !isLoopback(addr) {
			t.Fatalf("%s should count as loopback", addr)
		}
	}
	for _, addr := range []string{"0.0.0.0:0", "198.51.100.7:0", "api:0", ""} {
		if isLoopback(addr) {
			t.Fatalf("%s should count as routable", addr)
		}
	}
}

func TestHalfConfiguredTLSIsRefused(t *testing.T) {
	if err := Serve(Config{Addr: "127.0.0.1:0", CertFile: "cert.pem"}, nil); err == nil {
		t.Fatal("a certificate without a key should be refused")
	}
	if err := Serve(Config{Addr: "127.0.0.1:0", KeyFile: "key.pem"}, nil); err == nil {
		t.Fatal("a key without a certificate should be refused")
	}
}

func TestClientRejectsAnUnusableCABundle(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(empty, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("writing the bundle: %v", err)
	}
	if _, err := Client(ClientConfig{CAFile: empty}); err == nil {
		t.Fatal("a bundle with no certificates should be refused")
	}
	if _, err := Client(ClientConfig{CAFile: filepath.Join(dir, "missing.pem")}); err == nil {
		t.Fatal("a missing bundle should be refused")
	}
}

// Verification is never disabled: an unverified TLS connection is a plaintext
// connection that looks safe.
func TestClientAlwaysVerifies(t *testing.T) {
	c, err := Client(ClientConfig{})
	if err != nil {
		t.Fatalf("Client: %v", err)
	}
	if c.Timeout <= 0 {
		t.Fatal("a client without a timeout can hang a poll loop forever")
	}
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("unexpected transport %T", c.Transport)
	}
	if tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("certificate verification is disabled")
	}
	if tr.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatalf("TLS minimum version is %x", tr.TLSClientConfig.MinVersion)
	}
}
