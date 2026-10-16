//go:build ignore

// Generates a throwaway CA and a server certificate for local testing.
//
//	go run scripts/gen-dev-certs.go -dir certs -host 127.0.0.1,localhost,api
//
// These are for development. Nothing here belongs in a deployment: the key
// is written unencrypted and the CA has no protection at all.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	dir := flag.String("dir", "certs", "directory to write the CA and server certificate into")
	hosts := flag.String("host", "127.0.0.1,localhost", "comma-separated hosts and IPs the certificate covers")
	days := flag.Int("days", 90, "certificate lifetime in days")
	flag.Parse()

	if err := os.MkdirAll(*dir, 0o700); err != nil {
		log.Fatalf("creating %s: %v", *dir, err)
	}

	caKey, caDER := mustIssue(&x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "scrubline dev CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(0, 0, *days),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, nil, nil)
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		log.Fatalf("parsing the CA: %v", err)
	}

	leaf := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: "scrubline"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(0, 0, *days),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range strings.Split(*hosts, ",") {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			leaf.IPAddresses = append(leaf.IPAddresses, ip)
			continue
		}
		leaf.DNSNames = append(leaf.DNSNames, h)
	}
	leafKey, leafDER := mustIssue(leaf, caCert, caKey)

	write(filepath.Join(*dir, "ca.pem"), "CERTIFICATE", caDER, 0o644)
	write(filepath.Join(*dir, "server.pem"), "CERTIFICATE", leafDER, 0o644)
	writeKey(filepath.Join(*dir, "server-key.pem"), leafKey)
	log.Printf("wrote %s/ca.pem, %s/server.pem and %s/server-key.pem for %s", *dir, *dir, *dir, *hosts)
}

func mustIssue(tmpl, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*ecdsa.PrivateKey, []byte) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("generating a key: %v", err)
	}
	signer, signerKey := parent, parentKey
	if signer == nil {
		signer, signerKey = tmpl, key // self-signed
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		log.Fatalf("issuing a certificate: %v", err)
	}
	return key, der
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		log.Fatalf("generating a serial: %v", err)
	}
	return n
}

func write(path, blockType string, der []byte, mode os.FileMode) {
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), mode); err != nil {
		log.Fatalf("writing %s: %v", path, err)
	}
}

func writeKey(path string, key *ecdsa.PrivateKey) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		log.Fatalf("encoding the key: %v", err)
	}
	write(path, "EC PRIVATE KEY", der, 0o600)
}
