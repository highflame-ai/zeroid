package demo

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"
)

// ClientTrusting returns an HTTP client that trusts the system roots plus
// the CA certificate at caFile (in the compose demo, Caddy's local CA). It
// waits up to wait for the file to appear, since Caddy writes it on first
// start. An empty caFile trusts the system roots only.
func ClientTrusting(caFile string, wait time.Duration) (*http.Client, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if caFile != "" {
		deadline := time.Now().Add(wait)
		for {
			pem, err := os.ReadFile(caFile)
			if err == nil && pool.AppendCertsFromPEM(pem) {
				break
			}
			if time.Now().After(deadline) {
				return nil, fmt.Errorf("no CA certificate at %s after %s", caFile, wait)
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
	return &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}, nil
}

// Env returns the environment variable name, or def when it is unset.
func Env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}
