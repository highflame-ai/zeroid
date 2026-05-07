package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/pkg/authjwt"
)

// insecureHTTPClient returns an http.Client that skips TLS verification —
// used to talk to the httptest TLS server, whose self-signed cert is not in
// the system trust store.
func insecureHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec
	}
}

// fakeJWKSServer publishes a JWKS containing a single ES256 key. The
// rotateKey method swaps in a new key and bumps the served kid — used by
// the rotation test to verify on-demand JWKS refresh works.
type fakeJWKSServer struct {
	t       *testing.T
	srv     *httptest.Server
	hits    atomic.Int64
	keySet  jwk.Set
	curPriv *ecdsa.PrivateKey
}

func newFakeJWKSServer(t *testing.T, kid string) *fakeJWKSServer {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ec key: %v", err)
	}
	keySet := jwk.NewSet()
	pub, err := jwk.FromRaw(&priv.PublicKey)
	if err != nil {
		t.Fatalf("jwk.FromRaw: %v", err)
	}
	_ = pub.Set(jwk.KeyIDKey, kid)
	_ = pub.Set(jwk.AlgorithmKey, jwa.ES256)
	_ = pub.Set(jwk.KeyUsageKey, jwk.ForSignature)
	_ = keySet.AddKey(pub)

	f := &fakeJWKSServer{t: t, keySet: keySet, curPriv: priv}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(f.keySet)
	}))
	return f
}

func (f *fakeJWKSServer) URL() string { return f.srv.URL }

func (f *fakeJWKSServer) Close() { f.srv.Close() }

func (f *fakeJWKSServer) Hits() int64 { return f.hits.Load() }

// TestExternalIssuerRegistry_LifecycleAndLookup exercises the registry
// happy path: synchronous initial JWKS fetch on construction, lookup by
// configured iss, miss for an unconfigured iss, and clean shutdown.
func TestExternalIssuerRegistry_LifecycleAndLookup(t *testing.T) {
	jwks := newFakeJWKSServer(t, "test-kid-1")
	defer jwks.Close()

	cfg := domain.ExternalIssuerConfig{
		Issuer:       "https://auth.example.test",
		JWKSURI:      jwks.URL(),
		Audience:     "https://zeroid.example.test",
		ClaimMapping: map[string]string{"user_id": "sub"},
	}
	cfg.Defaults()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	registry, err := NewExternalIssuerRegistry(
		context.Background(),
		[]domain.ExternalIssuerConfig{cfg},
		authjwt.WithHTTPClient(insecureHTTPClient(2*time.Second)),
	)
	if err != nil {
		t.Fatalf("NewExternalIssuerRegistry: %v", err)
	}
	defer registry.Close()

	if !registry.HasAny() {
		t.Fatalf("HasAny() = false, want true after registering one issuer")
	}
	if jwks.Hits() == 0 {
		t.Fatalf("expected JWKS to be fetched synchronously on registry construction; hit count = 0")
	}

	entry := registry.Lookup(cfg.Issuer)
	if entry == nil {
		t.Fatalf("Lookup(%q) returned nil; want non-nil entry", cfg.Issuer)
	}
	if entry.Config.Issuer != cfg.Issuer {
		t.Errorf("entry.Config.Issuer = %q, want %q", entry.Config.Issuer, cfg.Issuer)
	}
	if entry.JWKS == nil {
		t.Fatalf("entry.JWKS is nil; expected a configured JWKS client")
	}
	if entry.JWKS.KeySet() == nil || entry.JWKS.KeySet().Len() != 1 {
		t.Fatalf("expected JWKS client to hold exactly 1 key; got %v", entry.JWKS.KeySet())
	}

	if registry.Lookup("https://unknown.example.test") != nil {
		t.Errorf("Lookup of unconfigured issuer should return nil")
	}
}

// TestExternalIssuerRegistry_FailsFastOnUnreachableJWKS confirms that a
// misconfigured issuer (unreachable JWKS URL) fails registry construction
// instead of silently registering and breaking the first token-exchange
// request.
func TestExternalIssuerRegistry_FailsFastOnUnreachableJWKS(t *testing.T) {
	cfg := domain.ExternalIssuerConfig{
		Issuer:       "https://auth.example.test",
		JWKSURI:      "https://127.0.0.1:1/.well-known/jwks.json", // port 1 is reserved → connect refused
		Audience:     "https://zeroid.example.test",
		ClaimMapping: map[string]string{"user_id": "sub"},
	}
	cfg.Defaults()

	_, err := NewExternalIssuerRegistry(
		context.Background(),
		[]domain.ExternalIssuerConfig{cfg},
		authjwt.WithHTTPClient(insecureHTTPClient(500*time.Millisecond)),
	)
	if err == nil {
		t.Fatalf("expected NewExternalIssuerRegistry to fail when JWKS is unreachable; got nil")
	}
}
