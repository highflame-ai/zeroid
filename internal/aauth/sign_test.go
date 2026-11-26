package aauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestSignAsServerVerifies signs a revocation as the Agent Provider and
// verifies it with the package's own verifier, as a person server would
// after discovering the key from id, dwk and kid.
func TestSignAsServerVerifies(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := Ed25519JWK(pub)
	jwk.Kid = "ap-key-1"
	k := &signingKey{priv: priv, jwk: jwk}

	body := []byte(`{"jti":"abc","exp":1900000000}`)
	req, _ := http.NewRequest(http.MethodPost, "https://ps.example/revoke", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	now := time.Now()
	if err := k.signAsServer(req, body, "https://ap.example", now); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get(HeaderSignatureKey); got != `sig=jwks_uri;id="https://ap.example";dwk="aauth-agent.json";kid="ap-key-1"` {
		t.Fatalf("Signature-Key = %s", got)
	}
	if !strings.Contains(req.Header.Get(HeaderSignatureInput), `"content-digest" "content-type");created=`) {
		t.Fatalf("Signature-Input does not cover the body: %s", req.Header.Get(HeaderSignatureInput))
	}

	// As received by ps.example.
	req.Host = "ps.example"
	var gotParams map[string]any
	v, err := VerifyRequest(req, body, VerifyOptions{
		Now: now, Authority: "ps.example", RequireBodyCoverage: true, Schemes: []string{"jwks_uri"},
		ResolveKey: func(_ string, params map[string]any) (JWK, error) { gotParams = params; return jwk, nil },
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if v.Scheme != "jwks_uri" || gotParams["id"] != "https://ap.example" || gotParams["dwk"] != AgentMetadataDWK || gotParams["kid"] != "ap-key-1" {
		t.Fatalf("scheme %s, params %v", v.Scheme, gotParams)
	}

	// A body changed after signing does not verify.
	if _, err := VerifyRequest(req, []byte(`{"jti":"xyz","exp":1900000000}`), VerifyOptions{
		Now: now, Authority: "ps.example", RequireBodyCoverage: true, Schemes: []string{"jwks_uri"},
		ResolveKey: func(string, map[string]any) (JWK, error) { return jwk, nil },
	}); err == nil {
		t.Fatal("a changed body verified")
	}

	// A bodiless poll covers only the base components.
	poll, _ := http.NewRequest(http.MethodGet, "https://ps.example:443/pending/1", nil)
	if err := k.signAsServer(poll, nil, "https://ap.example", now); err != nil {
		t.Fatal(err)
	}
	poll.Host = "ps.example"
	if _, err := VerifyRequest(poll, nil, VerifyOptions{
		Now: now, Authority: "ps.example", Schemes: []string{"jwks_uri"},
		ResolveKey: func(string, map[string]any) (JWK, error) { return jwk, nil },
	}); err != nil {
		t.Fatalf("verify poll: %v", err)
	}
}

// TestJWKStrictBase64 refuses a non-canonical encoding of a key: the spare
// bits of Ed25519's last base64url character would otherwise let one key
// present several thumbprints.
func TestJWKStrictBase64(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k := Ed25519JWK(pub)
	if _, err := k.PublicKey(); err != nil {
		t.Fatal(err)
	}
	last := k.X[len(k.X)-1]
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	i := strings.IndexByte(alphabet, last)
	k.X = k.X[:len(k.X)-1] + string(alphabet[i^1]) // flip a spare bit
	if _, err := k.PublicKey(); err == nil {
		t.Fatal("a non-canonical x was accepted")
	}
}
