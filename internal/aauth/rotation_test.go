package aauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeKey(t *testing.T, dir, name string, public bool) (string, ed25519.PrivateKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if public {
		der, err := x509.MarshalPKIXPublicKey(priv.Public())
		if err != nil {
			t.Fatal(err)
		}
		block = &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	} else {
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		block = &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, priv
}

// TestSigningKeyRotation: after the signing key is replaced, tokens the old
// key signed still verify while it is published as retired, new tokens are
// signed by the new key, and a key that is not published is refused.
func TestSigningKeyRotation(t *testing.T) {
	dir := t.TempDir()
	const issuer = "https://ap.example"
	oldPath, _ := writeKey(t, dir, "old.pem", false)
	newPath, _ := writeKey(t, dir, "new.pem", false)
	strangerPath, _ := writeKey(t, dir, "stranger.pem", false)

	_, agentPriv, _ := ed25519.GenerateKey(rand.Reader)
	cnf := Ed25519JWK(agentPriv.Public().(ed25519.PublicKey))
	now := time.Now()
	mint := func(k *signingKey) string {
		t.Helper()
		tok, err := k.sign(issuer, "aauth:a@ap.example", cnf, "jti-"+k.jwk.Kid, now, now.Add(10*time.Minute), tokenExtras{})
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}

	before, err := loadSigningKey(oldPath, "")
	if err != nil {
		t.Fatal(err)
	}
	oldToken := mint(before)

	after, err := loadSigningKey(newPath, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := after.addRetired(oldPath, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := after.verify(oldToken, issuer, now); err != nil {
		t.Fatalf("a token signed before the rotation: %v", err)
	}
	newToken := mint(after)
	if _, err := after.verify(newToken, issuer, now); err != nil {
		t.Fatalf("a token signed after the rotation: %v", err)
	}
	if _, err := before.verify(newToken, issuer, now); err == nil {
		t.Fatal("the old key set accepted a token from a key it does not publish")
	}
	keys := after.jwks()["keys"].([]JWK)
	if len(keys) != 2 || keys[0].Kid != after.jwk.Kid || keys[1].Kid != before.jwk.Kid || keys[1].Alg != AlgEd25519 {
		t.Fatalf("published keys: %+v", keys)
	}

	stranger, err := loadSigningKey(strangerPath, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := after.verify(mint(stranger), issuer, now); err == nil {
		t.Fatal("a token from an unpublished key verified")
	}

	// A retired key may be given as its public half, under the kid it signed with.
	pubPath, _ := writeKey(t, dir, "retired-public.pem", true)
	if err := after.addRetired(pubPath, "key-2025"); err != nil {
		t.Fatalf("PKIX public key: %v", err)
	}
	if err := after.addRetired(oldPath, ""); err == nil {
		t.Fatal("the same retired key was published twice")
	}
	if err := after.addRetired(newPath, "other-kid"); err == nil {
		t.Fatal("the current key was published again as retired")
	}
}
