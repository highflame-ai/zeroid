package service

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestVerifyClientSecret(t *testing.T) {
	const secret = "4f2c0d9e8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e"

	stored := hashClientSecret(secret)
	if !strings.HasPrefix(stored, sha256SecretPrefix) {
		t.Fatalf("hash %q missing %q prefix", stored, sha256SecretPrefix)
	}
	if ok, legacy := verifyClientSecret(stored, secret); !ok || legacy {
		t.Errorf("sha256 correct secret: ok=%v legacy=%v, want true false", ok, legacy)
	}
	if ok, _ := verifyClientSecret(stored, secret+"x"); ok {
		t.Error("sha256 wrong secret verified")
	}

	b, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if ok, legacy := verifyClientSecret(string(b), secret); !ok || !legacy {
		t.Errorf("bcrypt correct secret: ok=%v legacy=%v, want true true", ok, legacy)
	}
	if ok, legacy := verifyClientSecret(string(b), "wrong"); ok || legacy {
		t.Errorf("bcrypt wrong secret: ok=%v legacy=%v, want false false", ok, legacy)
	}

	// A public client stores "" — nothing may verify against it, including "".
	if ok, _ := verifyClientSecret("", ""); ok {
		t.Error("empty stored hash verified")
	}
	// The digest itself is not a credential.
	if ok, _ := verifyClientSecret(stored, stored); ok {
		t.Error("stored digest accepted as the secret")
	}
}

func TestHashNewSecretRespectsSetting(t *testing.T) {
	const secret = "4f2c0d9e8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e"
	s := &OAuthClientService{}

	// Off (the default): bcrypt, readable by builds that predate SHA-256.
	h, err := s.hashNewSecret(secret, bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(h, sha256SecretPrefix) || bcrypt.CompareHashAndPassword([]byte(h), []byte(secret)) != nil {
		t.Errorf("default must store bcrypt, got %q", h)
	}

	s.SetSHA256ClientSecrets(true)
	if h, _ = s.hashNewSecret(secret, bcrypt.MinCost); h != hashClientSecret(secret) {
		t.Errorf("enabled must store SHA-256, got %q", h)
	}
}

func TestShouldUpgradeSecretHash(t *testing.T) {
	const generated = "4f2c0d9e8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e"
	for _, tc := range []struct {
		name            string
		legacy, enabled bool
		secret          string
		want            bool
	}{
		{"legacy, enabled, generated", true, true, generated, true},
		{"setting off keeps bcrypt", true, false, generated, false},
		{"already sha256", false, true, generated, false},
		{"human-chosen secret keeps bcrypt", true, true, "MyTeamPassword1", false},
		{"uppercase hex is not ours", true, true, strings.ToUpper(generated), false},
		{"wrong length", true, true, generated[:63], false},
	} {
		if got := shouldUpgradeSecretHash(tc.legacy, tc.enabled, tc.secret); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}
