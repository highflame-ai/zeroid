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
