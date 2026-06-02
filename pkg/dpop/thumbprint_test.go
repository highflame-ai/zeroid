package dpop

import (
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwk"
)

func TestJKT_NilKey(t *testing.T) {
	_, err := JKT(nil)
	if err == nil {
		t.Fatal("nil key should error")
	}
}

func TestJKT_StablePerKey(t *testing.T) {
	// Different alg families — each produces a deterministic, stable thumbprint.
	for _, alg := range []string{"ES256", "ES384", "EdDSA", "RS256"} {
		t.Run(alg, func(t *testing.T) {
			k := genTestKey(t, alg)
			t1, err := JKT(k.public)
			if err != nil {
				t.Fatalf("JKT: %v", err)
			}
			t2, err := JKT(k.public)
			if err != nil {
				t.Fatalf("JKT (second call): %v", err)
			}
			if t1 != t2 {
				t.Fatalf("thumbprint not stable: %q vs %q", t1, t2)
			}
			if t1 == "" {
				t.Fatal("thumbprint is empty")
			}
		})
	}
}

func TestJKT_PrivateAndPublicMatch(t *testing.T) {
	// The thumbprint of the private key (which has the public material inside)
	// must equal the thumbprint of the corresponding public key. This is the
	// RFC 7638 contract — thumbprint is over the public-required members only.
	for _, alg := range []string{"ES256", "EdDSA", "RS256"} {
		t.Run(alg, func(t *testing.T) {
			k := genTestKey(t, alg)
			pubT, err := JKT(k.public)
			if err != nil {
				t.Fatalf("JKT(public): %v", err)
			}
			privT, err := JKT(k.private)
			if err != nil {
				t.Fatalf("JKT(private): %v", err)
			}
			if pubT != privT {
				t.Fatalf("priv/pub thumbprints differ: pub=%q priv=%q", pubT, privT)
			}
		})
	}
}

func TestJKT_RFC7638_Vector(t *testing.T) {
	// RFC 7638 §3.1 example: an RSA public key whose thumbprint is the
	// well-known canonical test vector. This locks our implementation to
	// the spec — any divergence in field ordering, whitespace, or canonical
	// encoding would change the hash.
	const rfcKey = `{
        "kty": "RSA",
        "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        "e": "AQAB"
    }`
	const expected = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

	key, err := jwk.ParseKey([]byte(rfcKey))
	if err != nil {
		t.Fatalf("parse RFC 7638 key: %v", err)
	}
	got, err := JKT(key)
	if err != nil {
		t.Fatalf("JKT: %v", err)
	}
	if got != expected {
		t.Fatalf("thumbprint mismatch:\n  got:      %s\n  expected: %s", got, expected)
	}
}
