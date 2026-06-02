package dpop

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
)

// testKey wraps a freshly-generated keypair for proof signing in tests.
type testKey struct {
	alg     jwa.SignatureAlgorithm
	algStr  string
	private jwk.Key
	public  jwk.Key
}

// genTestKey returns a freshly-generated keypair for the given alg.
// Supported algs: ES256, ES384, EdDSA, RS256.
func genTestKey(t *testing.T, alg string) testKey {
	t.Helper()
	switch alg {
	case "ES256":
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey: %v", err)
		}
		pub := priv.PublicKey
		pj := mustImport(t, priv)
		uj := mustImport(t, &pub)
		return testKey{alg: jwa.ES256(), algStr: alg, private: pj, public: uj}
	case "ES384":
		priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey: %v", err)
		}
		pub := priv.PublicKey
		pj := mustImport(t, priv)
		uj := mustImport(t, &pub)
		return testKey{alg: jwa.ES384(), algStr: alg, private: pj, public: uj}
	case "EdDSA":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("ed25519.GenerateKey: %v", err)
		}
		pj := mustImport(t, priv)
		uj := mustImport(t, pub)
		return testKey{alg: jwa.EdDSA(), algStr: alg, private: pj, public: uj}
	case "RS256":
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("rsa.GenerateKey: %v", err)
		}
		pub := priv.PublicKey
		pj := mustImport(t, priv)
		uj := mustImport(t, &pub)
		return testKey{alg: jwa.RS256(), algStr: alg, private: pj, public: uj}
	default:
		t.Fatalf("genTestKey: unsupported alg %q", alg)
		return testKey{}
	}
}

// mustImport wraps jwk.Import. jwk.Import[T Key] expects the RETURN type T
// to satisfy the Key constraint; passing jwk.Key gives us a generic key back.
func mustImport(t *testing.T, raw any) jwk.Key {
	t.Helper()
	k, err := jwk.Import[jwk.Key](raw)
	if err != nil {
		t.Fatalf("jwk.Import: %v", err)
	}
	return k
}

// signProof signs a DPoP proof with the typ=dpop+jwt header, the embedded
// public jwk, and the given claims. Returns the compact-encoded proof.
func (k testKey) signProof(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}

	hdrs := jws.NewHeaders()
	if err := hdrs.Set(jws.TypeKey, "dpop+jwt"); err != nil {
		t.Fatalf("hdrs.Set(typ): %v", err)
	}
	if err := hdrs.Set(jws.JWKKey, k.public); err != nil {
		t.Fatalf("hdrs.Set(jwk): %v", err)
	}

	signed, err := jws.Sign(payload, jws.WithKey(k.alg, k.private, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		t.Fatalf("jws.Sign: %v", err)
	}
	return string(signed)
}

// signProofWithTyp signs a proof but lets the caller override the typ
// header. Used for negative tests.
func (k testKey) signProofWithTyp(t *testing.T, typ string, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	hdrs := jws.NewHeaders()
	if typ != "" {
		if err := hdrs.Set(jws.TypeKey, typ); err != nil {
			t.Fatalf("hdrs.Set(typ): %v", err)
		}
	}
	if err := hdrs.Set(jws.JWKKey, k.public); err != nil {
		t.Fatalf("hdrs.Set(jwk): %v", err)
	}
	signed, err := jws.Sign(payload, jws.WithKey(k.alg, k.private, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		t.Fatalf("jws.Sign: %v", err)
	}
	return string(signed)
}

// signProofNoJWK signs a proof without embedding the jwk header. Used to
// verify "missing jwk" rejection.
func (k testKey) signProofNoJWK(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	hdrs := jws.NewHeaders()
	if err := hdrs.Set(jws.TypeKey, "dpop+jwt"); err != nil {
		t.Fatalf("hdrs.Set(typ): %v", err)
	}
	signed, err := jws.Sign(payload, jws.WithKey(k.alg, k.private, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		t.Fatalf("jws.Sign: %v", err)
	}
	return string(signed)
}

// signProofWithPrivateJWK embeds the PRIVATE jwk in the header — used to
// verify rejection of private-material leakage.
func (k testKey) signProofWithPrivateJWK(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	hdrs := jws.NewHeaders()
	if err := hdrs.Set(jws.TypeKey, "dpop+jwt"); err != nil {
		t.Fatalf("hdrs.Set(typ): %v", err)
	}
	if err := hdrs.Set(jws.JWKKey, k.private); err != nil {
		t.Fatalf("hdrs.Set(jwk): %v", err)
	}
	signed, err := jws.Sign(payload, jws.WithKey(k.alg, k.private, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		t.Fatalf("jws.Sign: %v", err)
	}
	return string(signed)
}

// validClaims produces a baseline claim set the tests can mutate.
func validClaims(method, htu string) map[string]any {
	return map[string]any{
		"jti": newJTI(),
		"htm": method,
		"htu": htu,
		"iat": time.Now().Unix(),
	}
}

// newJTI returns a unique-enough id for tests (not crypto-strength; just
// distinct across the test binary's run).
var jtiCounter int64

func newJTI() string {
	jtiCounter++
	return "test-jti-" + time.Now().Format("20060102T150405.000000000") + "-" + intToHex(jtiCounter)
}

func intToHex(n int64) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 0, 16)
	for n > 0 {
		out = append([]byte{hex[n&0xF]}, out...)
		n >>= 4
	}
	if len(out) == 0 {
		return "0"
	}
	return string(out)
}
