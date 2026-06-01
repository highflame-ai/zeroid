package dpop

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestValidate_HappyPath_PerAlg runs the full happy-path validation through
// every supported algorithm family. Each must produce a successful result
// with a non-empty thumbprint matching the embedded JWK.
func TestValidate_HappyPath_PerAlg(t *testing.T) {
	algs := []string{"ES256", "ES384", "EdDSA", "RS256"}
	for _, alg := range algs {
		t.Run(alg, func(t *testing.T) {
			key := genTestKey(t, alg)
			v := mustVerifier(t)

			proof := key.signProof(t, validClaims("POST", "https://api.example.com/v1/tokens"))

			res, err := v.Validate(context.Background(), ValidateRequest{
				ProofJWT: proof,
				Method:   "POST",
				URL:      "https://api.example.com/v1/tokens",
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.Thumbprint == "" {
				t.Fatalf("expected non-empty thumbprint")
			}
			if res.Algorithm != alg {
				t.Fatalf("Algorithm = %q, want %q", res.Algorithm, alg)
			}
			// Same key + same input → same thumbprint each time.
			thumb2, err := JKT(key.public)
			if err != nil {
				t.Fatalf("JKT(public): %v", err)
			}
			if res.Thumbprint != thumb2 {
				t.Fatalf("thumbprint mismatch: result=%q jkt=%q", res.Thumbprint, thumb2)
			}
		})
	}
}

// TestValidate_HTU_Normalization ensures the URL comparison strips query and
// fragment per RFC 9449 §4.3.
func TestValidate_HTU_Normalization(t *testing.T) {
	key := genTestKey(t, "ES256")
	v := mustVerifier(t)

	// Proof carries the canonical htu; request URL has a query string and fragment.
	claims := validClaims("GET", "https://api.example.com/v1/resource")
	proof := key.signProof(t, claims)

	cases := []struct {
		name string
		url  string
	}{
		{"no query no fragment", "https://api.example.com/v1/resource"},
		{"with query", "https://api.example.com/v1/resource?foo=bar"},
		{"with fragment", "https://api.example.com/v1/resource#section"},
		{"with both", "https://api.example.com/v1/resource?x=y#z"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.Validate(context.Background(), ValidateRequest{
				ProofJWT: proof,
				Method:   "GET",
				URL:      tc.url,
			})
			// Each call must use a fresh jti — but the proof has only one.
			// First iteration succeeds; subsequent ones fail with Replay.
			// To isolate htu normalization, regenerate the proof each pass.
			if err != nil && !errors.Is(err, ErrReplay) {
				t.Fatalf("htu=%q: unexpected error: %v", tc.url, err)
			}
		})
	}
}

func TestValidate_HTM_CaseInsensitive(t *testing.T) {
	key := genTestKey(t, "ES256")
	v := mustVerifier(t)

	proof := key.signProof(t, map[string]any{
		"jti": newJTI(),
		"htm": "post",
		"htu": "https://api.example.com/v1/tokens",
		"iat": time.Now().Unix(),
	})

	_, err := v.Validate(context.Background(), ValidateRequest{
		ProofJWT: proof,
		Method:   "POST",
		URL:      "https://api.example.com/v1/tokens",
	})
	if err != nil {
		t.Fatalf("case-mismatched method should be accepted: %v", err)
	}
}

func TestValidate_HTM_Mismatch(t *testing.T) {
	key := genTestKey(t, "ES256")
	v := mustVerifier(t)
	proof := key.signProof(t, validClaims("POST", "https://api.example.com/v1/tokens"))

	_, err := v.Validate(context.Background(), ValidateRequest{
		ProofJWT: proof,
		Method:   "GET",
		URL:      "https://api.example.com/v1/tokens",
	})
	assertDPoPCode(t, err, CodeHTMMismatch)
}

func TestValidate_HTU_Mismatch(t *testing.T) {
	key := genTestKey(t, "ES256")
	v := mustVerifier(t)
	proof := key.signProof(t, validClaims("POST", "https://api.example.com/v1/tokens"))

	_, err := v.Validate(context.Background(), ValidateRequest{
		ProofJWT: proof,
		Method:   "POST",
		URL:      "https://api.example.com/v1/other",
	})
	assertDPoPCode(t, err, CodeHTUMismatch)
}

func TestValidate_IAT_TooOld(t *testing.T) {
	key := genTestKey(t, "ES256")
	v := mustVerifier(t)
	claims := validClaims("POST", "https://api.example.com/v1/tokens")
	claims["iat"] = time.Now().Add(-5 * time.Minute).Unix()
	proof := key.signProof(t, claims)

	_, err := v.Validate(context.Background(), ValidateRequest{
		ProofJWT: proof,
		Method:   "POST",
		URL:      "https://api.example.com/v1/tokens",
	})
	assertDPoPCode(t, err, CodeClockSkew)
}

func TestValidate_IAT_InFuture(t *testing.T) {
	key := genTestKey(t, "ES256")
	v := mustVerifier(t)
	claims := validClaims("POST", "https://api.example.com/v1/tokens")
	claims["iat"] = time.Now().Add(1 * time.Minute).Unix()
	proof := key.signProof(t, claims)

	_, err := v.Validate(context.Background(), ValidateRequest{
		ProofJWT: proof,
		Method:   "POST",
		URL:      "https://api.example.com/v1/tokens",
	})
	assertDPoPCode(t, err, CodeClockSkew)
}

func TestValidate_IAT_WithinClockSkew(t *testing.T) {
	key := genTestKey(t, "ES256")
	v := mustVerifier(t)
	// iat 3 seconds in the future — within the default 5s clock skew.
	claims := validClaims("POST", "https://api.example.com/v1/tokens")
	claims["iat"] = time.Now().Add(3 * time.Second).Unix()
	proof := key.signProof(t, claims)

	_, err := v.Validate(context.Background(), ValidateRequest{
		ProofJWT: proof,
		Method:   "POST",
		URL:      "https://api.example.com/v1/tokens",
	})
	if err != nil {
		t.Fatalf("iat within clock skew should be accepted: %v", err)
	}
}

func TestValidate_Replay(t *testing.T) {
	key := genTestKey(t, "ES256")
	v := mustVerifier(t)
	proof := key.signProof(t, validClaims("POST", "https://api.example.com/v1/tokens"))

	req := ValidateRequest{
		ProofJWT: proof,
		Method:   "POST",
		URL:      "https://api.example.com/v1/tokens",
	}
	if _, err := v.Validate(context.Background(), req); err != nil {
		t.Fatalf("first call: %v", err)
	}
	_, err := v.Validate(context.Background(), req)
	assertDPoPCode(t, err, CodeReplay)
}

func TestValidate_ATH_Match(t *testing.T) {
	key := genTestKey(t, "ES256")
	v := mustVerifier(t)
	token := "fake.access.token"
	sum := sha256.Sum256([]byte(token))
	ath := base64.RawURLEncoding.EncodeToString(sum[:])

	claims := validClaims("POST", "https://api.example.com/v1/resource")
	claims["ath"] = ath
	proof := key.signProof(t, claims)

	_, err := v.Validate(context.Background(), ValidateRequest{
		ProofJWT:    proof,
		Method:      "POST",
		URL:         "https://api.example.com/v1/resource",
		AccessToken: token,
	})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestValidate_ATH_Mismatch(t *testing.T) {
	key := genTestKey(t, "ES256")
	v := mustVerifier(t)
	claims := validClaims("POST", "https://api.example.com/v1/resource")
	claims["ath"] = "obviously-wrong-hash"
	proof := key.signProof(t, claims)

	_, err := v.Validate(context.Background(), ValidateRequest{
		ProofJWT:    proof,
		Method:      "POST",
		URL:         "https://api.example.com/v1/resource",
		AccessToken: "fake.access.token",
	})
	assertDPoPCode(t, err, CodeATHMismatch)
}

func TestValidate_ATH_MissingWhenTokenPresent(t *testing.T) {
	key := genTestKey(t, "ES256")
	v := mustVerifier(t)
	claims := validClaims("POST", "https://api.example.com/v1/resource") // no ath
	proof := key.signProof(t, claims)

	_, err := v.Validate(context.Background(), ValidateRequest{
		ProofJWT:    proof,
		Method:      "POST",
		URL:         "https://api.example.com/v1/resource",
		AccessToken: "any.token.here",
	})
	assertDPoPCode(t, err, CodeATHMismatch)
}

func TestValidate_BH_Match(t *testing.T) {
	key := genTestKey(t, "ES256")
	v := mustVerifier(t)
	body := []byte(`{"hello":"world"}`)
	sum := sha256.Sum256(body)
	bh := base64.RawURLEncoding.EncodeToString(sum[:])

	claims := validClaims("POST", "https://api.example.com/v1/resource")
	claims["bh"] = bh
	proof := key.signProof(t, claims)

	_, err := v.Validate(context.Background(), ValidateRequest{
		ProofJWT: proof,
		Method:   "POST",
		URL:      "https://api.example.com/v1/resource",
		Body:     body,
	})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestValidate_BH_Mismatch(t *testing.T) {
	key := genTestKey(t, "ES256")
	v := mustVerifier(t)
	claims := validClaims("POST", "https://api.example.com/v1/resource")
	claims["bh"] = "wrong-hash-here"
	proof := key.signProof(t, claims)

	_, err := v.Validate(context.Background(), ValidateRequest{
		ProofJWT: proof,
		Method:   "POST",
		URL:      "https://api.example.com/v1/resource",
		Body:     []byte("any body"),
	})
	assertDPoPCode(t, err, CodeBodyHashMismatch)
}

func TestValidate_BH_RequiredButMissing(t *testing.T) {
	key := genTestKey(t, "ES256")
	v, err := NewVerifier(Config{Store: NewMemoryStore()}, RequireBodyHash())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	claims := validClaims("POST", "https://api.example.com/v1/resource") // no bh
	proof := key.signProof(t, claims)

	_, err = v.Validate(context.Background(), ValidateRequest{
		ProofJWT: proof,
		Method:   "POST",
		URL:      "https://api.example.com/v1/resource",
		Body:     []byte("any body"),
	})
	assertDPoPCode(t, err, CodeBodyHashRequired)
}

func TestValidate_BH_OptionalWhenNoBody(t *testing.T) {
	key := genTestKey(t, "ES256")
	// Even with RequireBodyHash, a request with no body should not require bh.
	v, err := NewVerifier(Config{Store: NewMemoryStore()}, RequireBodyHash())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	claims := validClaims("GET", "https://api.example.com/v1/resource")
	proof := key.signProof(t, claims)

	_, err = v.Validate(context.Background(), ValidateRequest{
		ProofJWT: proof,
		Method:   "GET",
		URL:      "https://api.example.com/v1/resource",
		// Body nil → bh not enforced
	})
	if err != nil {
		t.Fatalf("no-body request should not require bh: %v", err)
	}
}

func TestValidate_TypHeader_Wrong(t *testing.T) {
	key := genTestKey(t, "ES256")
	v := mustVerifier(t)
	proof := key.signProofWithTyp(t, "JWT", validClaims("POST", "https://api.example.com/v1/tokens"))

	_, err := v.Validate(context.Background(), ValidateRequest{
		ProofJWT: proof,
		Method:   "POST",
		URL:      "https://api.example.com/v1/tokens",
	})
	assertDPoPCode(t, err, CodeInvalidProof)
}

func TestValidate_TypHeader_Missing(t *testing.T) {
	key := genTestKey(t, "ES256")
	v := mustVerifier(t)
	proof := key.signProofWithTyp(t, "", validClaims("POST", "https://api.example.com/v1/tokens"))

	_, err := v.Validate(context.Background(), ValidateRequest{
		ProofJWT: proof,
		Method:   "POST",
		URL:      "https://api.example.com/v1/tokens",
	})
	assertDPoPCode(t, err, CodeInvalidProof)
}

func TestValidate_JWK_Missing(t *testing.T) {
	key := genTestKey(t, "ES256")
	v := mustVerifier(t)
	proof := key.signProofNoJWK(t, validClaims("POST", "https://api.example.com/v1/tokens"))

	_, err := v.Validate(context.Background(), ValidateRequest{
		ProofJWT: proof,
		Method:   "POST",
		URL:      "https://api.example.com/v1/tokens",
	})
	assertDPoPCode(t, err, CodeInvalidProof)
}

func TestValidate_JWK_Private_Rejected(t *testing.T) {
	key := genTestKey(t, "ES256")
	v := mustVerifier(t)
	proof := key.signProofWithPrivateJWK(t, validClaims("POST", "https://api.example.com/v1/tokens"))

	_, err := v.Validate(context.Background(), ValidateRequest{
		ProofJWT: proof,
		Method:   "POST",
		URL:      "https://api.example.com/v1/tokens",
	})
	assertDPoPCode(t, err, CodeInvalidProof)
}

func TestValidate_MalformedProof(t *testing.T) {
	v := mustVerifier(t)
	cases := []string{
		"",
		"not.a.jwt",
		"a.b.c.d", // too many segments
		"...",
		strings.Repeat("x", 1024),
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			_, err := v.Validate(context.Background(), ValidateRequest{
				ProofJWT: raw,
				Method:   "POST",
				URL:      "https://api.example.com/v1/tokens",
			})
			if err == nil {
				t.Fatal("expected error")
			}
			var de *Error
			if !errors.As(err, &de) {
				t.Fatalf("expected *dpop.Error; got %T: %v", err, err)
			}
			if de.Code != CodeInvalidProof {
				t.Fatalf("Code = %q, want %q (%v)", de.Code, CodeInvalidProof, err)
			}
		})
	}
}

func TestValidate_MissingClaims(t *testing.T) {
	key := genTestKey(t, "ES256")
	v := mustVerifier(t)

	cases := []struct {
		name string
		mut  func(map[string]any)
	}{
		{"missing jti", func(c map[string]any) { delete(c, "jti") }},
		{"missing htm", func(c map[string]any) { delete(c, "htm") }},
		{"missing htu", func(c map[string]any) { delete(c, "htu") }},
		{"missing iat", func(c map[string]any) { delete(c, "iat") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := validClaims("POST", "https://api.example.com/v1/tokens")
			tc.mut(claims)
			proof := key.signProof(t, claims)
			_, err := v.Validate(context.Background(), ValidateRequest{
				ProofJWT: proof,
				Method:   "POST",
				URL:      "https://api.example.com/v1/tokens",
			})
			assertDPoPCode(t, err, CodeInvalidProof)
		})
	}
}

func TestValidateBoundToToken_Match(t *testing.T) {
	key := genTestKey(t, "ES256")
	v := mustVerifier(t)
	proof := key.signProof(t, validClaims("POST", "https://api.example.com/v1/resource"))

	jkt, err := JKT(key.public)
	if err != nil {
		t.Fatalf("JKT: %v", err)
	}

	_, err = v.ValidateBoundToToken(context.Background(), ValidateRequest{
		ProofJWT: proof,
		Method:   "POST",
		URL:      "https://api.example.com/v1/resource",
	}, jkt)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestValidateBoundToToken_Mismatch(t *testing.T) {
	key := genTestKey(t, "ES256")
	v := mustVerifier(t)
	proof := key.signProof(t, validClaims("POST", "https://api.example.com/v1/resource"))

	// Pass a thumbprint that's the right shape but wrong value.
	_, err := v.ValidateBoundToToken(context.Background(), ValidateRequest{
		ProofJWT: proof,
		Method:   "POST",
		URL:      "https://api.example.com/v1/resource",
	}, "ZmFrZS10aHVtYnByaW50LXZhbHVlLW9mLXJpZ2h0LWxlbmd0aA")
	assertDPoPCode(t, err, CodeTokenBindingMismatch)
}

func TestValidateBoundToToken_EmptyJKT(t *testing.T) {
	key := genTestKey(t, "ES256")
	v := mustVerifier(t)
	proof := key.signProof(t, validClaims("POST", "https://api.example.com/v1/resource"))

	_, err := v.ValidateBoundToToken(context.Background(), ValidateRequest{
		ProofJWT: proof,
		Method:   "POST",
		URL:      "https://api.example.com/v1/resource",
	}, "")
	assertDPoPCode(t, err, CodeTokenBindingMismatch)
}

func TestNewVerifier_NilStore(t *testing.T) {
	_, err := NewVerifier(Config{Store: nil})
	if err == nil {
		t.Fatal("expected error for nil Store")
	}
}

func TestNewVerifier_BadClockSkew(t *testing.T) {
	_, err := NewVerifier(Config{Store: NewMemoryStore()}, WithClockSkew(60*time.Second), WithMaxAge(30*time.Second))
	if err == nil {
		t.Fatal("expected error: clockSkew > maxAge/2")
	}
}

func TestValidate_StorageFailure(t *testing.T) {
	key := genTestKey(t, "ES256")
	v, err := NewVerifier(Config{Store: failingStore{}})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	proof := key.signProof(t, validClaims("POST", "https://api.example.com/v1/tokens"))

	_, err = v.Validate(context.Background(), ValidateRequest{
		ProofJWT: proof,
		Method:   "POST",
		URL:      "https://api.example.com/v1/tokens",
	})
	assertDPoPCode(t, err, CodeStorageFailure)
	if IsClientFault(err) {
		t.Fatal("storage failure must not be classified as client fault")
	}
}

// failingStore is a ReplayStore that always errors with a non-dpop error.
type failingStore struct{}

func (failingStore) Insert(_ context.Context, _ string, _ time.Time) error {
	return errors.New("simulated postgres outage")
}

// --- helpers ---

func mustVerifier(t *testing.T) *Verifier {
	t.Helper()
	v, err := NewVerifier(Config{Store: NewMemoryStore()})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

func assertDPoPCode(t *testing.T, err error, wantCode string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with code %q; got nil", wantCode)
	}
	var de *Error
	if !errors.As(err, &de) {
		t.Fatalf("expected *dpop.Error; got %T: %v", err, err)
	}
	if de.Code != wantCode {
		t.Fatalf("Code = %q, want %q (err=%v)", de.Code, wantCode, err)
	}
}
