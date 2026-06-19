package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwt"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/pkg/authjwt"
)

// TestExtractMappedClaimString covers the v1 claim-mapping shapes the three
// reference IdPs (Okta, Entra, Google) emit. v1 is single-level only — no
// JSONPath, no expressions.
func TestExtractMappedClaimString(t *testing.T) {
	t.Run("string sub from Okta", func(t *testing.T) {
		got, ok := extractMappedClaimString(map[string]any{"sub": "00uABC"}, "sub")
		if !ok || got != "00uABC" {
			t.Fatalf("expected (00uABC, true), got (%q, %v)", got, ok)
		}
	})

	t.Run("numeric oid from Entra is stringified", func(t *testing.T) {
		got, ok := extractMappedClaimString(map[string]any{"oid": float64(42)}, "oid")
		if !ok || got != "42" {
			t.Fatalf("expected (42, true), got (%q, %v)", got, ok)
		}
	})

	t.Run("large numeric subject avoids scientific notation", func(t *testing.T) {
		// JSON unmarshals a 16-digit integer literal into float64. %v / %g
		// would render this as 1.234567890123456e+15 and break downstream
		// equality checks against the upstream's stable subject identifier.
		got, ok := extractMappedClaimString(map[string]any{"sub": float64(1234567890123456)}, "sub")
		if !ok {
			t.Fatalf("expected ok=true for large numeric subject")
		}
		if got != "1234567890123456" {
			t.Fatalf("expected plain decimal %q, got %q", "1234567890123456", got)
		}
	})

	t.Run("missing path returns false", func(t *testing.T) {
		_, ok := extractMappedClaimString(map[string]any{"sub": "x"}, "email")
		if ok {
			t.Fatalf("expected ok=false for missing claim")
		}
	})

	t.Run("empty path returns false", func(t *testing.T) {
		_, ok := extractMappedClaimString(map[string]any{"sub": "x"}, "")
		if ok {
			t.Fatalf("empty path means no mapping configured; should be ok=false")
		}
	})

	t.Run("non-stringifiable value returns false", func(t *testing.T) {
		_, ok := extractMappedClaimString(map[string]any{"sub": map[string]any{}}, "sub")
		if ok {
			t.Fatalf("nested object cannot be coerced to string in v1; should be ok=false")
		}
	})
}

// TestCheckExternalIDTokenAlg verifies that the algorithm gate refuses
// none/HS* family tokens up front and respects the configured allow-list.
//
// We exercise it with crafted JWS strings rather than spinning up a real
// signer — the function only reads the protected header.
func TestCheckExternalIDTokenAlg(t *testing.T) {
	// alg=none token: header={"alg":"none","typ":"JWT"}, no signature.
	// Build by hand — base64url("{\"alg\":\"none\",\"typ\":\"JWT\"}") + ".eyJ9." (empty body, empty sig)
	// We don't bother — jws.Parse rejects unsigned tokens.
	// Instead we test alg=HS256 which has the same payload structure but is rejected.
	// HS256 header: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
	hs256 := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ4In0.AAAA"
	if err := checkExternalIDTokenAlg(hs256, []string{"RS256", "ES256"}); err == nil {
		t.Fatalf("expected HS256 to be rejected as non-asymmetric, got nil")
	}

	// RS256 with explicit allow-list match — header eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9
	rs256 := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ4In0.AAAA"
	if err := checkExternalIDTokenAlg(rs256, []string{"RS256"}); err != nil {
		t.Fatalf("expected RS256 to pass with allow-list [RS256], got %v", err)
	}

	// RS256 with an allow-list that excludes it.
	if err := checkExternalIDTokenAlg(rs256, []string{"ES256"}); err == nil {
		t.Fatalf("expected RS256 to be rejected when allow-list is [ES256]")
	}

	// Empty allow-list → defaults to the hard whitelist of asymmetric algs.
	if err := checkExternalIDTokenAlg(rs256, nil); err != nil {
		t.Fatalf("expected RS256 to pass with empty allow-list, got %v", err)
	}
}

// TestExternalIDTokenExchange_UnknownIssuerWrapsSentinel verifies the dual
// signaling path for the unknown-issuer case: the OAuth handler picks up the
// error code via errors.As on *OAuthError, while service-layer callers can
// branch with errors.Is(ErrUnknownExternalIssuer).
func TestExternalIDTokenExchange_UnknownIssuerWrapsSentinel(t *testing.T) {
	// Build a registry that knows iss=A but not iss=B.
	jwks := newFakeJWKSServer(t, "kid-1")
	defer jwks.Close()

	cfg := domain.ExternalIssuerConfig{
		Issuer:          "https://known.example.test",
		JWKSURI:         jwks.URL(),
		Audience:        "https://zeroid.example.test",
		ClaimMapping:    map[string]string{"user_id": "sub"},
		AllowedAccounts: []string{"acct"},
	}
	cfg.Defaults()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate cfg: %v", err)
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

	// Mint a JWT whose iss is *not* the configured one. Lookup should miss
	// and the federation path should return before any signature work.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tok, err := jwt.NewBuilder().
		Issuer("https://stranger.example.test").
		Subject("alice").
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(5 * time.Minute)).
		Build()
	if err != nil {
		t.Fatalf("build token: %v", err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), priv))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	svc := &OAuthService{externalIssuerRegistry: registry}
	_, err = svc.externalIDTokenExchange(context.Background(), TokenRequest{
		SubjectToken: string(signed),
		AccountID:    "acct",
		ProjectID:    "proj",
	})
	if err == nil {
		t.Fatalf("expected error for unknown issuer, got nil")
	}

	// Handler path: errors.As on *OAuthError must yield invalid_request / 400.
	var oauthErr *OAuthError
	if !errors.As(err, &oauthErr) {
		t.Fatalf("expected *OAuthError in chain, got %T: %v", err, err)
	}
	if oauthErr.Code != "invalid_request" {
		t.Errorf("Code = %q, want invalid_request", oauthErr.Code)
	}
	if oauthErr.HTTPStatus != http.StatusBadRequest {
		t.Errorf("HTTPStatus = %d, want 400", oauthErr.HTTPStatus)
	}

	// Caller path: errors.Is on the sentinel must succeed.
	if !errors.Is(err, ErrUnknownExternalIssuer) {
		t.Errorf("expected errors.Is(err, ErrUnknownExternalIssuer) to be true; chain = %v", err)
	}
}
