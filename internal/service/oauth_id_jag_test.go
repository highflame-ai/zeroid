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
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/pkg/authjwt"
)

// signWithTyp serialises the given claim map as an ES256 JWT whose protected
// header carries the supplied typ — used to mint ID-JAG-shaped (typ:
// oauth-id-jag+jwt) and ordinary assertions for the typ-branch tests.
func signWithTyp(t *testing.T, priv *ecdsa.PrivateKey, kid, typ string, claims map[string]any) string {
	t.Helper()
	tok := jwt.New()
	for k, v := range claims {
		if err := tok.Set(k, v); err != nil {
			t.Fatalf("set claim %q: %v", k, err)
		}
	}
	hdr := jws.NewHeaders()
	if kid != "" {
		_ = hdr.Set(jws.KeyIDKey, kid)
	}
	if typ != "" {
		_ = hdr.Set(jws.TypeKey, typ)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), priv, jws.WithProtectedHeaders(hdr)))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return string(signed)
}

// TestIsIDJAGAssertion verifies the typ-branch discriminator: only an assertion
// whose JWS typ header is exactly oauth-id-jag+jwt routes to the ID-JAG path.
// Everything else (a JWT typ, no typ, a malformed token) stays on the NHI
// self-signed path. This is the gate the whole ADR 0010 D2 branch hinges on.
func TestIsIDJAGAssertion(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	base := map[string]any{"iss": "https://idp.test", "sub": "alice"}

	t.Run("typ oauth-id-jag+jwt is an ID-JAG", func(t *testing.T) {
		tok := signWithTyp(t, priv, "kid", idJAGTyp, base)
		if !isIDJAGAssertion(tok) {
			t.Fatalf("expected oauth-id-jag+jwt assertion to be detected as ID-JAG")
		}
	})

	t.Run("typ JWT is NOT an ID-JAG (NHI path)", func(t *testing.T) {
		tok := signWithTyp(t, priv, "kid", "JWT", base)
		if isIDJAGAssertion(tok) {
			t.Fatalf("a typ=JWT assertion must NOT be treated as an ID-JAG")
		}
	})

	t.Run("no typ header is NOT an ID-JAG (NHI path)", func(t *testing.T) {
		tok := signWithTyp(t, priv, "kid", "", base)
		if isIDJAGAssertion(tok) {
			t.Fatalf("an assertion without a typ header must NOT be treated as an ID-JAG")
		}
	})

	t.Run("garbage is NOT an ID-JAG", func(t *testing.T) {
		if isIDJAGAssertion("not-a-jwt") {
			t.Fatalf("a malformed assertion must NOT be treated as an ID-JAG")
		}
		if isIDJAGAssertion("") {
			t.Fatalf("an empty assertion must NOT be treated as an ID-JAG")
		}
	})
}

// TestExtractMappedClaimStrings covers the two multi-valued claim shapes the
// ID-JAG path reads: a space-delimited `scope` string and an array-valued
// claim (groups / privilege_scope). Numeric array entries are stringified.
func TestExtractMappedClaimStrings(t *testing.T) {
	t.Run("space-delimited scope string", func(t *testing.T) {
		got, ok := extractMappedClaimStrings(map[string]any{"scope": "read write admin"}, "scope")
		if !ok {
			t.Fatalf("expected ok=true")
		}
		if len(got) != 3 || got[0] != "read" || got[2] != "admin" {
			t.Fatalf("expected [read write admin], got %v", got)
		}
	})

	t.Run("string array", func(t *testing.T) {
		got, ok := extractMappedClaimStrings(map[string]any{"groups": []any{"eng", "admin"}}, "groups")
		if !ok || len(got) != 2 || got[0] != "eng" || got[1] != "admin" {
			t.Fatalf("expected [eng admin], got %v (ok=%v)", got, ok)
		}
	})

	t.Run("numeric array entries stringified", func(t *testing.T) {
		got, ok := extractMappedClaimStrings(map[string]any{"ids": []any{float64(1), float64(2)}}, "ids")
		if !ok || len(got) != 2 || got[0] != "1" || got[1] != "2" {
			t.Fatalf("expected [1 2], got %v (ok=%v)", got, ok)
		}
	})

	t.Run("missing claim returns false", func(t *testing.T) {
		if _, ok := extractMappedClaimStrings(map[string]any{"scope": "x"}, "groups"); ok {
			t.Fatalf("expected ok=false for missing claim")
		}
	})

	t.Run("empty path returns false", func(t *testing.T) {
		if _, ok := extractMappedClaimStrings(map[string]any{"scope": "x"}, ""); ok {
			t.Fatalf("expected ok=false for empty path (no mapping configured)")
		}
	})
}

// idJAGTestRegistry builds a single-issuer registry pointed at a fake JWKS,
// returning the registry plus the upstream signer so a test can mint a
// validly-signed ID-JAG.
func idJAGTestRegistry(t *testing.T, accountID string) (*ExternalIssuerRegistry, *fakeJWKSServer, string, string) {
	t.Helper()
	const kid = "idjag-kid-1"
	jwks := newFakeJWKSServer(t, kid)
	t.Cleanup(jwks.Close)

	const iss = "https://corp-idp.example.test"
	const aud = "https://zeroid.example.test"
	cfg := domain.ExternalIssuerConfig{
		Issuer:          iss,
		JWKSURI:         jwks.URL(),
		Audience:        aud,
		ClaimMapping:    map[string]string{"user_id": "sub", "email": "email"},
		AllowedAccounts: []string{accountID},
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
	t.Cleanup(registry.Close)
	return registry, jwks, iss, aud
}

// signIDJAG mints a validly-signed ID-JAG (typ oauth-id-jag+jwt) against the
// fake JWKS server's current key.
func signIDJAG(t *testing.T, jwks *fakeJWKSServer, claims map[string]any) string {
	t.Helper()
	return signWithTyp(t, jwks.curPriv, "idjag-kid-1", idJAGTyp, claims)
}

// requireInvalidGrant asserts the error carries an *OAuthError with code
// invalid_grant / 400 — the fail-closed contract for the ID-JAG path.
func requireInvalidGrant(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected invalid_grant error, got nil")
	}
	var oauthErr *OAuthError
	if !errors.As(err, &oauthErr) {
		t.Fatalf("expected *OAuthError in chain, got %T: %v", err, err)
	}
	if oauthErr.Code != "invalid_grant" {
		t.Errorf("Code = %q, want invalid_grant; err=%v", oauthErr.Code, err)
	}
	if oauthErr.HTTPStatus != http.StatusBadRequest {
		t.Errorf("HTTPStatus = %d, want 400", oauthErr.HTTPStatus)
	}
}

// The following tests exercise idJAGBearer's fail-closed gates that fire BEFORE
// any token mint — so they need only a registry, no DB / CredentialService.
// The end-to-end happy path (mapped claims + aud==resource) is covered by the
// integration test (tests/integration/id_jag_test.go) where a full server with
// a real DB is available.

func TestIDJAGBearer_UnknownIssuer_InvalidGrant(t *testing.T) {
	const acct = "acct-idjag"
	registry, _, _, aud := idJAGTestRegistry(t, acct)

	// Sign an ID-JAG whose iss is NOT the configured issuer. Lookup misses →
	// fail closed with invalid_grant (NOT invalid_request — that is the
	// id_token-exchange semantics; ADR 0010 D3 mandates invalid_grant here).
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	stranger := signWithTyp(t, priv, "kid", idJAGTyp, map[string]any{
		"iss":      "https://stranger.example.test",
		"sub":      "alice",
		"aud":      aud,
		"resource": "https://mcp.example.test",
		"iat":      now.Unix(),
		"exp":      now.Add(5 * time.Minute).Unix(),
	})

	svc := &OAuthService{externalIssuerRegistry: registry}
	_, err := svc.idJAGBearer(context.Background(), TokenRequest{
		Subject:   stranger,
		AccountID: acct,
		ProjectID: "proj",
	})
	requireInvalidGrant(t, err)
	if !errors.Is(err, ErrUnknownExternalIssuer) {
		t.Errorf("expected errors.Is(err, ErrUnknownExternalIssuer); chain=%v", err)
	}
}

func TestIDJAGBearer_BadSignature_InvalidGrant(t *testing.T) {
	const acct = "acct-idjag"
	registry, _, iss, aud := idJAGTestRegistry(t, acct)

	// Sign with a DIFFERENT key than the JWKS publishes → signature verify fails.
	wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	forged := signWithTyp(t, wrongKey, "idjag-kid-1", idJAGTyp, map[string]any{
		"iss":      iss,
		"sub":      "alice",
		"aud":      aud,
		"resource": "https://mcp.example.test",
		"iat":      now.Unix(),
		"exp":      now.Add(5 * time.Minute).Unix(),
	})

	svc := &OAuthService{externalIssuerRegistry: registry}
	_, err := svc.idJAGBearer(context.Background(), TokenRequest{
		Subject:   forged,
		AccountID: acct,
		ProjectID: "proj",
	})
	requireInvalidGrant(t, err)
}

func TestIDJAGBearer_TenantBindingFailure_InvalidGrant(t *testing.T) {
	const acct = "acct-idjag"
	registry, jwks, iss, aud := idJAGTestRegistry(t, acct)

	now := time.Now()
	idjag := signIDJAG(t, jwks, map[string]any{
		"iss":      iss,
		"sub":      "alice",
		"aud":      aud,
		"resource": "https://mcp.example.test",
		"iat":      now.Unix(),
		"exp":      now.Add(5 * time.Minute).Unix(),
	})

	svc := &OAuthService{externalIssuerRegistry: registry}
	// account_id NOT in AllowedAccounts → fail closed before any verification.
	_, err := svc.idJAGBearer(context.Background(), TokenRequest{
		Subject:   idjag,
		AccountID: "acct-not-allowed",
		ProjectID: "proj",
	})
	requireInvalidGrant(t, err)
}

func TestIDJAGBearer_MissingResource_InvalidGrant(t *testing.T) {
	const acct = "acct-idjag"
	registry, jwks, iss, aud := idJAGTestRegistry(t, acct)

	now := time.Now()
	// A perfectly valid, correctly-signed ID-JAG that simply omits `resource`.
	// The audience-restriction MUST (D4) makes this fail closed: there is no
	// MCP server to bind the minted token's aud to.
	noResource := signIDJAG(t, jwks, map[string]any{
		"iss": iss,
		"sub": "alice",
		"aud": aud,
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
	})

	svc := &OAuthService{externalIssuerRegistry: registry}
	_, err := svc.idJAGBearer(context.Background(), TokenRequest{
		Subject:   noResource,
		AccountID: acct,
		ProjectID: "proj",
	})
	requireInvalidGrant(t, err)
}

func TestIDJAGBearer_UnmappableIdentity_InvalidGrant(t *testing.T) {
	const acct = "acct-idjag"
	_, _, iss, aud := idJAGTestRegistry(t, acct)

	now := time.Now()
	// The ID-JAG is validly signed and carries `sub` (so the RFC 7523 §3
	// presence check passes), but ClaimMapping routes user_id to
	// "preferred_username", which the assertion does NOT carry → the external
	// identity cannot be mapped → fail closed (D3). This isolates the *mapping*
	// failure from the presence check (which also requires `sub`).
	const kid = "idjag-kid-2"
	jwks2 := newFakeJWKSServer(t, kid)
	t.Cleanup(jwks2.Close)
	cfg := domain.ExternalIssuerConfig{
		Issuer:          iss + "-2",
		JWKSURI:         jwks2.URL(),
		Audience:        aud,
		ClaimMapping:    map[string]string{"user_id": "preferred_username"},
		AllowedAccounts: []string{acct},
	}
	cfg.Defaults()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate cfg: %v", err)
	}
	registry2, err := NewExternalIssuerRegistry(
		context.Background(),
		[]domain.ExternalIssuerConfig{cfg},
		authjwt.WithHTTPClient(insecureHTTPClient(2*time.Second)),
	)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	t.Cleanup(registry2.Close)

	// Has sub (so presence check passes) but NO preferred_username (so mapping fails).
	idjag := signWithTyp(t, jwks2.curPriv, kid, idJAGTyp, map[string]any{
		"iss":      iss + "-2",
		"sub":      "opaque-subject",
		"aud":      aud,
		"resource": "https://mcp.example.test",
		"iat":      now.Unix(),
		"exp":      now.Add(5 * time.Minute).Unix(),
	})

	svc := &OAuthService{externalIssuerRegistry: registry2}
	_, err = svc.idJAGBearer(context.Background(), TokenRequest{
		Subject:   idjag,
		AccountID: acct,
		ProjectID: "proj",
	})
	requireInvalidGrant(t, err)
}
