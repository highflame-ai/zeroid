package service

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// Tests for mintAuthCodeJWT — the pure-function half of the
// authorization_code grant's issuance side. The decoder lives next to
// it (decodeAuthCodeJWT) and is already covered by the existing
// integration tests for /oauth2/token. These tests pin the symmetry:
// what mintAuthCodeJWT produces, decodeAuthCodeJWT consumes.

const (
	testMintHMAC   = "test-hmac-secret-do-not-use-in-prod-32b!"
	testMintIssuer = "https://auth.test.example.com"
)

// TestMintAuthCodeJWT_RoundTripsThroughDecoder is the load-bearing
// contract test for this PR — it pins that the mint side produces a
// JWT shape the decode side accepts unchanged. If a future change
// renames a claim or tightens validation on either end and forgets to
// update the other, this test breaks here, surfacing the drift before
// any handler-level test does.
func TestMintAuthCodeJWT_RoundTripsThroughDecoder(t *testing.T) {
	t.Parallel()

	verifier := strings.Repeat("a", 43) // RFC 7636 minimum
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	now := time.Now()
	in := &AuthCodeClaims{
		ClientID:      "test-cli",
		CodeChallenge: challenge,
		RedirectURI:   "http://localhost:17580/callback",
		Scopes:        []string{"read:thing", "write:thing"},
		UserID:        "user-42",
		OrgID:         "org-99",
		AccountID:     "acct-001",
		ProjectID:     "proj-001",
	}

	code, err := mintAuthCodeJWT(in, testMintHMAC, testMintIssuer, now)
	if err != nil {
		t.Fatalf("mintAuthCodeJWT failed: %v", err)
	}
	if code == "" {
		t.Fatal("mintAuthCodeJWT returned empty code")
	}

	// Decode using the same parser /oauth2/token uses at exchange time.
	out, err := decodeAuthCodeJWT(code, testMintHMAC, testMintIssuer)
	if err != nil {
		t.Fatalf("decodeAuthCodeJWT failed on minted code: %v", err)
	}

	// Pin every claim — this is the contract between mint and decode.
	if out.ClientID != in.ClientID {
		t.Errorf("ClientID: got %q want %q", out.ClientID, in.ClientID)
	}
	if out.CodeChallenge != in.CodeChallenge {
		t.Errorf("CodeChallenge: got %q want %q", out.CodeChallenge, in.CodeChallenge)
	}
	if out.RedirectURI != in.RedirectURI {
		t.Errorf("RedirectURI: got %q want %q", out.RedirectURI, in.RedirectURI)
	}
	if out.UserID != in.UserID {
		t.Errorf("UserID: got %q want %q", out.UserID, in.UserID)
	}
	if out.OrgID != in.OrgID {
		t.Errorf("OrgID: got %q want %q", out.OrgID, in.OrgID)
	}
	if out.AccountID != in.AccountID {
		t.Errorf("AccountID: got %q want %q", out.AccountID, in.AccountID)
	}
	if out.ProjectID != in.ProjectID {
		t.Errorf("ProjectID: got %q want %q", out.ProjectID, in.ProjectID)
	}
	if len(out.Scopes) != len(in.Scopes) {
		t.Errorf("Scopes length: got %d want %d", len(out.Scopes), len(in.Scopes))
	}
	for i, s := range in.Scopes {
		if i < len(out.Scopes) && out.Scopes[i] != s {
			t.Errorf("Scopes[%d]: got %q want %q", i, out.Scopes[i], s)
		}
	}
	if out.JTI == "" {
		t.Error("JTI is empty — single-use enforcement at /oauth2/token would silently fail")
	}

	// Verifier→challenge round-trip — the PKCE invariant.
	rehash := sha256.Sum256([]byte(verifier))
	recomputed := base64.RawURLEncoding.EncodeToString(rehash[:])
	if out.CodeChallenge != recomputed {
		t.Errorf("PKCE round-trip broken: cc=%q sha256(verifier)=%q", out.CodeChallenge, recomputed)
	}
}

// TestMintAuthCodeJWT_OptionalClaimsOmittedWhenEmpty pins that empty
// UserID / OrgID / ProjectID don't produce empty-string claims in the
// JWT (which would be confusing for downstream consumers reading the
// "oid"/"pid"/"uid" fields), and also that Scopes=nil produces no scp
// claim at all.
func TestMintAuthCodeJWT_OptionalClaimsOmittedWhenEmpty(t *testing.T) {
	t.Parallel()

	now := time.Now()
	in := &AuthCodeClaims{
		ClientID:      "test-cli",
		CodeChallenge: "some-challenge",
		RedirectURI:   "http://localhost:17580/callback",
		AccountID:     "acct-001",
		// UserID, OrgID, ProjectID, Scopes deliberately omitted.
	}
	code, err := mintAuthCodeJWT(in, testMintHMAC, testMintIssuer, now)
	if err != nil {
		t.Fatalf("mintAuthCodeJWT failed: %v", err)
	}
	out, err := decodeAuthCodeJWT(code, testMintHMAC, testMintIssuer)
	if err != nil {
		t.Fatalf("decodeAuthCodeJWT failed: %v", err)
	}
	if out.UserID != "" {
		t.Errorf("UserID should be empty when not provided; got %q", out.UserID)
	}
	if out.OrgID != "" {
		t.Errorf("OrgID should be empty when not provided; got %q", out.OrgID)
	}
	if out.ProjectID != "" {
		t.Errorf("ProjectID should be empty when not provided; got %q", out.ProjectID)
	}
	if len(out.Scopes) != 0 {
		t.Errorf("Scopes should be empty when not provided; got %v", out.Scopes)
	}
	if out.AccountID != "acct-001" {
		t.Errorf("AccountID should round-trip; got %q want %q", out.AccountID, "acct-001")
	}
}

// TestMintAuthCodeJWT_RejectsMissingRequiredFields pins that mint
// rejects an incompletely-populated AuthCodeClaims before producing a
// JWT that would later fail at the decoder for unclear reasons. Each
// case omits exactly one required field and expects a non-nil error.
func TestMintAuthCodeJWT_RejectsMissingRequiredFields(t *testing.T) {
	t.Parallel()

	full := func() *AuthCodeClaims {
		return &AuthCodeClaims{
			ClientID:      "c",
			CodeChallenge: "ch",
			RedirectURI:   "http://localhost/cb",
			AccountID:     "a",
		}
	}

	cases := []struct {
		name     string
		mutate   func(*AuthCodeClaims)
		hmac     string
		issuer   string
		wantSubs string
	}{
		{"empty hmac secret", func(c *AuthCodeClaims) {}, "", testMintIssuer, "hmac secret"},
		{"empty issuer", func(c *AuthCodeClaims) {}, testMintHMAC, "", "issuer"},
		{"nil claims", func(c *AuthCodeClaims) {}, testMintHMAC, testMintIssuer, "claims are nil"},
		{"empty client_id", func(c *AuthCodeClaims) { c.ClientID = "" }, testMintHMAC, testMintIssuer, "client_id"},
		{"empty code_challenge", func(c *AuthCodeClaims) { c.CodeChallenge = "" }, testMintHMAC, testMintIssuer, "code_challenge"},
		{"empty redirect_uri", func(c *AuthCodeClaims) { c.RedirectURI = "" }, testMintHMAC, testMintIssuer, "redirect_uri"},
		{"empty account_id", func(c *AuthCodeClaims) { c.AccountID = "" }, testMintHMAC, testMintIssuer, "account_id"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var c *AuthCodeClaims
			if tc.name != "nil claims" {
				c = full()
				tc.mutate(c)
			}
			_, err := mintAuthCodeJWT(c, tc.hmac, tc.issuer, time.Now())
			if err == nil {
				t.Fatalf("%s: expected error, got nil", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantSubs) {
				t.Errorf("%s: error %q does not mention %q", tc.name, err.Error(), tc.wantSubs)
			}
		})
	}
}

// TestMintAuthCodeJWT_RespectsCustomJTI pins that a caller-supplied
// jti is preserved through the mint, allowing tests (and production
// callers that want deterministic codes for replay-test fixtures) to
// pin the value rather than fight the time-derived default.
func TestMintAuthCodeJWT_RespectsCustomJTI(t *testing.T) {
	t.Parallel()

	const customJTI = "my-deterministic-test-jti-xyz"
	in := &AuthCodeClaims{
		JTI:           customJTI,
		ClientID:      "c",
		CodeChallenge: "ch",
		RedirectURI:   "http://localhost/cb",
		AccountID:     "a",
	}
	code, err := mintAuthCodeJWT(in, testMintHMAC, testMintIssuer, time.Now())
	if err != nil {
		t.Fatalf("mintAuthCodeJWT failed: %v", err)
	}
	out, err := decodeAuthCodeJWT(code, testMintHMAC, testMintIssuer)
	if err != nil {
		t.Fatalf("decodeAuthCodeJWT failed: %v", err)
	}
	if out.JTI != customJTI {
		t.Errorf("JTI: got %q want %q (caller-supplied jti must round-trip)", out.JTI, customJTI)
	}
}

// TestMintAuthCodeJWT_DefaultExpHonoursAuthCodeTTL pins that an
// AuthCodeClaims with zero ExpiresAt gets the default AuthCodeTTL
// applied, matching the documented invariant.
func TestMintAuthCodeJWT_DefaultExpHonoursAuthCodeTTL(t *testing.T) {
	t.Parallel()

	now := time.Now()
	in := &AuthCodeClaims{
		ClientID:      "c",
		CodeChallenge: "ch",
		RedirectURI:   "http://localhost/cb",
		AccountID:     "a",
	}
	code, err := mintAuthCodeJWT(in, testMintHMAC, testMintIssuer, now)
	if err != nil {
		t.Fatalf("mintAuthCodeJWT failed: %v", err)
	}
	out, err := decodeAuthCodeJWT(code, testMintHMAC, testMintIssuer)
	if err != nil {
		t.Fatalf("decodeAuthCodeJWT failed: %v", err)
	}
	// Allow ±2s drift between mint and decode for clock noise on slow runners.
	wantExp := now.Add(AuthCodeTTL)
	drift := out.ExpiresAt.Sub(wantExp)
	if drift < -2*time.Second || drift > 2*time.Second {
		t.Errorf("default exp = %v, expected %v ± 2s (AuthCodeTTL = %v)", out.ExpiresAt, wantExp, AuthCodeTTL)
	}
}

// TestRedirectURIAllowed pins the loopback normalization rule applied
// at IssueAuthCode-time: 127.0.0.1 and localhost are equivalent (RFC
// 8252 §7.3), but other normalisations (case folding, default ports,
// trailing slashes) are NOT applied — clients must register the exact
// URI they'll use otherwise.
func TestRedirectURIAllowed(t *testing.T) {
	t.Parallel()
	registered := []string{
		"http://localhost:17580/callback",
		"https://app.example.com/oauth/callback",
	}
	cases := []struct {
		name      string
		candidate string
		want      bool
	}{
		{"exact match localhost", "http://localhost:17580/callback", true},
		{"127.0.0.1 ↔ localhost equiv", "http://127.0.0.1:17580/callback", true},
		{"exact match https", "https://app.example.com/oauth/callback", true},
		{"wrong port", "http://localhost:17581/callback", false},
		{"wrong path", "http://localhost:17580/other", false},
		{"wrong host", "https://attacker.example.com/oauth/callback", false},
		{"unregistered scheme", "http://app.example.com/oauth/callback", false},
		{"empty candidate", "", false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := redirectURIAllowed(tc.candidate, registered)
			if got != tc.want {
				t.Errorf("redirectURIAllowed(%q) = %v, want %v", tc.candidate, got, tc.want)
			}
		})
	}
}
