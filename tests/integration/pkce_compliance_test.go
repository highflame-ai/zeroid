// RFC 7636 (Proof Key for Code Exchange — PKCE) compliance suite.
//
// See COMPLIANCE.md for the conventions this file follows.
//
// Happy-path coverage lives in authorization_code_test.go. This file pins
// the §4 MUSTs: S256 is the only method ZeroID supports, the code_verifier
// MUST match the stored code_challenge at token-exchange time, the code is
// single-use, and a wrong verifier surfaces invalid_grant.

package integration_test

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pkceFixture mints an auth code under PKCE so each compliance test can
// vary the verifier presented at /oauth2/token.
type pkceFixture struct {
	Verifier  string
	Challenge string
	Code      string
}

func setupPKCEFixture(t *testing.T) pkceFixture {
	t.Helper()
	verifier, challenge := buildPKCEPair(t)
	code := buildAuthCode(t, testMCPClientID, uid("compliance-pkce-user"),
		testRedirectURI, challenge, []string{"data:read"})
	return pkceFixture{Verifier: verifier, Challenge: challenge, Code: code}
}

// ── RFC 7636 §4.2 — code_challenge_method ───────────────────────────────────

func TestRFC7636_S4_3_ChallengeIsBase64UrlSha256OfVerifier(t *testing.T) {
	// RFC 7636 §4.3 (S256): "code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))"
	// Smoke-test our helper to pin the algorithm we expose to clients —
	// ensures buildPKCEPair (and anything that re-implements it) doesn't
	// drift from the spec.
	verifier, challenge := buildPKCEPair(t)
	hash := sha256.Sum256([]byte(verifier))
	expected := base64.RawURLEncoding.EncodeToString(hash[:])
	assert.Equal(t, expected, challenge,
		"PKCE S256 challenge MUST equal base64url(SHA-256(verifier)) per RFC 7636 §4.3")
}

// ── RFC 7636 §4.6 — Verifier check at token endpoint ────────────────────────

func TestRFC7636_S4_6_VerifierMustMatchChallenge(t *testing.T) {
	// RFC 7636 §4.6: "If the values are not equal, an error response
	//   indicating 'invalid_grant' as described in Section 5.2 of [RFC6749]
	//   MUST be returned."
	f := setupPKCEFixture(t)
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "authorization_code",
		"client_id":     testMCPClientID,
		"code":          f.Code,
		"code_verifier": "wrong-verifier-value",
		"redirect_uri":  testRedirectURI,
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body := decode(t, resp)
	assert.Equal(t, "invalid_grant", body["error"])
}

func TestRFC7636_S4_6_MissingVerifierRejected(t *testing.T) {
	// RFC 7636 §4.6: token exchange "MUST [verify the code_verifier]" — and
	// you can't verify without it. The handler reports the missing field as
	// invalid_request (RFC 6749 §5.2).
	f := setupPKCEFixture(t)
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":   "authorization_code",
		"client_id":    testMCPClientID,
		"code":         f.Code,
		"redirect_uri": testRedirectURI,
		// code_verifier deliberately omitted
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body := decode(t, resp)
	assert.Equal(t, "invalid_request", body["error"])
}

// ── RFC 7636 §4.5 — Authorization code is single-use ────────────────────────

func TestRFC7636_S4_5_AuthorizationCodeIsSingleUse(t *testing.T) {
	// RFC 6749 §4.1.2 (cross-referenced by RFC 7636): "If an authorization
	//   code is used more than once, the authorization server MUST deny the
	//   request and SHOULD revoke (when possible) all tokens previously
	//   issued based on that authorization code."
	//
	// Pinning the single-use invariant: the same code presented twice must
	// fail the second time, even with the correct PKCE verifier.
	f := setupPKCEFixture(t)
	body := map[string]any{
		"grant_type":    "authorization_code",
		"client_id":     testMCPClientID,
		"code":          f.Code,
		"code_verifier": f.Verifier,
		"redirect_uri":  testRedirectURI,
	}
	first := post(t, "/oauth2/token", body, nil)
	require.Equal(t, http.StatusOK, first.StatusCode, "first exchange must succeed")
	_ = first.Body.Close()

	second := post(t, "/oauth2/token", body, nil)
	require.Equal(t, http.StatusBadRequest, second.StatusCode,
		"second exchange of same code MUST fail (single-use invariant)")
	errBody := decode(t, second)
	assert.Equal(t, "invalid_grant", errBody["error"])
}

// ── RFC 7636 §4.2 — Plain method NOT supported by this server ───────────────

// This is a deployment-policy assertion: RFC 7636 §4.2 permits both `plain`
// and `S256`, but the "plain" method is widely considered insecure (the
// challenge equals the verifier, providing no PKCE benefit). ZeroID's
// authcode service implements only S256 (see internal/service/authcode.go
// `verifyCodeChallenge`). The negative-space proof here is that a manually
// crafted "plain" challenge cannot be verified — there is no S256 hash that
// equals an arbitrary verifier — so a "plain-style" exchange where
// challenge == verifier is rejected.
func TestRFC7636_S4_2_PlainMethodNotAccepted(t *testing.T) {
	// RFC 7636 §4.2: "If the client is capable of using S256, it MUST use
	//   S256, as 'plain' is REQUIRED only as a fallback." ZeroID does not
	//   register a fallback at all — only S256 is honoured at /oauth2/token.
	plainVerifier := "verifier-equal-challenge-would-mean-plain-method"
	// Use the plain verifier AS the challenge (the "plain" semantic).
	code := buildAuthCode(t, testMCPClientID, uid("compliance-plain"),
		testRedirectURI, plainVerifier, []string{"data:read"})
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "authorization_code",
		"client_id":     testMCPClientID,
		"code":          code,
		"code_verifier": plainVerifier, // matching plain-style: verifier == challenge
		"redirect_uri":  testRedirectURI,
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"a 'plain' PKCE exchange (verifier == challenge) MUST be rejected — server is S256-only")
	body := decode(t, resp)
	assert.Equal(t, "invalid_grant", body["error"])
}
