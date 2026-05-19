// RFC 7009 (OAuth 2.0 Token Revocation) compliance suite.
//
// See COMPLIANCE.md for the conventions this file follows: one MUST per
// test, name carries the citation, first comment quotes the clause.
//
// The endpoint is `/oauth2/token/revoke`. Most of RFC 7009 is "the server
// MUST treat any failure as success" — the goal is to avoid leaking
// information about which tokens exist. Tests focus on that always-success
// invariant plus the post-condition that revoked tokens stop introspecting
// as `active=true`.

package integration_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// issueRevokeTestToken mints an access token via client_credentials so the
// revoke tests have something real to revoke.
func issueRevokeTestToken(t *testing.T) string {
	t.Helper()
	agentID := uid("compliance-revoke")
	registerIdentity(t, agentID, []string{"data:read"})
	client := registerOAuthClient(t, agentID, []string{"data:read"})
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	token, _ := decode(t, resp)["access_token"].(string)
	require.NotEmpty(t, token)
	return token
}

// ── RFC 7009 §2.2 — Revocation Response ─────────────────────────────────────

func TestRFC7009_S2_2_RevokeReturns200OnSuccess(t *testing.T) {
	// RFC 7009 §2.2: "The authorization server responds with HTTP status
	//   code 200 if the token has been revoked successfully or if the
	//   client submitted an invalid token."
	token := issueRevokeTestToken(t)
	resp := post(t, "/oauth2/token/revoke", map[string]any{"token": token}, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"successful revocation MUST return 200")
	_ = resp.Body.Close()
}

func TestRFC7009_S2_2_RevokeReturns200OnUnknownToken(t *testing.T) {
	// RFC 7009 §2.2: "Note: invalid tokens do not cause an error response
	//   since the client cannot handle such an error in a reasonable way."
	// An unknown / never-issued token MUST also return 200.
	resp := post(t, "/oauth2/token/revoke", map[string]any{
		"token": "this-is-not-a-real-jwt-it-is-just-a-string",
	}, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"unknown token MUST 200 — RFC 7009 forbids leaking existence info")
	_ = resp.Body.Close()
}

func TestRFC7009_S2_2_RevokeIsIdempotent(t *testing.T) {
	// RFC 7009 §2.2: "an already revoked token ... is considered valid";
	// implies repeated revocation of the same token MUST 200 every time.
	token := issueRevokeTestToken(t)

	r1 := post(t, "/oauth2/token/revoke", map[string]any{"token": token}, nil)
	require.Equal(t, http.StatusOK, r1.StatusCode)
	_ = r1.Body.Close()

	r2 := post(t, "/oauth2/token/revoke", map[string]any{"token": token}, nil)
	assert.Equal(t, http.StatusOK, r2.StatusCode,
		"second revocation of same token MUST also 200 (idempotent)")
	_ = r2.Body.Close()
}

// ── Post-condition: revoked token is `active=false` ─────────────────────────

func TestRFC7009_RevocationCausesIntrospectionInactive(t *testing.T) {
	// RFC 7009 §2 / RFC 7662 §2.2: revocation is the inverse of issuance.
	// A revoked token MUST introspect as `active=false` going forward.
	token := issueRevokeTestToken(t)

	// Sanity: active=true before revocation.
	before := introspect(t, token)
	require.Equal(t, true, before["active"], "freshly-issued token must be active")

	revoke := post(t, "/oauth2/token/revoke", map[string]any{"token": token}, nil)
	require.Equal(t, http.StatusOK, revoke.StatusCode)
	_ = revoke.Body.Close()

	after := introspect(t, token)
	assert.Equal(t, false, after["active"],
		"introspection of a revoked token MUST report active=false")
}
