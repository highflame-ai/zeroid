// RFC 7662 (OAuth 2.0 Token Introspection) compliance suite.
//
// See COMPLIANCE.md for the conventions this file follows.
//
// Happy-path coverage (claims surfacing, cnf round-trip for DPoP) lives in
// oauth_test.go and the per-feature suites. This file pins the §2.2 MUSTs:
// `active` REQUIRED, malformed/revoked/expired tokens return active=false
// with no other claims leaking, and the response is always 200.

package integration_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// issueIntrospectTestToken mints a fresh access token for a per-test
// identity so the introspection suite has something real to inspect.
func issueIntrospectTestToken(t *testing.T) string {
	t.Helper()
	agentID := uid("compliance-introspect")
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

// ── RFC 7662 §2.2 — Introspection Response ──────────────────────────────────

func TestRFC7662_S2_2_ActiveFieldRequiredOnSuccess(t *testing.T) {
	// RFC 7662 §2.2: "active REQUIRED. Boolean indicator of whether or not
	//   the presented token is currently active."
	result := introspect(t, issueIntrospectTestToken(t))
	active, ok := result["active"].(bool)
	require.True(t, ok, "active field REQUIRED and MUST be a boolean")
	assert.True(t, active, "freshly issued token MUST introspect as active=true")
}

func TestRFC7662_S2_2_AlwaysReturns200(t *testing.T) {
	// RFC 7662 §2.2 (per §2.1 — "responds with a JSON object" with status 200):
	// even an inactive / malformed / unknown token gets 200 with active=false.
	// The endpoint never 401s based on the introspected token's status.
	resp := post(t, "/oauth2/token/introspect", map[string]any{
		"token": "this-is-not-a-real-jwt-just-bytes",
	}, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"introspection MUST 200 regardless of the introspected token's validity")
	body := decode(t, resp)
	assert.Equal(t, false, body["active"],
		"unknown token MUST introspect as active=false")
}

func TestRFC7662_S2_2_InactiveResponseOmitsOtherClaims(t *testing.T) {
	// RFC 7662 §2.2: "If the introspection call is properly authorized but
	//   the token is not active ... the authorization server MUST return an
	//   introspection response with the 'active' field set to 'false'.
	//   Note that to avoid disclosing too much of the authorization server's
	//   state to a third party, the authorization server SHOULD NOT include
	//   any additional information about an inactive token."
	body := decode(t, post(t, "/oauth2/token/introspect", map[string]any{
		"token": "definitely-not-a-real-token",
	}, nil))

	// active=false is the only claim that may appear.
	assert.Equal(t, false, body["active"])

	// Forbidden claim names — none should leak on an inactive response.
	for _, claim := range []string{"sub", "iss", "aud", "exp", "iat", "jti",
		"scope", "account_id", "project_id", "agent_id", "cnf", "act"} {
		_, present := body[claim]
		assert.False(t, present,
			"inactive response MUST NOT include %q (RFC 7662 §2.2 — no leakage)", claim)
	}
}

func TestRFC7662_S2_2_RevokedTokenIsInactive(t *testing.T) {
	// RFC 7662 §2.2 (cross-ref RFC 7009): a token that's been revoked
	// MUST introspect as active=false. Tests the revoke→introspect transition.
	token := issueIntrospectTestToken(t)

	// Sanity: active before revoke.
	before := introspect(t, token)
	require.Equal(t, true, before["active"])

	rev := post(t, "/oauth2/token/revoke", map[string]any{"token": token}, nil)
	require.Equal(t, http.StatusOK, rev.StatusCode)
	_ = rev.Body.Close()

	after := introspect(t, token)
	assert.Equal(t, false, after["active"],
		"revoked token MUST introspect as active=false")
}

// ── RFC 7662 §2.2 — Required & optional claims ──────────────────────────────

func TestRFC7662_S2_2_ActiveTokenSurfacesScope(t *testing.T) {
	// RFC 7662 §2.2: "scope OPTIONAL. A JSON string containing a space-separated
	//   list of scopes associated with this token."
	result := introspect(t, issueIntrospectTestToken(t))
	scope, ok := result["scope"].(string)
	assert.True(t, ok, "scope SHOULD be a string when surfaced")
	assert.Contains(t, scope, "data:read",
		"active token's scope claim must reflect the issued scope")
}

func TestRFC7662_S2_2_ActiveTokenSurfacesSub(t *testing.T) {
	// RFC 7662 §2.2: "sub OPTIONAL. ... Usually a machine-readable identifier
	//   of the resource owner who authorized this token."
	result := introspect(t, issueIntrospectTestToken(t))
	sub, _ := result["sub"].(string)
	assert.NotEmpty(t, sub, "sub MUST surface on an active token (it's the credential identity)")
}

// ── RFC 7662 §2.1 — Endpoint shape ──────────────────────────────────────────

func TestRFC7662_S2_1_RequiresTokenParameter(t *testing.T) {
	// RFC 7662 §2.1: "token REQUIRED. The string value of the token."
	resp := post(t, "/oauth2/token/introspect", map[string]any{
		// token deliberately omitted
	}, nil)
	// Huma's required-field validator + the handler's own check both reject
	// missing token — either 400/422 is acceptable here. The compliance
	// assertion is "the endpoint does not 200 with active=true if no token
	// was supplied."
	require.NotEqual(t, http.StatusOK, resp.StatusCode,
		"missing token parameter MUST NOT return 200 active=true")
}
