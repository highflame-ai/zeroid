package integration_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Regression coverage for the self-mint scope escalation: apiKeyGrant,
// clientCredentials and jwtBearer used to silently narrow an unauthorized
// requested scope down to an empty set and mint anyway. IssueCredential
// omits the `scopes` claim entirely when the granted set is empty
// (credential.go: `if len(req.Scopes) > 0`), and Shield's checkScopeCeiling
// deliberately treats an absent claim as "check not applicable" — a
// backward-compat allowance for tokens minted before the scopes feature
// existed. The two behaviors compose into an escalation: an identity with
// allowed_scopes=["tools:read"] that explicitly asked for "tools:execute"
// got a token Shield would enforce NOTHING against, rather than one it
// would deny call_tool on.
//
// The fix (requireGrantableScope in oauth.go) mirrors tokenExchange's
// existing "empty result -> invalid_scope" safety net, extended to the
// three grants that mint a token for the caller's own use.

// TestAPIKeyGrant_UnauthorizedScopeRequestRejected is the exact repro:
// an identity registered with allowed_scopes=["tools:read"] asks the
// api_key grant for "tools:execute" and must be refused outright, not
// handed a token with no scopes claim at all.
func TestAPIKeyGrant_UnauthorizedScopeRequestRejected(t *testing.T) {
	externalID := uid("apikey-scope-escalation")
	resp := post(t, adminPath("/agents/register"), map[string]any{
		"name":           externalID,
		"external_id":    externalID,
		"sub_type":       "tool_agent",
		"trust_level":    "first_party",
		"created_by":     "test-user",
		"allowed_scopes": []string{"tools:read"},
	}, adminHeaders())
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	reg := decode(t, resp)
	apiKey, _ := reg["api_key"].(string)
	require.NotEmpty(t, apiKey)

	tokenResp := post(t, "/oauth2/token", map[string]any{
		"grant_type": "api_key",
		"api_key":    apiKey,
		"scope":      "tools:execute",
	}, nil)
	require.Equal(t, http.StatusBadRequest, tokenResp.StatusCode,
		"requesting a scope outside allowed_scopes must be rejected, not silently minted with no scopes claim")
	body := decode(t, tokenResp)
	assert.Equal(t, "invalid_scope", body["error"])
}

// TestAPIKeyGrant_AuthorizedScopeRequestGranted pins the normal narrowing
// path: requesting a scope that IS in allowed_scopes still mints, and mints
// exactly that scope (not the full ceiling). Unaffected by the fix.
func TestAPIKeyGrant_AuthorizedScopeRequestGranted(t *testing.T) {
	externalID := uid("apikey-scope-ok")
	resp := post(t, adminPath("/agents/register"), map[string]any{
		"name":           externalID,
		"external_id":    externalID,
		"sub_type":       "tool_agent",
		"trust_level":    "first_party",
		"created_by":     "test-user",
		"allowed_scopes": []string{"tools:read", "tools:execute"},
	}, adminHeaders())
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	apiKey, _ := decode(t, resp)["api_key"].(string)
	require.NotEmpty(t, apiKey)

	tokenResp := post(t, "/oauth2/token", map[string]any{
		"grant_type": "api_key",
		"api_key":    apiKey,
		"scope":      "tools:read",
	}, nil)
	require.Equal(t, http.StatusOK, tokenResp.StatusCode)
	token := decode(t, tokenResp)
	assert.Equal(t, "tools:read", token["scope"], "scope should be capped at requested value")
}

// TestAPIKeyGrant_NoScopeRequestGetsFullCeiling pins the RFC 6749 §3.3
// default: omitting scope entirely still grants the full ceiling. The fix
// only rejects an EXPLICIT request that resolves to nothing — an absent
// request is untouched.
func TestAPIKeyGrant_NoScopeRequestGetsFullCeiling(t *testing.T) {
	externalID := uid("apikey-scope-default")
	resp := post(t, adminPath("/agents/register"), map[string]any{
		"name":           externalID,
		"external_id":    externalID,
		"sub_type":       "tool_agent",
		"trust_level":    "first_party",
		"created_by":     "test-user",
		"allowed_scopes": []string{"tools:read", "tools:execute"},
	}, adminHeaders())
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	apiKey, _ := decode(t, resp)["api_key"].(string)
	require.NotEmpty(t, apiKey)

	tokenResp := post(t, "/oauth2/token", map[string]any{
		"grant_type": "api_key",
		"api_key":    apiKey,
	}, nil)
	require.Equal(t, http.StatusOK, tokenResp.StatusCode)
	token := decode(t, tokenResp)
	scope, _ := token["scope"].(string)
	assert.Contains(t, scope, "tools:read")
	assert.Contains(t, scope, "tools:execute")
}

// TestClientCredentials_UnauthorizedScopeRequestRejected is the
// client_credentials sibling: a client registered with a non-empty but
// narrower scope set (as opposed to TestOAuthAuthzHardening_
// ScopelessClientCannotWiden's zero-scope case, which takes a separate
// explicit-deny branch and never reached intersectScopes) must refuse a
// request for a scope outside that set.
func TestClientCredentials_UnauthorizedScopeRequestRejected(t *testing.T) {
	agentID := uid("cc-scope-escalation")
	registerIdentity(t, agentID, []string{"data:read"})
	client := registerOAuthClient(t, agentID, []string{"data:read"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
		"scope":         "data:write",
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"requesting a scope outside the client's registered scopes must be rejected")
	body := decode(t, resp)
	assert.Equal(t, "invalid_scope", body["error"])
}

// TestJWTBearer_UnauthorizedScopeRequestRejected is the jwt_bearer sibling.
func TestJWTBearer_UnauthorizedScopeRequestRejected(t *testing.T) {
	agentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	agentID := uid("jwtb-scope-escalation")
	identity := registerIdentity(t, agentID, []string{"data:read"}, ecPublicKeyPEM(t, agentKey))
	assertion := buildAssertion(t, agentKey, identity.WIMSEURI)

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
		"assertion":  assertion,
		"scope":      "data:write",
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"jwt_bearer requesting a scope outside allowed_scopes must be rejected")
	body := decode(t, resp)
	assert.Equal(t, "invalid_scope", body["error"])
}
