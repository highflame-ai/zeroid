// RFC 6749 (OAuth 2.0) compliance suite.
//
// See COMPLIANCE.md for the conventions this file follows: one MUST per test,
// test name carries the RFC + section citation, first comment quotes the
// clause, and the file groups tests in RFC order.
//
// Happy-path coverage of the various grant types lives in oauth_test.go.
// This file is the negative-space proof of §5.1 (successful response shape)
// and §5.2 (error response codes + shape) — the contract every OAuth client
// integrates against.

package integration_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── RFC 6749 §3.2 — Token endpoint ───────────────────────────────────────────

func TestRFC6749_S3_2_TokenEndpointRejectsUnsupportedGrantType(t *testing.T) {
	// RFC 6749 §3.2 / §5.2: "unsupported_grant_type ... The authorization
	//   grant type is not supported by the authorization server."
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type": "no_such_grant",
		"account_id": testAccountID,
		"project_id": testProjectID,
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body := decode(t, resp)
	assert.Equal(t, "unsupported_grant_type", body["error"])
}

// ── RFC 6749 §4.4 — Client Credentials grant ────────────────────────────────

func TestRFC6749_S4_4_ClientCredentialsRequiresAuthentication(t *testing.T) {
	// RFC 6749 §4.4.2 / §3.2.1: "The client MUST authenticate with the
	//   authorization server" — missing/blank client_secret is rejected.
	agentID := uid("compliance-cc-no-secret")
	registerIdentity(t, agentID, []string{"data:read"})
	client := registerOAuthClient(t, agentID, []string{"data:read"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type": "client_credentials",
		"client_id":  client.ClientID,
		// client_secret deliberately omitted
		"account_id": testAccountID,
		"project_id": testProjectID,
	}, nil)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"missing client_secret on client_credentials MUST 401 (RFC 6749 §3.2.1)")
	body := decode(t, resp)
	assert.Contains(t, []any{"invalid_client", "unauthorized_client"}, body["error"],
		"error code must be invalid_client or unauthorized_client (server choice)")
}

func TestRFC6749_S4_4_ClientCredentialsWrongSecretRejected(t *testing.T) {
	// RFC 6749 §5.2: "invalid_client ... Client authentication failed
	//   (e.g., unknown client, no client authentication included,
	//   or unsupported authentication method)."
	agentID := uid("compliance-cc-wrong-secret")
	registerIdentity(t, agentID, []string{"data:read"})
	client := registerOAuthClient(t, agentID, []string{"data:read"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     client.ClientID,
		"client_secret": "not-the-real-secret",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
	}, nil)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	body := decode(t, resp)
	assert.Equal(t, "invalid_client", body["error"])
}

// ── RFC 6749 §5.1 — Successful response ─────────────────────────────────────

func TestRFC6749_S5_1_SuccessfulResponseShape(t *testing.T) {
	// RFC 6749 §5.1: "access_token REQUIRED. ... token_type REQUIRED. ...
	//   expires_in RECOMMENDED. ... scope OPTIONAL (REQUIRED if scope of the
	//   access token differs from the requested scope)."
	agentID := uid("compliance-success-shape")
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
	body := decode(t, resp)

	assert.NotEmpty(t, body["access_token"], "access_token REQUIRED")
	assert.NotEmpty(t, body["token_type"], "token_type REQUIRED")
	assert.NotEmpty(t, body["expires_in"], "expires_in RECOMMENDED — ZeroID always sends it")
}

func TestRFC6749_S5_1_TokenTypeIsBearer(t *testing.T) {
	// RFC 6749 §7.1 (cross-ref): "Currently 'bearer' [RFC6750] ... is widely
	//   used." ZeroID emits token_type=Bearer for non-DPoP issuance.
	agentID := uid("compliance-token-type")
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
	body := decode(t, resp)
	assert.Equal(t, "Bearer", body["token_type"],
		"non-DPoP issuance MUST report token_type=Bearer (case-sensitive RFC 6750 §6.1.1)")
}

// ── RFC 6749 §5.2 — Error response ──────────────────────────────────────────

func TestRFC6749_S5_2_ErrorResponseShape(t *testing.T) {
	// RFC 6749 §5.2: "the authorization server responds with an HTTP 400
	//   ... and includes the following parameters: error REQUIRED,
	//   error_description OPTIONAL, error_uri OPTIONAL."
	// §5.2 also permits 401 specifically for invalid_client — which is what
	// a nonexistent client_id triggers — so the assertion accepts both
	// 400 and 401.
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type": "client_credentials",
		"client_id":  uid("nonexistent-client"),
		"account_id": testAccountID,
		"project_id": testProjectID,
	}, nil)
	assert.Contains(t, []int{http.StatusBadRequest, http.StatusUnauthorized}, resp.StatusCode,
		"error response MUST use 400 (or 401 for invalid_client per §5.2)")
	body := decode(t, resp)
	assert.NotEmpty(t, body["error"], "error field REQUIRED in error response")
	_, isStr := body["error"].(string)
	assert.True(t, isStr, "error field MUST be a string")
}

func TestRFC6749_S5_2_InvalidRequestOnMissingRequiredField(t *testing.T) {
	// RFC 6749 §5.2: "invalid_request ... The request is missing a required
	//   parameter, includes an invalid parameter value, includes a parameter
	//   more than once, or is otherwise malformed."
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type": "client_credentials",
		// account_id + project_id deliberately omitted
		"client_id":     "any",
		"client_secret": "any",
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body := decode(t, resp)
	assert.Equal(t, "invalid_request", body["error"],
		"missing required field MUST map to invalid_request, not invalid_grant or invalid_client")
}

func TestRFC6749_S5_2_JwtBearerInvalidRequestOnMissingSubject(t *testing.T) {
	// RFC 6749 §5.2: "invalid_request ... The request is missing a required
	//   parameter ...". §5.2 also defines invalid_grant for grants that are
	//   "invalid, expired, revoked, [or] do not match" — but the assertion
	//   itself missing is a request-shape error, not a grant-validity error.
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
		// subject (the assertion JWT) deliberately omitted
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body := decode(t, resp)
	assert.Equal(t, "invalid_request", body["error"])
}
