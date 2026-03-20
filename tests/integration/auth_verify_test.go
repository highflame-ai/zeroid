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

// issueAPIKeyToken registers an agent, exchanges its API key for a JWT, and
// returns the access token string.
func issueAPIKeyToken(t *testing.T, externalID string) string {
	t.Helper()
	agent := registerAgent(t, externalID)
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type": "api_key",
		"api_key":    agent.APIKey,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "issueAPIKeyToken: expected 200 from /oauth2/token")
	return decode(t, resp)["access_token"].(string)
}

// TestAuthVerify_MissingAuthorizationHeader checks that a request with no
// Authorization header is rejected with 401 and the correct WWW-Authenticate
// challenge.
func TestAuthVerify_MissingAuthorizationHeader(t *testing.T) {
	resp := get(t, "/oauth2/token/verify", nil)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, `Bearer error="missing_token"`, resp.Header.Get("WWW-Authenticate"))
}

// TestAuthVerify_WrongScheme checks that a non-Bearer Authorization scheme
// (e.g. "Basic") is rejected as an invalid request.
func TestAuthVerify_WrongScheme(t *testing.T) {
	resp := get(t, "/oauth2/token/verify", map[string]string{
		"Authorization": "Basic dXNlcjpwYXNz",
	})
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, `Bearer error="invalid_request"`, resp.Header.Get("WWW-Authenticate"))
}

// TestAuthVerify_EmptyBearerToken checks that "Bearer " followed by only
// whitespace is rejected as an invalid request.
func TestAuthVerify_EmptyBearerToken(t *testing.T) {
	resp := get(t, "/oauth2/token/verify", map[string]string{
		"Authorization": "Bearer   ",
	})
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, `Bearer error="invalid_request"`, resp.Header.Get("WWW-Authenticate"))
}

// TestAuthVerify_InvalidToken checks that a well-formed but unrecognised token
// string is rejected with the invalid_token challenge.
func TestAuthVerify_InvalidToken(t *testing.T) {
	resp := get(t, "/oauth2/token/verify", map[string]string{
		"Authorization": "Bearer not.a.valid.jwt",
	})
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, `Bearer error="invalid_token"`, resp.Header.Get("WWW-Authenticate"))
}

// TestAuthVerify_ValidToken checks that a valid JWT issued by ZeroID is
// accepted with 200 and that identity headers are populated from the token
// claims.
func TestAuthVerify_ValidToken(t *testing.T) {
	token := issueAPIKeyToken(t, uid("verify-agent"))

	resp := get(t, "/oauth2/token/verify", map[string]string{
		"Authorization": "Bearer " + token,
	})
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// sub → X-Forwarded-User must always be set for a linked-identity token.
	assert.NotEmpty(t, resp.Header.Get("X-Forwarded-User"), "X-Forwarded-User should be set from sub claim")

	// Tenant scope headers.
	assert.Equal(t, testAccountID, resp.Header.Get("X-Zeroid-Account-ID"))
	assert.Equal(t, testProjectID, resp.Header.Get("X-Zeroid-Project-ID"))
}

// TestAuthVerify_RevokedToken checks that a token revoked via
// POST /oauth2/token/revoke is subsequently rejected by the verify endpoint.
func TestAuthVerify_RevokedToken(t *testing.T) {
	token := issueAPIKeyToken(t, uid("verify-revoked-agent"))

	// Revoke the token.
	revokeResp := post(t, "/oauth2/token/revoke", map[string]string{"token": token}, nil)
	require.Equal(t, http.StatusOK, revokeResp.StatusCode)
	revokeResp.Body.Close()

	// Verify must now reject it.
	resp := get(t, "/oauth2/token/verify", map[string]string{
		"Authorization": "Bearer " + token,
	})
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, `Bearer error="invalid_token"`, resp.Header.Get("WWW-Authenticate"))
}

// TestAuthVerify_ResponseBodyOnSuccess checks that the 200 response body is
// the expected {"active":true} JSON — nginx auth_request ignores it but
// explicit clients may depend on it.
func TestAuthVerify_ResponseBodyOnSuccess(t *testing.T) {
	token := issueAPIKeyToken(t, uid("verify-body-agent"))

	resp := get(t, "/oauth2/token/verify", map[string]string{
		"Authorization": "Bearer " + token,
	})
	body := decode(t, resp)

	active, _ := body["active"].(bool)
	assert.True(t, active)
}

// authVerifyHeaders calls /oauth2/token/verify with the given JWT and returns
// the response headers (and closes the body).
func authVerifyHeaders(t *testing.T, token string) http.Header {
	t.Helper()
	resp := get(t, "/oauth2/token/verify", map[string]string{
		"Authorization": "Bearer " + token,
	})
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	return resp.Header
}

// TestAuthVerify_Headers_APIKeyGrant verifies that all identity headers are set
// for an api_key token, including X-Zeroid-Act-Sub (act.sub = created_by user).
func TestAuthVerify_Headers_APIKeyGrant(t *testing.T) {
	token := issueAPIKeyToken(t, uid("hdr-apikey-agent"))
	h := authVerifyHeaders(t, token)

	assert.NotEmpty(t, h.Get("X-Forwarded-User"), "sub → X-Forwarded-User")
	assert.Equal(t, "agent", h.Get("X-Zeroid-Identity-Type"), "identity_type → X-Zeroid-Identity-Type")
	assert.NotEmpty(t, h.Get("X-Zeroid-Trust-Level"), "trust_level → X-Zeroid-Trust-Level")
	assert.Equal(t, testAccountID, h.Get("X-Zeroid-Account-Id"), "account_id → X-Zeroid-Account-Id")
	assert.Equal(t, testProjectID, h.Get("X-Zeroid-Project-Id"), "project_id → X-Zeroid-Project-Id")
	assert.NotEmpty(t, h.Get("X-Zeroid-External-Id"), "external_id → X-Zeroid-External-Id")
	assert.NotEmpty(t, h.Get("X-Zeroid-Act-Sub"), "act.sub should be set for api_key grant (created_by user)")
}

// TestAuthVerify_Headers_ClientCredentials verifies that all identity headers
// are set for a client_credentials token and that X-Zeroid-Act-Sub is absent
// (no delegation chain — agent acts purely on its own authority).
func TestAuthVerify_Headers_ClientCredentials(t *testing.T) {
	agentID := uid("hdr-cc-agent")
	registerIdentity(t, agentID, []string{"data:read"})
	client := registerOAuthClient(t, agentID, []string{"data:read"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	token := decode(t, resp)["access_token"].(string)

	h := authVerifyHeaders(t, token)

	assert.NotEmpty(t, h.Get("X-Forwarded-User"), "sub → X-Forwarded-User")
	assert.NotEmpty(t, h.Get("X-Zeroid-Trust-Level"), "trust_level → X-Zeroid-Trust-Level")
	assert.Equal(t, testAccountID, h.Get("X-Zeroid-Account-Id"), "account_id → X-Zeroid-Account-Id")
	assert.Equal(t, testProjectID, h.Get("X-Zeroid-Project-Id"), "project_id → X-Zeroid-Project-Id")
	assert.Empty(t, h.Get("X-Zeroid-Act-Sub"), "X-Zeroid-Act-Sub must be absent for client_credentials (no delegation)")
}

// TestAuthVerify_Headers_TokenExchange verifies that X-Zeroid-Act-Sub is set to
// the orchestrator's WIMSE URI for a delegated token_exchange token.
func TestAuthVerify_Headers_TokenExchange(t *testing.T) {
	// Set up orchestrator with client_credentials.
	orchID := uid("hdr-orch")
	registerIdentity(t, orchID, []string{"data:read"})
	orchClient := registerOAuthClient(t, orchID, []string{"data:read"})

	orchResp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     orchClient.ClientID,
		"client_secret": orchClient.ClientSecret,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, orchResp.StatusCode)
	orchToken := decode(t, orchResp)["access_token"].(string)
	orchWIMSE := introspect(t, orchToken)["sub"].(string)

	// Set up sub-agent with a key pair for the actor assertion.
	subKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	subID := uid("hdr-sub")
	subIdentity := registerIdentity(t, subID, []string{"data:read"}, ecPublicKeyPEM(t, subKey))
	actorAssertion := buildAssertion(t, subKey, subIdentity.WIMSEURI)

	// Exchange: orchestrator delegates to sub-agent.
	exchResp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": orchToken,
		"actor_token":   actorAssertion,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, exchResp.StatusCode)
	delegatedToken := decode(t, exchResp)["access_token"].(string)

	h := authVerifyHeaders(t, delegatedToken)

	assert.Equal(t, subIdentity.WIMSEURI, h.Get("X-Forwarded-User"), "sub should be the sub-agent WIMSE URI")
	assert.Equal(t, orchWIMSE, h.Get("X-Zeroid-Act-Sub"), "act.sub should be the orchestrator WIMSE URI")
	assert.NotEmpty(t, h.Get("X-Zeroid-Trust-Level"))
	assert.Equal(t, testAccountID, h.Get("X-Zeroid-Account-Id"))
	assert.Equal(t, testProjectID, h.Get("X-Zeroid-Project-Id"))
}
