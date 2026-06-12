package integration_test

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests for client_secret_basic support on the introspection (RFC 7662) and
// revocation (RFC 7009) endpoints. The endpoints accept client credentials
// either as body fields (client_secret_post) or via the Authorization header
// (client_secret_basic, RFC 6749 §2.3.1); using both at once is rejected per
// RFC 6749 §2.3.
//
// Run in isolation:
//
//	go test ./tests/integration/ -run 'TestInspectionBasicAuth' -count=1

// basicAuthHeader builds an RFC 6749 §2.3.1 Basic credential header.
func basicAuthHeader(clientID, clientSecret string) map[string]string {
	cred := base64.StdEncoding.EncodeToString([]byte(clientID + ":" + clientSecret))
	return map[string]string{"Authorization": "Basic " + cred}
}

// inspectionFixture mints a token plus the confidential client that owns it.
func inspectionFixture(t *testing.T, prefix string) (token string, client oauthClientResp) {
	t.Helper()
	agentID := uid(prefix)
	registerIdentity(t, agentID, []string{"data:read"})
	client = registerOAuthClient(t, agentID, []string{"data:read"})
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	return decode(t, resp)["access_token"].(string), client
}

// TestInspectionBasicAuth_IntrospectAcceptsBasic verifies a valid
// client_secret_basic header authenticates an introspection call.
func TestInspectionBasicAuth_IntrospectAcceptsBasic(t *testing.T) {
	token, client := inspectionFixture(t, "basic-introspect")

	resp := post(t, "/oauth2/token/introspect", map[string]any{
		"token": token,
	}, basicAuthHeader(client.ClientID, client.ClientSecret))
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	assert.Equal(t, true, body["active"], "valid token introspected with Basic auth must be active")
}

// TestInspectionBasicAuth_IntrospectRejectsWrongBasicSecret verifies a wrong
// secret in the Basic header is rejected with invalid_client and the RFC 6749
// §5.2 WWW-Authenticate echo.
func TestInspectionBasicAuth_IntrospectRejectsWrongBasicSecret(t *testing.T) {
	token, client := inspectionFixture(t, "basic-introspect-bad")

	resp := post(t, "/oauth2/token/introspect", map[string]any{
		"token": token,
	}, basicAuthHeader(client.ClientID, "definitely-the-wrong-secret"))
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("WWW-Authenticate"), "Basic",
		"401 on a Basic attempt must carry a Basic WWW-Authenticate challenge (RFC 6749 §5.2)")
	body := decode(t, resp)
	assert.Equal(t, "invalid_client", body["error"])
}

// TestInspectionBasicAuth_RejectsBothMethods verifies that presenting Basic
// header credentials AND body credentials in the same request is rejected
// (RFC 6749 §2.3: at most one client authentication method per request).
func TestInspectionBasicAuth_RejectsBothMethods(t *testing.T) {
	token, client := inspectionFixture(t, "basic-both-methods")

	resp := post(t, "/oauth2/token/introspect", map[string]any{
		"token":         token,
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
	}, basicAuthHeader(client.ClientID, client.ClientSecret))
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body := decode(t, resp)
	assert.Equal(t, "invalid_request", body["error"])
}

// TestInspectionBasicAuth_RevokeAcceptsBasic verifies a valid
// client_secret_basic header authenticates a revocation call, and the token
// is actually revoked.
func TestInspectionBasicAuth_RevokeAcceptsBasic(t *testing.T) {
	token, client := inspectionFixture(t, "basic-revoke")

	resp := post(t, "/oauth2/token/revoke", map[string]any{
		"token": token,
	}, basicAuthHeader(client.ClientID, client.ClientSecret))
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	assert.False(t, introspect(t, token)["active"].(bool), "token must be inactive after Basic-authed revoke")
}

// TestInspectionBasicAuth_RevokeRejectsWrongBasicSecret verifies the revoke
// endpoint rejects a wrong Basic secret with invalid_client — the RFC 7009
// §2.2.1 carve-out from the always-200 contract — and does NOT revoke.
func TestInspectionBasicAuth_RevokeRejectsWrongBasicSecret(t *testing.T) {
	token, client := inspectionFixture(t, "basic-revoke-bad")

	resp := post(t, "/oauth2/token/revoke", map[string]any{
		"token": token,
	}, basicAuthHeader(client.ClientID, "definitely-the-wrong-secret"))
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("WWW-Authenticate"), "Basic")
	_ = resp.Body.Close()

	assert.True(t, introspect(t, token)["active"].(bool), "token must remain active after rejected revoke")
}

// TestInspectionBasicAuth_MalformedBasicHeaderRejected verifies a Basic header
// that is not valid base64 (or lacks the id:secret shape) is invalid_request.
func TestInspectionBasicAuth_MalformedBasicHeaderRejected(t *testing.T) {
	token, _ := inspectionFixture(t, "basic-malformed")

	resp := post(t, "/oauth2/token/introspect", map[string]any{
		"token": token,
	}, map[string]string{"Authorization": "Basic not-base64!!"})
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body := decode(t, resp)
	assert.Equal(t, "invalid_request", body["error"])
}

// TestInspectionBasicAuth_MetadataAdvertisesAuthMethods verifies the RFC 8414
// document advertises the supported client auth methods for both endpoints.
func TestInspectionBasicAuth_MetadataAdvertisesAuthMethods(t *testing.T) {
	resp := get(t, "/.well-known/oauth-authorization-server", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)

	for _, key := range []string{
		"introspection_endpoint_auth_methods_supported",
		"revocation_endpoint_auth_methods_supported",
	} {
		methods, ok := body[key].([]any)
		require.True(t, ok, "metadata must include %s", key)
		assert.ElementsMatch(t, []any{"client_secret_post", "client_secret_basic"}, methods, key)
	}
}
