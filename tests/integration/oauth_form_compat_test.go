package integration_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// postForm posts an application/x-www-form-urlencoded body to the test server
// and returns the response. Mirrors the request shape the SDK's
// pkg/authjwt.Verifier produces for real-time introspection and the shape
// every RFC 6749/7662/7009 client produces by default.
func postForm(t *testing.T, path string, form url.Values) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, testServer.URL+path, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

// TestOAuthFormCompatTokenIntrospectRevoke exercises the full RFC 6749/7662/7009
// form-encoded happy path. Guards against regressions of the incompatibility
// where the global JSON-only Content-Type gate rejected spec-compliant clients
// (notably pkg/authjwt.VerifyRealTime) with a 400 before the OAuth handlers
// ever saw the request.
func TestOAuthFormCompatTokenIntrospectRevoke(t *testing.T) {
	agentID := uid("form-compat")
	scopes := []string{"data:read"}
	registerIdentity(t, agentID, scopes)
	client := registerOAuthClient(t, agentID, scopes)

	// 1. Token endpoint — form-encoded client_credentials grant.
	tokenResp := postForm(t, "/oauth2/token", url.Values{
		"grant_type":    {"client_credentials"},
		"account_id":    {testAccountID},
		"project_id":    {testProjectID},
		"client_id":     {client.ClientID},
		"client_secret": {client.ClientSecret},
		"scope":         {"data:read"},
	})
	require.Equal(t, http.StatusOK, tokenResp.StatusCode,
		"form-encoded token request must be accepted (RFC 6749 §4.4.2)")
	var tokBody map[string]any
	require.NoError(t, json.NewDecoder(tokenResp.Body).Decode(&tokBody))
	_ = tokenResp.Body.Close()
	accessToken, _ := tokBody["access_token"].(string)
	require.NotEmpty(t, accessToken)

	// 2. Introspect endpoint — form-encoded (RFC 7662 §2.1).
	introspectResp := postForm(t, "/oauth2/token/introspect", url.Values{"token": {accessToken}})
	require.Equal(t, http.StatusOK, introspectResp.StatusCode,
		"form-encoded introspect must be accepted (RFC 7662 §2.1)")
	var introBody map[string]any
	require.NoError(t, json.NewDecoder(introspectResp.Body).Decode(&introBody))
	_ = introspectResp.Body.Close()
	assert.True(t, introBody["active"].(bool), "token should introspect active")

	// 3. Revoke endpoint — form-encoded (RFC 7009 §2.1).
	revokeResp := postForm(t, "/oauth2/token/revoke", url.Values{"token": {accessToken}})
	require.Equal(t, http.StatusOK, revokeResp.StatusCode,
		"form-encoded revoke must be accepted (RFC 7009 §2.1)")
	_, _ = io.Copy(io.Discard, revokeResp.Body)
	_ = revokeResp.Body.Close()

	// 4. Introspect again — should now be inactive.
	introspectResp = postForm(t, "/oauth2/token/introspect", url.Values{"token": {accessToken}})
	require.Equal(t, http.StatusOK, introspectResp.StatusCode)
	require.NoError(t, json.NewDecoder(introspectResp.Body).Decode(&introBody))
	_ = introspectResp.Body.Close()
	assert.False(t, introBody["active"].(bool), "token should introspect inactive after revocation")
}

// TestOAuthFormCompatDoesNotLeakToOtherEndpoints confirms the form-compat
// rewrite is scoped only to the OAuth endpoints it targets. Form-encoded
// bodies to non-OAuth POST endpoints must still be rejected by the JSON-only
// validator.
func TestOAuthFormCompatDoesNotLeakToOtherEndpoints(t *testing.T) {
	resp := postForm(t, adminPath("/identities"), url.Values{"external_id": {"x"}})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"non-OAuth endpoints must still reject form-encoded bodies")
	_ = resp.Body.Close()
}
