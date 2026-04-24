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

// TestOAuthFormCompatContentTypeCaseInsensitive verifies RFC 7231 §3.1.1.1
// case-insensitive media-type matching: a mixed-case Content-Type value and
// a charset parameter must still be accepted.
func TestOAuthFormCompatContentTypeCaseInsensitive(t *testing.T) {
	agentID := uid("form-compat-case")
	scopes := []string{"data:read"}
	registerIdentity(t, agentID, scopes)
	client := registerOAuthClient(t, agentID, scopes)

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"account_id":    {testAccountID},
		"project_id":    {testProjectID},
		"client_id":     {client.ClientID},
		"client_secret": {client.ClientSecret},
		"scope":         {"data:read"},
	}
	req, err := http.NewRequest(http.MethodPost, testServer.URL+"/oauth2/token", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "Application/X-WWW-Form-Urlencoded; charset=UTF-8")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"mixed-case Content-Type with charset param must be accepted")
}

// TestOAuthFormCompatRejectsDuplicateParams enforces RFC 6749 §3.1: request
// parameters MUST NOT be included more than once. Duplicates must be
// rejected, not silently collapsed to the first value.
func TestOAuthFormCompatRejectsDuplicateParams(t *testing.T) {
	// Handcraft a body with a repeated parameter.
	body := "grant_type=client_credentials&scope=a&scope=b"
	req, err := http.NewRequest(http.MethodPost, testServer.URL+"/oauth2/token", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"duplicate OAuth parameters must be rejected (RFC 6749 §3.1)")
	var body400 map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body400))
	errObj, ok := body400["error"].(map[string]any)
	require.True(t, ok)
	assert.Contains(t, errObj["message"], "duplicate OAuth parameter")
}

// TestOAuthFormCompatEmptyParamsOmitted enforces RFC 6749 §3.2: parameters
// sent without a value MUST be treated as if they were omitted. Verified by
// sending an empty scope param — the request should still succeed and the
// missing-scope semantics should apply (no mandatory-field failure because
// of the empty value, no bound empty-string on the server side).
func TestOAuthFormCompatEmptyParamsOmitted(t *testing.T) {
	agentID := uid("form-compat-empty")
	scopes := []string{"data:read"}
	registerIdentity(t, agentID, scopes)
	client := registerOAuthClient(t, agentID, scopes)

	resp := postForm(t, "/oauth2/token", url.Values{
		"grant_type":    {"client_credentials"},
		"account_id":    {testAccountID},
		"project_id":    {testProjectID},
		"client_id":     {client.ClientID},
		"client_secret": {client.ClientSecret},
		// scope intentionally empty — must be treated as omitted.
		"scope": {""},
	})
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"empty-value params must be treated as omitted, not a bind error")
}

// TestOAuthFormCompatOpenAPIAdvertisesFormContentType confirms that the
// OpenAPI specification exposes application/x-www-form-urlencoded alongside
// application/json for each OAuth endpoint so generated clients and docs
// know which wire shapes the server accepts.
func TestOAuthFormCompatOpenAPIAdvertisesFormContentType(t *testing.T) {
	resp, err := http.Get(testServer.URL + "/openapi.json")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var spec map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&spec))

	paths, _ := spec["paths"].(map[string]any)
	require.NotNil(t, paths)

	for _, p := range []string{"/oauth2/token", "/oauth2/token/introspect", "/oauth2/token/revoke"} {
		pathItem, _ := paths[p].(map[string]any)
		require.NotNil(t, pathItem, "path %s missing from OpenAPI spec", p)
		op, _ := pathItem["post"].(map[string]any)
		require.NotNil(t, op, "post op missing for %s", p)
		reqBody, _ := op["requestBody"].(map[string]any)
		require.NotNil(t, reqBody, "requestBody missing for %s", p)
		content, _ := reqBody["content"].(map[string]any)
		require.NotNil(t, content, "content missing for %s", p)
		assert.Contains(t, content, "application/json", "%s must advertise JSON", p)
		assert.Contains(t, content, "application/x-www-form-urlencoded",
			"%s must advertise form encoding per RFC 6749/7662/7009", p)
	}
}
