// /oauth2/authorize — the browser GET leg (#263).
//
// RFC 6749 §4.1.1 makes GET mandatory on the authorization endpoint, and a
// browser redirect is the only shape an off-the-shelf OAuth client knows how to
// drive. v1 mounted POST only, which is why an MCP client doing CIMD could not
// start the flow at all.
//
// The v1 rationale for withholding GET — "GET would surface principal
// credentials in URL query strings + access logs" — is preserved rather than
// traded away. The handler binds AuthorizeRequest.Form to the POST body ONLY,
// so on a GET req.Form is empty by construction and a resolver must read a
// header or cookie. TestAuthorizeGET_CredentialInQueryStringIsIgnored holds
// that line; mutating the handler to bind r.Form makes it fail with a 302.
//
// These tests use the header-based stub resolver from TestMain, because a
// GET-capable resolver necessarily reads headers.
package integration_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// getAuthorize issues a GET /oauth2/authorize with query parameters, plus
// optional headers for the credential. Mirrors postAuthorize.
func getAuthorize(t *testing.T, query url.Values, headers map[string]string) *http.Response {
	t.Helper()

	req, err := http.NewRequestWithContext(context.Background(),
		http.MethodGet, testServer.URL+"/oauth2/authorize?"+query.Encode(), nil)
	require.NoError(t, err)

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	require.NoError(t, err)

	return resp
}

// principalHeaders is the credential the header stub resolver recognises.
func principalHeaders() map[string]string {
	return map[string]string{
		"X-Test-Principal-Account": testAccountID,
		"X-Test-Principal-Project": testProjectID,
		"X-Test-Principal-User":    "user-authorize-get-test",
	}
}

// authorizeGETQuery returns the protocol parameters for a GET authorization
// request, plus the PKCE verifier so the resulting code can be exchanged.
// Deliberately carries NO credential — that travels in a header.
func authorizeGETQuery(t *testing.T) (query url.Values, verifier string) {
	t.Helper()

	verifier, challenge := buildPKCEPair(t)

	return url.Values{
		"client_id":             {testCLIClientID},
		"redirect_uri":          {testRedirectURI},
		"response_type":         {"code"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {"get-state-abc"},
	}, verifier
}

// TestAuthorizeGET_IsRouted is the narrowest statement of the bug: before #263
// chi had no GET handler and answered 405.
func TestAuthorizeGET_IsRouted(t *testing.T) {
	query, _ := authorizeGETQuery(t)

	resp := getAuthorize(t, query, nil)
	defer func() { _ = resp.Body.Close() }()

	require.NotEqual(t, http.StatusMethodNotAllowed, resp.StatusCode,
		"GET /oauth2/authorize must be routed (RFC 6749 §4.1.1)")
}

// TestAuthorizeGET_HappyPath walks the browser leg end to end: query-string
// protocol parameters, credential in a header, 302 back to redirect_uri with
// code + state, and the code redeems at /oauth2/token.
func TestAuthorizeGET_HappyPath(t *testing.T) {
	query, verifier := authorizeGETQuery(t)

	resp := getAuthorize(t, query, principalHeaders())
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusFound, resp.StatusCode,
		"expected 302 from GET /oauth2/authorize")

	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)

	code := loc.Query().Get("code")
	require.NotEmpty(t, code, "302 must carry ?code=")
	require.Equal(t, "get-state-abc", loc.Query().Get("state"),
		"state must round-trip (RFC 6749 §4.1.1 CSRF chain)")
	require.Equal(t, "no-store", resp.Header.Get("Cache-Control"))

	// The code is real: it redeems.
	tokenResp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "authorization_code",
		"client_id":     testCLIClientID,
		"code":          code,
		"code_verifier": verifier,
		"redirect_uri":  testRedirectURI,
	}, nil)
	require.Equal(t, http.StatusOK, tokenResp.StatusCode,
		"code from the GET leg must redeem at /oauth2/token")
	require.NotEmpty(t, decode(t, tokenResp)["access_token"])
}

// TestAuthorizeGET_CredentialInQueryStringIsIgnored is the security property
// that justified withholding GET in v1, kept as a test instead of as a missing
// feature.
//
// The handler binds the resolver-facing Form accessor to the POST body only, so
// on a GET req.Form is empty by construction. A caller who puts the credential
// in the URL gets 401, not a code — otherwise credentials would land in access
// logs, browser history, and Referer headers.
func TestAuthorizeGET_CredentialInQueryStringIsIgnored(t *testing.T) {
	query, _ := authorizeGETQuery(t)
	// The header stub's credential in the wrong channel, plus the form stub's
	// field names, so neither resolver can pick them up from the URL.
	query.Set("X-Test-Principal-Account", testAccountID)
	query.Set("test_principal_account", testAccountID)
	query.Set("test_principal_project", testProjectID)

	resp := getAuthorize(t, query, nil)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"a credential in the query string must NOT authenticate the principal; "+
			"got %d — credentials would be leaking into URLs", resp.StatusCode)
	require.Empty(t, resp.Header.Get("Location"),
		"no authorization code may be issued for a query-string credential")
}

// TestAuthorizeGET_NoCredentialIs401 pins the distinction between "you did not
// present a credential" (401) and "this server is not configured" (503). The
// suite registers resolvers, so the empty-chain sentinel must not fire here.
func TestAuthorizeGET_NoCredentialIs401(t *testing.T) {
	query, _ := authorizeGETQuery(t)

	resp := getAuthorize(t, query, nil)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	var body map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.Equal(t, "invalid_client", body["error"])
}

// TestAuthorizeGET_MissingRequiredParam keeps the field gate working when the
// parameters arrive via the query string rather than the body.
func TestAuthorizeGET_MissingRequiredParam(t *testing.T) {
	query, _ := authorizeGETQuery(t)
	query.Del("code_challenge")

	resp := getAuthorize(t, query, principalHeaders())
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var body map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.Equal(t, "invalid_request", body["error"])
	require.Contains(t, body["error_description"], "code_challenge")
}

// TestAuthorizeGET_RejectsNonCodeResponseType keeps OAuth 2.1's no-implicit rule
// enforced on the new leg.
func TestAuthorizeGET_RejectsNonCodeResponseType(t *testing.T) {
	query, _ := authorizeGETQuery(t)
	query.Set("response_type", "token")

	resp := getAuthorize(t, query, principalHeaders())
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var body map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.Contains(t, strings.ToLower(body["error_description"]), "response_type")
}

// TestAuthorizePOST_BodyParamsStillWork guards against the GET split breaking
// the original path: POST reads the body, and only the body.
func TestAuthorizePOST_BodyParamsStillWork(t *testing.T) {
	form, _ := authorizeBaseForm(t)

	resp := postAuthorize(t, form)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusFound, resp.StatusCode)
	require.Contains(t, resp.Header.Get("Location"), "code=")
}

// TestAuthorizePOST_QueryParamsAreNotRead pins the other half of the
// one-source-per-method rule. Reading the merged r.Form would let a caller put
// one client_id in the body and another in the query; whichever the handler
// happened to read is a parameter-smuggling seam.
func TestAuthorizePOST_QueryParamsAreNotRead(t *testing.T) {
	form, _ := authorizeBaseForm(t)
	form.Del("client_id") // supply it only via the query string

	req, err := http.NewRequestWithContext(context.Background(),
		http.MethodPost,
		testServer.URL+"/oauth2/authorize?client_id="+url.QueryEscape(testCLIClientID),
		strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"a POST must read client_id from the body only; reading the query would "+
			"allow parameter smuggling")

	var body map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.Contains(t, body["error_description"], "client_id")
}
