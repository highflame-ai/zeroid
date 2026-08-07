// /oauth2/authorize — the browser GET leg and the built-in api_key
// PrincipalResolver (#263).
//
// Two gaps closed here, both of which made ZeroID advertise a flow no
// deployment could serve:
//
//   - GET was not mounted at all, though RFC 6749 §4.1.1 says the
//     authorization endpoint MUST support it, and a browser redirect is the
//     only shape an off-the-shelf OAuth client (an MCP client doing CIMD,
//     say) knows how to drive.
//   - No PrincipalResolver was registered anywhere in cmd/zeroid, so a
//     shipped ZeroID answered every request 503 while its AS metadata
//     advertised `authorization_code` and
//     `client_id_metadata_document_supported: true`.
//
// The v1 reason for withholding GET — "GET would surface principal
// credentials in URL query strings + access logs" — is preserved rather than
// traded away, and TestAuthorizeGET_APIKeyInQueryStringIsIgnored is the test
// that holds the line.
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

// authorizeGETQuery is authorizeBaseForm minus the stub resolver's magic
// fields: on GET those would have to travel in the query string, which is
// exactly what the credential rule forbids. The api_key resolver supplies
// the principal instead, via a header.
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

// TestAuthorizeGET_IsRouted is the narrowest statement of the bug: before
// #263 chi had no GET handler and answered 405.
func TestAuthorizeGET_IsRouted(t *testing.T) {
	query, _ := authorizeGETQuery(t)
	resp := getAuthorize(t, query, nil)
	defer func() { _ = resp.Body.Close() }()

	require.NotEqual(t, http.StatusMethodNotAllowed, resp.StatusCode,
		"GET /oauth2/authorize must be routed (RFC 6749 §4.1.1)")
	require.NotEqual(t, http.StatusServiceUnavailable, resp.StatusCode,
		"503 means the resolver chain is empty — the built-in api_key resolver "+
			"should always be present")
}

// TestAuthorizeGET_HappyPath walks the browser leg end to end: query-string
// protocol parameters, credential in a header, 302 back to redirect_uri with
// code + state, and the code redeems at /oauth2/token.
func TestAuthorizeGET_HappyPath(t *testing.T) {
	apiKey := registerAgent(t, "authz-get-happy").APIKey
	query, verifier := authorizeGETQuery(t)

	resp := getAuthorize(t, query, map[string]string{"X-API-Key": apiKey})
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusFound, resp.StatusCode,
		"expected 302 from GET /oauth2/authorize")

	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	code := loc.Query().Get("code")
	require.NotEmpty(t, code, "302 must carry ?code=")
	require.Equal(t, "get-state-abc", loc.Query().Get("state"),
		"state must round-trip (CSRF binding)")

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

// TestAuthorizeGET_APIKeyInQueryStringIsIgnored is the security property that
// justified withholding GET in v1, kept as a test instead of as a missing
// feature.
//
// The handler binds the resolver-facing Form accessor to the POST body only,
// so on a GET `req.Form("api_key")` is empty by construction. A caller who
// puts a valid key in the URL gets 401, not a code — otherwise credentials
// would end up in access logs, browser history, and Referer headers.
func TestAuthorizeGET_APIKeyInQueryStringIsIgnored(t *testing.T) {
	apiKey := registerAgent(t, "authz-get-queryleak").APIKey
	query, _ := authorizeGETQuery(t)
	query.Set("api_key", apiKey) // valid key, wrong channel

	resp := getAuthorize(t, query, nil)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"a credential in the query string must NOT authenticate the principal; "+
			"got %d — credentials would be leaking into URLs", resp.StatusCode)
	require.Empty(t, resp.Header.Get("Location"),
		"no authorization code may be issued for a query-string credential")
}

// TestAuthorizeGET_BearerAPIKey covers the other header shape. Only a Bearer
// that looks like an api_key is claimed — a bearer access token is a different
// credential and must fall through rather than surface as invalid_client.
func TestAuthorizeGET_BearerAPIKey(t *testing.T) {
	apiKey := registerAgent(t, "authz-get-bearer").APIKey
	query, _ := authorizeGETQuery(t)

	resp := getAuthorize(t, query, map[string]string{"Authorization": "Bearer " + apiKey})
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusFound, resp.StatusCode,
		"Authorization: Bearer <zid_sk_...> must authenticate the principal")
	require.Contains(t, resp.Header.Get("Location"), "code=")
}

// TestAuthorizeGET_NoCredentialIs401 pins the distinction the 503 used to
// destroy: "you did not present a credential" (401) is not "this server is
// not configured" (503).
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
	apiKey := registerAgent(t, "authz-get-missingparam").APIKey
	query, _ := authorizeGETQuery(t)
	query.Del("code_challenge")

	resp := getAuthorize(t, query, map[string]string{"X-API-Key": apiKey})
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var body map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.Equal(t, "invalid_request", body["error"])
	require.Contains(t, body["error_description"], "code_challenge")
}

// TestAuthorizePOST_BuiltinAPIKeyResolver proves the built-in works on the
// POST leg too, with no resolver registered for it — the stub resolver in
// TestMain declines because the test_principal_* fields are absent.
func TestAuthorizePOST_BuiltinAPIKeyResolver(t *testing.T) {
	apiKey := registerAgent(t, "authz-post-builtin").APIKey
	form, _ := authorizeBaseForm(t)
	for _, k := range []string{"test_principal_account", "test_principal_project", "test_principal_user"} {
		form.Del(k)
	}
	form.Set("api_key", apiKey)

	resp := postAuthorize(t, form)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusFound, resp.StatusCode,
		"the built-in api_key resolver must handle a POST no other resolver claims")
	require.Contains(t, resp.Header.Get("Location"), "code=")
}

// TestAuthorize_RegisteredResolverWinsOverBuiltin pins the ordering. The
// built-in runs LAST, so an embedder's resolver keeps precedence on any
// request it recognises — adding a fallback must not silently change who
// authenticates an existing deployment's traffic.
func TestAuthorize_RegisteredResolverWinsOverBuiltin(t *testing.T) {
	apiKey := registerAgent(t, "authz-precedence").APIKey
	form, verifier := authorizeBaseForm(t) // carries the stub's test_principal_* fields
	form.Set("api_key", apiKey)            // ...and a valid api_key

	resp := postAuthorize(t, form)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusFound, resp.StatusCode)

	// The stub resolver sets UserID from test_principal_user; the built-in
	// would set it from the api_key's identity. Redeem and introspect to see
	// which one ran.
	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	code := loc.Query().Get("code")
	require.NotEmpty(t, code)

	tokenResp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "authorization_code",
		"client_id":     testCLIClientID,
		"code":          code,
		"code_verifier": verifier,
		"redirect_uri":  testRedirectURI,
	}, nil)
	require.Equal(t, http.StatusOK, tokenResp.StatusCode)
	accessToken, _ := decode(t, tokenResp)["access_token"].(string)
	require.NotEmpty(t, accessToken)

	require.Equal(t, "user-authorize-test", introspect(t, accessToken)["sub"],
		"the registered resolver must win; the built-in api_key fallback ran instead")
}

// TestAuthorizeGET_RejectsNonCodeResponseType keeps OAuth 2.1's no-implicit
// rule enforced on the new leg.
func TestAuthorizeGET_RejectsNonCodeResponseType(t *testing.T) {
	apiKey := registerAgent(t, "authz-get-responsetype").APIKey
	query, _ := authorizeGETQuery(t)
	query.Set("response_type", "token")

	resp := getAuthorize(t, query, map[string]string{"X-API-Key": apiKey})
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var body map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.Contains(t, strings.ToLower(body["error_description"]), "response_type")
}
