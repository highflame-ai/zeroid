// /oauth2/authorize — the browser GET leg (#263).
//
// RFC 6749 §3.1 makes GET mandatory on the authorization endpoint and POST
// permitted ("MAY support"), so mounting both is conformant. A browser redirect
// is the only shape an off-the-shelf OAuth client knows how to drive, and v1
// mounted POST only — which is why an MCP client doing CIMD could not start the
// flow at all.
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
		"GET /oauth2/authorize must be routed (RFC 6749 §3.1)")
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
// in the URL does not get a code.
//
// Since #279 the shape of the refusal changed — an access_denied redirect rather
// than a 401 JSON body — but the property did not, and the assertions here are
// about the property: no `code` is issued, and (newly relevant now that there IS
// a Location) the credential must not appear anywhere in it. The redirect is
// built from the client's REGISTERED redirect_uri, never from the inbound URL,
// so an echoed query string would be a leak straight back out to the client.
func TestAuthorizeGET_CredentialInQueryStringIsIgnored(t *testing.T) {
	const leakedSecret = "zid_sk_querystringleak"

	query, _ := authorizeGETQuery(t)
	// The header stub's credential in the wrong channel, plus the form stub's
	// field names, so neither resolver can pick them up from the URL.
	query.Set("X-Test-Principal-Account", testAccountID)
	query.Set("test_principal_account", testAccountID)
	query.Set("test_principal_project", testProjectID)
	query.Set("api_key", leakedSecret)

	resp := getAuthorize(t, query, nil)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusFound, resp.StatusCode,
		"expected the access_denied redirect; got %d", resp.StatusCode)

	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)

	require.Empty(t, loc.Query().Get("code"),
		"a credential in the query string must NOT authenticate the principal — no code may be issued")
	require.Equal(t, "access_denied", loc.Query().Get("error"))
	require.NotContains(t, resp.Header.Get("Location"), leakedSecret,
		"the error redirect must not echo the inbound query string — that would hand the "+
			"credential back out in a Location header")
}

// TestAuthorizeGET_NoCredentialRedirectsAccessDenied pins the distinction between
// "you did not present a credential" and "this server is not configured".
//
// The first is the resource owner's failure and belongs back at the client as
// access_denied per RFC 6749 §4.1.2.1 — the browser case a user hits by not being
// signed in. The second is a deployer misconfiguration (empty resolver chain),
// which stays a 503 JSON body because it is not the client's problem and there is
// nothing useful for it to do with a redirect. The suite registers resolvers, so
// the empty-chain sentinel must not fire here.
func TestAuthorizeGET_NoCredentialRedirectsAccessDenied(t *testing.T) {
	query, _ := authorizeGETQuery(t)
	query.Set("state", "no-credential-state")

	resp := getAuthorize(t, query, nil)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusFound, resp.StatusCode)
	require.Equal(t, "no-store", resp.Header.Get("Cache-Control"))

	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "access_denied", loc.Query().Get("error"))
	require.NotEmpty(t, loc.Query().Get("error_description"))
	require.Equal(t, "no-credential-state", loc.Query().Get("state"),
		"state must round-trip on the error path — it is the client's correlation handle")
	require.Empty(t, loc.Query().Get("code"))
}

// TestAuthorizePOST_NoCredentialStaysJSON is the other half of the #279 gate. The
// POST caller is not a browser: it is a CLI, or a surface like Studio that
// authenticated the user itself and posts an RFC 7523 assertion. It has parsed
// JSON errors since v1 and there is no user agent in the exchange to redirect, so
// redirecting would break it for no benefit.
func TestAuthorizePOST_NoCredentialStaysJSON(t *testing.T) {
	form, _ := authorizeBaseForm(t)
	form.Del("test_principal_account") // no credential any resolver recognises

	resp := postAuthorize(t, form)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"POST must keep the JSON error body; redirecting it would break CLI and "+
			"assertion-posting callers")
	require.Empty(t, resp.Header.Get("Location"))

	var body map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.Equal(t, "invalid_client", body["error"])
}

// TestAuthorizeGET_UnknownClientStaysJSON pins the §4.1.2.1 exemption. An invalid
// client_id must NOT redirect: we have no validated redirect_uri, so any target
// would be attacker-supplied and the "fix" would be an open redirect.
func TestAuthorizeGET_UnknownClientStaysJSON(t *testing.T) {
	query, _ := authorizeGETQuery(t)
	query.Set("client_id", "no-such-client-9f43b1c2")

	resp := getAuthorize(t, query, principalHeaders())
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	require.Empty(t, resp.Header.Get("Location"),
		"an unknown client_id must never produce a redirect — the redirect_uri is unvalidated")

	var body map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.Equal(t, "invalid_client", body["error"])
}

// TestAuthorizeGET_UnregisteredRedirectURIStaysJSON is the second §4.1.2.1
// exemption, and the more dangerous one: redirecting to a redirect_uri the client
// never registered is precisely the attack the allow-list exists to stop.
func TestAuthorizeGET_UnregisteredRedirectURIStaysJSON(t *testing.T) {
	query, _ := authorizeGETQuery(t)
	query.Set("redirect_uri", "https://evil.example/steal")

	resp := getAuthorize(t, query, principalHeaders())
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Empty(t, resp.Header.Get("Location"),
		"an unregistered redirect_uri must never be redirected to")

	var body map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.Contains(t, body["error_description"], "redirect_uri")
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

// TestAuthorizeGET_ErrorDescriptionIsInCharset pins RFC 6749 §4.1.2.1's NQCHAR
// limit on error_description: %x20-21 / %x23-5B / %x5D-7E, i.e. printable ASCII
// without the double quote or backslash.
//
// It did not matter while every failure was a JSON body — §5.2 puts no charset
// limit there, and UTF-8 reads better. It matters now that the same strings ride
// in a Location query, where a client validating strictly is entitled to reject a
// non-ASCII byte. Percent-encoding makes any byte transport-safe, so this is about
// conformance rather than injection.
//
// Enforced by coercion at the redirect boundary rather than by keeping every
// literal ASCII, since descriptions reaching here include service-layer strings.
func TestAuthorizeGET_ErrorDescriptionIsInCharset(t *testing.T) {
	query, _ := authorizeGETQuery(t)

	resp := getAuthorize(t, query, nil)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusFound, resp.StatusCode)

	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)

	desc := loc.Query().Get("error_description")
	require.NotEmpty(t, desc)

	for i, r := range desc {
		require.True(t, r >= 0x20 && r <= 0x7e && r != '"' && r != '\\',
			"error_description[%d] = %q (U+%04X) is outside RFC 6749 §4.1.2.1 NQCHAR; full value %q",
			i, r, r, desc)
	}
}

// TestAuthorizeGET_NonS256IsRejectedBeforeAnyLookup keeps a request that cannot
// possibly succeed from costing anything.
//
// code_challenge_method=plain used to be caught only inside IssueAuthCode, at the
// very end. With the interactive-login hook in place that meant an unauthenticated
// caller could be sent through the deployer's login surface, authenticate, and
// only then be told their own parameter was wrong. The check costs a string
// comparison, so it belongs in the cheap gate.
func TestAuthorizeGET_NonS256IsRejectedBeforeAnyLookup(t *testing.T) {
	query, _ := authorizeGETQuery(t)
	query.Set("code_challenge_method", "plain")

	// No credential: if the S256 check did not run first, this request would reach
	// principal resolution and be reported as access_denied (or a login redirect)
	// rather than as the invalid_request it is.
	resp := getAuthorize(t, query, nil)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Empty(t, resp.Header.Get("Location"),
		"a request that cannot succeed must not be redirected anywhere, least of all to a login surface")

	var body map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.Equal(t, "invalid_request", body["error"])
	require.Contains(t, body["error_description"], "S256")
}
