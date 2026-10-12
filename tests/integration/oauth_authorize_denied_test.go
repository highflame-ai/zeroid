// A resource owner's explicit denial at /oauth2/authorize.
//
// The shape this serves: a login/consent front end authenticates the user,
// shows a consent screen, and POSTs a signed statement of the outcome to
// /oauth2/authorize server-to-server. On Approve it receives the code redirect
// and hands the Location to the browser. On Deny it needs the RFC 6749
// §4.1.2.1 error redirect to hand over instead — and it cannot build one,
// because only ZeroID has validated client_id and redirect_uri. A resolver
// reports the denial with ErrPrincipalAccessDenied and ZeroID builds it.
//
// The harness stubs: the header stub returns the sentinel when
// X-Test-Access-Denied is present (GET leg); the form stub returns it, wrapped,
// when test_principal_deny=true (POST leg).
package integration_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

// requireAccessDeniedRedirect asserts a 302 to redirectURI carrying the
// §4.1.2.1 error parameters and RFC 9207 iss, and returns its query.
func requireAccessDeniedRedirect(t *testing.T, resp *http.Response, redirectURI, issuer string) url.Values {
	t.Helper()

	require.Equal(t, http.StatusFound, resp.StatusCode)
	require.Equal(t, "no-store", resp.Header.Get("Cache-Control"))

	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)

	want, err := url.Parse(redirectURI)
	require.NoError(t, err)
	require.Equal(t, want.Scheme, loc.Scheme)
	require.Equal(t, want.Host, loc.Host)
	require.Equal(t, want.Path, loc.Path)

	q := loc.Query()
	require.Equal(t, "access_denied", q.Get("error"))
	require.NotEmpty(t, q.Get("error_description"))
	require.NotContains(t, q.Get("error_description"), "stub consent",
		"the resolver's own error text must not reach the client")
	require.Equal(t, []string{issuer}, q["iss"])
	require.Empty(t, q.Get("code"), "a denial must never carry a code")

	return q
}

func TestAuthorizeGET_AccessDeniedRedirects(t *testing.T) {
	query, _ := authorizeGETQuery(t)

	resp := getAuthorize(t, query, map[string]string{"X-Test-Access-Denied": "1"})
	defer func() { _ = resp.Body.Close() }()

	q := requireAccessDeniedRedirect(t, resp, testRedirectURI, testIssuer)
	require.Equal(t, "get-state-abc", q.Get("state"))
}

// POST redirects too — the one POST error that does, because the caller is the
// front end that forwards the Location to the browser.
func TestAuthorizePOST_AccessDeniedRedirects(t *testing.T) {
	form, _ := authorizeBaseForm(t)
	form.Set("test_principal_deny", "true")

	resp := postAuthorize(t, form)
	defer func() { _ = resp.Body.Close() }()

	q := requireAccessDeniedRedirect(t, resp, testRedirectURI, testIssuer)
	require.Equal(t, "test-state-abc", q.Get("state"))
}

func TestAuthorize_AccessDeniedOmitsStateWhenNoneSent(t *testing.T) {
	t.Run("GET", func(t *testing.T) {
		query, _ := authorizeGETQuery(t)
		query.Del("state")

		resp := getAuthorize(t, query, map[string]string{"X-Test-Access-Denied": "1"})
		defer func() { _ = resp.Body.Close() }()

		q := requireAccessDeniedRedirect(t, resp, testRedirectURI, testIssuer)
		_, present := q["state"]
		require.False(t, present, "state must be absent when the request carried none")
	})

	t.Run("POST", func(t *testing.T) {
		form, _ := authorizeBaseForm(t)
		form.Del("state")
		form.Set("test_principal_deny", "true")

		resp := postAuthorize(t, form)
		defer func() { _ = resp.Body.Close() }()

		q := requireAccessDeniedRedirect(t, resp, testRedirectURI, testIssuer)
		_, present := q["state"]
		require.False(t, present, "state must be absent when the request carried none")
	})
}

// The sentinel is only reached after step 3.5, so an unresolved client or an
// unregistered redirect_uri gets the §4.1.2.1-exempt JSON refusal — a resolver's
// denial can never be turned into a redirect to an unvalidated destination.
func TestAuthorize_AccessDeniedNeverRedirectsForUnvalidatedClient(t *testing.T) {
	t.Run("unknown client", func(t *testing.T) {
		form, _ := authorizeBaseForm(t)
		form.Set("client_id", "no-such-client-deny-7c2e")
		form.Set("test_principal_deny", "true")

		resp := postAuthorize(t, form)
		defer func() { _ = resp.Body.Close() }()

		require.NotEqual(t, http.StatusFound, resp.StatusCode)
		require.Empty(t, resp.Header.Get("Location"))
	})

	t.Run("unregistered redirect_uri", func(t *testing.T) {
		query, _ := authorizeGETQuery(t)
		query.Set("redirect_uri", "https://evil.example.test/cb")

		resp := getAuthorize(t, query, map[string]string{"X-Test-Access-Denied": "1"})
		defer func() { _ = resp.Body.Close() }()

		require.NotEqual(t, http.StatusFound, resp.StatusCode)
		require.Empty(t, resp.Header.Get("Location"))
	})
}

// Other resolver errors keep their existing shape: a rejected credential on
// POST is still the 401 invalid_client JSON body.
func TestAuthorizePOST_OtherResolverErrorsUnchanged(t *testing.T) {
	form, _ := authorizeBaseForm(t)
	form.Set("test_principal_reject", "true")

	resp := postAuthorize(t, form)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	require.Empty(t, resp.Header.Get("Location"))

	var body map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.Equal(t, "invalid_client", body["error"])
}

// A self-asserted (CIMD) client with a remote redirect_uri, on a deployment with
// no vetted publishers, is a destination ZeroID declines to redirect to — so the
// denial is reported as JSON, exactly as every other post-3.5 failure is for
// that client. A loopback redirect_uri on the same server is redirected.
func TestAuthorize_AccessDeniedSelfAssertedClient(t *testing.T) {
	const remoteRedirect = "https://app.cimd-deny.example.test/cb"

	base, docClient := newCIMDDocumentOrigin(t, fmt.Sprintf(`{
		"client_id": "%%CLIENT_ID%%",
		"client_name": "deny probe",
		"redirect_uris": [%q, %q],
		"grant_types": ["authorization_code"],
		"token_endpoint_auth_method": "none"
	}`, remoteRedirect, cimdTestRedirectURI))
	srvURL := newCIMDZeroID(t, docClient).URL
	clientID := base + "/.well-known/oauth-client"

	_, challenge := buildPKCEPair(t)
	form := func(redirectURI string) url.Values {
		return url.Values{
			"client_id":             {clientID},
			"redirect_uri":          {redirectURI},
			"response_type":         {"code"},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
			"state":                 {"cimd-deny-state"},
			"test_principal_deny":   {"true"},
		}
	}

	t.Run("remote redirect_uri gets JSON", func(t *testing.T) {
		resp := cimdAuthorize(t, srvURL, form(remoteRedirect))

		require.Equal(t, http.StatusForbidden, resp.StatusCode)
		require.Empty(t, resp.Header.Get("Location"),
			"an unvetted self-asserted destination must not be redirected to")

		var body map[string]string
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		require.Equal(t, "access_denied", body["error"])
	})

	t.Run("loopback redirect_uri is redirected", func(t *testing.T) {
		resp := cimdAuthorize(t, srvURL, form(cimdTestRedirectURI))

		q := requireAccessDeniedRedirect(t, resp, cimdTestRedirectURI, cimdTestIssuer)
		require.Equal(t, "cimd-deny-state", q.Get("state"))
	})
}
