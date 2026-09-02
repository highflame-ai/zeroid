// Interactive authentication at /oauth2/authorize (#276).
//
// A PrincipalResolver returns (*Principal, error) and so cannot redirect — it has
// no ResponseWriter. That left a cookie-based resolver with no way to START a
// login: declining reads as "wrong credential type", failing reads as "bad
// credential", and neither sends the user anywhere.
//
// ErrPrincipalInteractionRequired closes that. The resolver says "this request
// could be satisfied by logging in", and ZeroID performs the redirect on its
// behalf — so the resolver still never touches the transport. The target comes
// from Server.SetInteractiveLoginURL, wired in TestMain.
//
// The harness's header stub returns the sentinel when X-Test-Interaction-Required
// is present, standing in for a session resolver that finds no session.
package integration_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func interactionHeaders() map[string]string {
	return map[string]string{"X-Test-Interaction-Required": "1"}
}

// TestAuthorizeGET_InteractionRequiredRedirectsToLogin is the feature: a 302 to
// the deployer's surface rather than a refusal.
func TestAuthorizeGET_InteractionRequiredRedirectsToLogin(t *testing.T) {
	query, _ := authorizeGETQuery(t)

	resp := getAuthorize(t, query, interactionHeaders())
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusFound, resp.StatusCode)
	require.Equal(t, "no-store", resp.Header.Get("Cache-Control"))

	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "studio.example.test", loc.Host,
		"must redirect to the configured login surface, not the client's redirect_uri")
	require.Equal(t, "/login", loc.Path)

	// Not an error redirect — the flow is pausing, not failing.
	require.Empty(t, loc.Query().Get("error"))
	require.Empty(t, loc.Query().Get("code"))
}

// TestAuthorizeGET_InteractionReturnToResumesTheFlow — the login surface must be
// able to send the user back, so return_to has to be a complete authorize request
// aimed at this issuer.
func TestAuthorizeGET_InteractionReturnToResumesTheFlow(t *testing.T) {
	query, _ := authorizeGETQuery(t)

	resp := getAuthorize(t, query, interactionHeaders())
	defer func() { _ = resp.Body.Close() }()

	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)

	returnTo := loc.Query().Get("return_to")
	require.NotEmpty(t, returnTo, "without return_to the login surface cannot resume the flow")

	rt, err := url.Parse(returnTo)
	require.NoError(t, err)
	require.Equal(t, "/oauth2/authorize", rt.Path)
	require.Equal(t, testCLIClientID, rt.Query().Get("client_id"))
	require.Equal(t, testRedirectURI, rt.Query().Get("redirect_uri"))
	require.Equal(t, "code", rt.Query().Get("response_type"))
	require.Equal(t, "S256", rt.Query().Get("code_challenge_method"))
	require.NotEmpty(t, rt.Query().Get("code_challenge"))
	require.Equal(t, "get-state-abc", rt.Query().Get("state"),
		"state must survive the round trip or the client cannot correlate the result")
}

// TestAuthorizeGET_InteractionReturnToDropsExtraneousParams is a security
// property, not tidiness. return_to is rebuilt from the parameters ZeroID
// validated, never copied from the inbound URL — so a credential a caller put in
// the wrong channel is not forwarded on to the login surface, and into its logs,
// as a side effect of failing to sign in.
func TestAuthorizeGET_InteractionReturnToDropsExtraneousParams(t *testing.T) {
	const leaked = "zid_sk_interactiveleak"

	query, _ := authorizeGETQuery(t)
	query.Set("api_key", leaked)
	query.Set("utm_source", "tracking-junk")

	resp := getAuthorize(t, query, interactionHeaders())
	defer func() { _ = resp.Body.Close() }()

	location := resp.Header.Get("Location")
	require.NotContains(t, location, leaked,
		"the login redirect must not forward a query-string credential")
	require.NotContains(t, location, "tracking-junk",
		"return_to must carry only the validated protocol parameters")
}

// TestAuthorizeGET_InteractionRequiresAValidatedClientFirst pins the ordering that
// makes this safe. The sentinel is only reached AFTER the client and redirect_uri
// are validated at step 3.5, so an unknown client cannot trigger a login redirect
// — it gets the §4.1.2.1-mandated JSON refusal instead. Otherwise an attacker
// could bounce users through our login surface with a client_id we never resolved.
func TestAuthorizeGET_InteractionRequiresAValidatedClientFirst(t *testing.T) {
	query, _ := authorizeGETQuery(t)
	query.Set("client_id", "no-such-client-4a1b9c")

	resp := getAuthorize(t, query, interactionHeaders())
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	require.Empty(t, resp.Header.Get("Location"),
		"an unresolved client must never reach the interactive-login redirect")
}

// TestAuthorizePOST_InteractionIsNotRedirected — a POST has no user agent to send
// anywhere. Its caller is a CLI, or a surface that already authenticated the user
// and is posting an assertion, so it gets the JSON refusal.
func TestAuthorizePOST_InteractionIsNotRedirected(t *testing.T) {
	form, _ := authorizeBaseForm(t)

	req, err := http.NewRequest(http.MethodPost,
		testServer.URL+"/oauth2/authorize", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Test-Interaction-Required", "1")

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Do(req)
	require.NoError(t, err)

	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"POST must get the JSON refusal, not a login redirect")
	require.Empty(t, resp.Header.Get("Location"))
}
