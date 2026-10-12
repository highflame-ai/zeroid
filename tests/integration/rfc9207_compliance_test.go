// RFC 9207 (OAuth 2.0 Authorization Server Issuer Identification) compliance
// suite.
//
// See COMPLIANCE.md for the conventions this file follows.
//
// RFC 9207 is a mix-up defense: a client that talks to more than one
// authorization server cannot otherwise tell which one produced the response it
// received at its redirect_uri. The AS adds iss=<its issuer identifier> to every
// authorization response, success and error alike, and says so in its metadata.

package integration_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	zeroid "github.com/highflame-ai/zeroid"
)

// authorizeRedirect parses the Location of a 302 from /oauth2/authorize.
func authorizeRedirect(t *testing.T, resp *http.Response) *url.URL {
	t.Helper()
	require.Equal(t, http.StatusFound, resp.StatusCode, "expected a 302 authorization response")

	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)

	return loc
}

// ── RFC 9207 §2 — Response parameter iss ────────────────────────────────────

func TestRFC9207_S2_SuccessResponseCarriesIss(t *testing.T) {
	// RFC 9207 §2: "Authorization servers supporting this specification MUST
	//   provide their issuer identifier to clients in the authorization
	//   response." — the code response is the first of those.
	query, _ := authorizeGETQuery(t)

	resp := getAuthorize(t, query, principalHeaders())
	defer func() { _ = resp.Body.Close() }()

	loc := authorizeRedirect(t, resp)
	require.NotEmpty(t, loc.Query().Get("code"))
	require.Equal(t, []string{testIssuer}, loc.Query()["iss"],
		"the success response must carry exactly one iss, equal to the issuer identifier")
}

func TestRFC9207_S2_PostSuccessResponseCarriesIss(t *testing.T) {
	// RFC 9207 §2: the requirement attaches to the authorization RESPONSE, not
	//   to the request method — the POST leg emits the same 302 and so carries
	//   iss too.
	form, _ := authorizeBaseForm(t)

	resp := postAuthorize(t, form)
	defer func() { _ = resp.Body.Close() }()

	loc := authorizeRedirect(t, resp)
	require.NotEmpty(t, loc.Query().Get("code"))
	require.Equal(t, testIssuer, loc.Query().Get("iss"))
}

func TestRFC9207_S2_ErrorResponseCarriesIss(t *testing.T) {
	// RFC 9207 §2: "This parameter MUST be included in ... error responses"
	//   as well — an attacker can relay an error as easily as a code, and a
	//   client must be able to check every response it gets.
	query, _ := authorizeGETQuery(t)
	query.Set("state", "rfc9207-error-state")

	resp := getAuthorize(t, query, nil) // no credential → access_denied redirect
	defer func() { _ = resp.Body.Close() }()

	loc := authorizeRedirect(t, resp)
	require.Equal(t, "access_denied", loc.Query().Get("error"))
	require.Equal(t, "rfc9207-error-state", loc.Query().Get("state"))
	require.Equal(t, []string{testIssuer}, loc.Query()["iss"],
		"the error response must carry exactly one iss, equal to the issuer identifier")
}

func TestRFC9207_S2_ParameterValidationErrorCarriesIss(t *testing.T) {
	// RFC 9207 §2 applies to every error redirect, including one raised by
	//   request validation after the client and redirect_uri checked out
	//   (here: a non-S256 PKCE method).
	query, _ := authorizeGETQuery(t)
	query.Set("code_challenge_method", "plain")

	resp := getAuthorize(t, query, principalHeaders())
	defer func() { _ = resp.Body.Close() }()

	loc := authorizeRedirect(t, resp)
	require.NotEmpty(t, loc.Query().Get("error"))
	require.Empty(t, loc.Query().Get("code"))
	require.Equal(t, testIssuer, loc.Query().Get("iss"))
}

func TestRFC9207_S2_IssIsTheExactIssuerIdentifier(t *testing.T) {
	// RFC 9207 §2.4: the client compares iss with the expected issuer
	//   identifier by simple string comparison (RFC 3986 §6.2.1), so the value
	//   must be the issuer verbatim — form-urlencoded on the wire, nothing
	//   appended or normalised (no added trailing slash).
	query, _ := authorizeGETQuery(t)

	resp := getAuthorize(t, query, principalHeaders())
	defer func() { _ = resp.Body.Close() }()

	raw := resp.Header.Get("Location")
	require.Contains(t, raw, "iss="+url.QueryEscape(testIssuer),
		"iss must be the form-urlencoded issuer identifier")

	loc := authorizeRedirect(t, resp)
	require.Equal(t, testIssuer, loc.Query().Get("iss"))
	require.Equal(t, fetchASMetadata(t)["issuer"], loc.Query().Get("iss"),
		"iss must match the issuer the AS metadata publishes — that is what the client compares against")
}

func TestRFC9207_S2_RedirectURIQueryIsPreserved(t *testing.T) {
	// RFC 6749 §3.1.2: the redirection endpoint URI "MAY include an
	//   application/x-www-form-urlencoded formatted ... query component, which
	//   MUST be retained when adding additional query parameters." Adding iss
	//   must not disturb it.
	const clientID = "zeroid-rfc9207-query-client"
	const redirectURI = "http://localhost:9999/callback?tenant=acme&mode=cli"

	require.NoError(t, testZeroIDServer.EnsureClient(context.Background(), zeroid.OAuthClientConfig{
		ClientID:     clientID,
		Name:         clientID,
		GrantTypes:   []string{"authorization_code"},
		RedirectURIs: []string{redirectURI},
	}))

	query, _ := authorizeGETQuery(t)
	query.Set("client_id", clientID)
	query.Set("redirect_uri", redirectURI)

	resp := getAuthorize(t, query, principalHeaders())
	defer func() { _ = resp.Body.Close() }()

	loc := authorizeRedirect(t, resp)
	require.True(t, strings.HasPrefix(loc.String(), "http://localhost:9999/callback?"))
	require.Equal(t, "acme", loc.Query().Get("tenant"))
	require.Equal(t, "cli", loc.Query().Get("mode"))
	require.NotEmpty(t, loc.Query().Get("code"))
	require.Equal(t, testIssuer, loc.Query().Get("iss"))

	// Error path, same client: the registered query survives there too.
	errResp := getAuthorize(t, query, nil)
	defer func() { _ = errResp.Body.Close() }()

	errLoc := authorizeRedirect(t, errResp)
	require.Equal(t, "acme", errLoc.Query().Get("tenant"))
	require.Equal(t, "cli", errLoc.Query().Get("mode"))
	require.Equal(t, "access_denied", errLoc.Query().Get("error"))
	require.Equal(t, testIssuer, errLoc.Query().Get("iss"))
}

// ── RFC 9207 §3 — Authorization server metadata ─────────────────────────────

func TestRFC9207_S3_MetadataAdvertisesIssParameterSupported(t *testing.T) {
	// RFC 9207 §3: "authorization_response_iss_parameter_supported: Boolean
	//   parameter indicating whether the authorization server provides the iss
	//   parameter in the authorization response." Both metadata documents are
	//   checked; the OIDC one is a superset of the RFC 8414 one.
	for _, path := range []string{
		"/.well-known/oauth-authorization-server",
		"/.well-known/openid-configuration",
	} {
		resp := get(t, path, nil)
		require.Equal(t, http.StatusOK, resp.StatusCode, path)

		body := decode(t, resp)
		require.Equal(t, true, body["authorization_response_iss_parameter_supported"],
			"%s must advertise authorization_response_iss_parameter_supported: true", path)
	}
}

func TestRFC9207_S3_FlagRidesTheAuthorizationCodeGate(t *testing.T) {
	// RFC 9207 §3 describes authorization responses. With no servable
	//   authorization_code flow there are none, so the flag is withheld along
	//   with the rest of the flow's metadata rather than promising responses
	//   the AS never sends.
	testZeroIDServer.SetAuthorizationCodeAvailable(func() bool { return false })
	defer testZeroIDServer.SetAuthorizationCodeAvailable(nil)

	require.NotContains(t, fetchASMetadata(t), "authorization_response_iss_parameter_supported")
}
