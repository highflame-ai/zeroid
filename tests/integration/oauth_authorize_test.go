// /oauth2/authorize integration tests — the upstream half of the
// authorization_code grant. Exercises the new endpoint end-to-end:
// register a stub PrincipalResolver (see helpers_test.go TestMain),
// POST form-encoded params, assert 302 with the code in the
// Location query, exchange the code at /oauth2/token, and verify
// the resulting access token carries the resolver-supplied tenant
// context.
//
// The decoder/consumer side at /oauth2/token is covered by
// authorization_code_test.go and pkce_compliance_test.go; this file
// covers the mint + resolve side that those tests previously couldn't
// exercise (no /oauth2/authorize existed).

package integration_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// postAuthorize posts form-encoded values to /oauth2/authorize and
// returns the raw response. Form encoding (not JSON) because the
// /oauth2/authorize handler is a plain chi route that reads
// r.PostForm directly — see internal/handler/authorize.go.
//
// follow=false because the endpoint always 302s on success and we want
// to assert on the Location header.
func postAuthorize(t *testing.T, form url.Values) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(),
		http.MethodPost, testServer.URL+"/oauth2/authorize",
		strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{
		// Don't follow redirects — we assert on the 302.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	require.NoError(t, err)
	return resp
}

// authorizeBaseForm returns the minimum required form values for a
// /oauth2/authorize POST, plus the matching PKCE verifier so tests can
// exchange the resulting code at /oauth2/token. Tests add /override
// fields as needed.
func authorizeBaseForm(t *testing.T) (form url.Values, verifier string) {
	t.Helper()
	verifier, challenge := buildPKCEPair(t)
	form = url.Values{
		"client_id":             {testCLIClientID},
		"redirect_uri":          {testRedirectURI},
		"response_type":         {"code"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {"test-state-abc"},
		// Stub PrincipalResolver — see TestMain in helpers_test.go.
		"test_principal_account": {testAccountID},
		"test_principal_project": {testProjectID},
		"test_principal_user":    {"user-authorize-test"},
	}
	return form, verifier
}

// TestAuthorize_HappyPath is the load-bearing integration test for the
// new endpoint. Walks the full /oauth2/authorize → /oauth2/token flow:
//
//  1. POST /oauth2/authorize with PKCE form + resolver-credential
//     fields → expect 302 with Location: redirect_uri?code=...&state=...
//  2. Extract the code, post it to /oauth2/token with the matching
//     verifier → expect 200 with access_token
//  3. Decode the access token and pin the tenant context the resolver
//     produced (account_id, project_id, sub)
func TestAuthorize_HappyPath(t *testing.T) {
	form, verifier := authorizeBaseForm(t)

	resp := postAuthorize(t, form)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusFound, resp.StatusCode,
		"expected 302 from /oauth2/authorize")

	loc := resp.Header.Get("Location")
	require.NotEmpty(t, loc, "302 must carry Location header")

	u, err := url.Parse(loc)
	require.NoError(t, err)
	require.Equal(t, testRedirectURI,
		(&url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}).String(),
		"Location host+path must match redirect_uri exactly")

	code := u.Query().Get("code")
	state := u.Query().Get("state")
	require.NotEmpty(t, code, "Location must carry ?code=")
	require.Equal(t, "test-state-abc", state,
		"state must round-trip unchanged (RFC 6749 §4.1.1 CSRF chain)")

	// Cache-Control: no-store per RFC 6749 §5.1 — tokens (and codes)
	// must not be cached by intermediaries.
	assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))

	// Step 2: exchange the code at /oauth2/token.
	tokenResp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "authorization_code",
		"client_id":     testCLIClientID,
		"code":          code,
		"code_verifier": verifier,
		"redirect_uri":  testRedirectURI,
	}, nil)
	require.Equal(t, http.StatusOK, tokenResp.StatusCode,
		"code exchange must succeed (the code zeroid just minted must verify against zeroid's own decoder)")

	tok := decode(t, tokenResp)
	accessToken, _ := tok["access_token"].(string)
	require.NotEmpty(t, accessToken)

	// Step 3: introspect to pin the tenant context the resolver
	// supplied flowed through to the access token unchanged.
	intro := introspect(t, accessToken)
	assert.True(t, intro["active"].(bool), "introspection must report active=true")
	assert.Equal(t, testAccountID, intro["account_id"],
		"account_id must match what the PrincipalResolver returned")
	assert.Equal(t, testProjectID, intro["project_id"],
		"project_id must match what the PrincipalResolver returned")
	assert.Equal(t, "user-authorize-test", intro["sub"],
		"sub must match the resolver-supplied UserID")
}

// TestAuthorize_StateOmitted pins the state-handling contract: when
// the caller omits state, the redirect Location must NOT carry a
// state= query param at all (vs. carrying state=""). Some clients
// distinguish missing vs empty when assembling their CSRF chain.
func TestAuthorize_StateOmitted(t *testing.T) {
	form, _ := authorizeBaseForm(t)
	form.Del("state")

	resp := postAuthorize(t, form)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusFound, resp.StatusCode)
	u, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	_, present := u.Query()["state"]
	assert.False(t, present, "Location must not include state= when caller omitted it")
}

// TestAuthorize_MissingRequiredFields walks every required form field
// and pins that omitting it produces a 400 invalid_request response
// with a per-field error_description. Validates the handler-layer
// required-field gate (Step 3 in authorizeHandler), which provides
// actionable feedback before any DB hit.
func TestAuthorize_MissingRequiredFields(t *testing.T) {
	cases := []struct {
		field       string
		wantDescSub string
	}{
		{"client_id", "client_id is required"},
		{"redirect_uri", "redirect_uri is required"},
		{"code_challenge", "code_challenge is required"},
		{"code_challenge_method", "code_challenge_method is required"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.field, func(t *testing.T) {
			form, _ := authorizeBaseForm(t)
			form.Del(tc.field)
			resp := postAuthorize(t, form)
			defer func() { _ = resp.Body.Close() }()
			require.Equal(t, http.StatusBadRequest, resp.StatusCode,
				"missing %s must return 400", tc.field)
			body := decode(t, resp)
			assert.Equal(t, "invalid_request", body["error"])
			desc, _ := body["error_description"].(string)
			assert.Contains(t, desc, tc.wantDescSub,
				"error_description must mention the missing field")
		})
	}
}

// TestAuthorize_NonS256ChallengeMethod pins that plain (deprecated,
// removed in OAuth 2.1) is rejected. Misconfigured CLI clients cannot
// downgrade themselves silently.
func TestAuthorize_NonS256ChallengeMethod(t *testing.T) {
	form, _ := authorizeBaseForm(t)
	form.Set("code_challenge_method", "plain")
	resp := postAuthorize(t, form)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body := decode(t, resp)
	assert.Equal(t, "invalid_request", body["error"])
	desc, _ := body["error_description"].(string)
	assert.Contains(t, desc, "S256")
}

// TestAuthorize_NonCodeResponseType pins that response_type values
// other than "code" are rejected — we only support authorization_code,
// and silently accepting an unknown response_type would set the
// caller's expectations wrong about what flow is in play.
func TestAuthorize_NonCodeResponseType(t *testing.T) {
	form, _ := authorizeBaseForm(t)
	form.Set("response_type", "token")
	resp := postAuthorize(t, form)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body := decode(t, resp)
	assert.Equal(t, "invalid_request", body["error"])
}

// TestAuthorize_UnknownClient pins that an unregistered client_id is
// rejected at the IssueAuthCode-side client lookup (Step 6 in
// authorizeHandler delegates to OAuthService.IssueAuthCode →
// oauthClientSvc.GetPublicClient). 401 invalid_client matches the
// /oauth2/token contract for the same condition.
func TestAuthorize_UnknownClient(t *testing.T) {
	form, _ := authorizeBaseForm(t)
	form.Set("client_id", "nonexistent-client-id")
	resp := postAuthorize(t, form)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	body := decode(t, resp)
	assert.Equal(t, "invalid_client", body["error"])
}

// TestAuthorize_RedirectURIMismatch pins that a redirect_uri not in
// the client's pre-registered list is rejected. This is the gate that
// prevents an attacker who stole a code from redirecting it to their
// own callback.
func TestAuthorize_RedirectURIMismatch(t *testing.T) {
	form, _ := authorizeBaseForm(t)
	form.Set("redirect_uri", "https://attacker.example.com/callback")
	resp := postAuthorize(t, form)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body := decode(t, resp)
	assert.Equal(t, "invalid_request", body["error"])
	desc, _ := body["error_description"].(string)
	assert.Contains(t, desc, "redirect_uri")
}

// TestAuthorize_RedirectURILoopbackEquivalence pins the RFC 8252 §7.3
// loopback equivalence rule: 127.0.0.1 and localhost are interchangeable
// for native-app callbacks. The CLI registers one form; the user might
// hit the other depending on their /etc/hosts.
func TestAuthorize_RedirectURILoopbackEquivalence(t *testing.T) {
	form, _ := authorizeBaseForm(t)
	// testRedirectURI registers "http://localhost:9999/callback"
	// (see helpers_test.go constant); hit the 127.0.0.1 form.
	form.Set("redirect_uri", "http://127.0.0.1:9999/callback")
	resp := postAuthorize(t, form)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusFound, resp.StatusCode,
		"127.0.0.1 form must be accepted when localhost form is registered (RFC 8252 §7.3)")
}

// TestAuthorize_NoPrincipalMatched pins the chain-end behavior: when
// every registered resolver returns ErrPrincipalNotApplicable (in this
// test setup, that means the caller didn't supply
// test_principal_account), the handler returns 401 invalid_client with
// the "no applicable credential" description.
func TestAuthorize_NoPrincipalMatched(t *testing.T) {
	form, _ := authorizeBaseForm(t)
	// Remove the magic field that makes the stub resolver match.
	form.Del("test_principal_account")
	resp := postAuthorize(t, form)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	body := decode(t, resp)
	assert.Equal(t, "invalid_client", body["error"])
	desc, _ := body["error_description"].(string)
	assert.Contains(t, desc, "no applicable credential")
}

// TestAuthorize_ResolverError pins the non-sentinel-error path: when a
// resolver matches the request but rejects the credential (e.g. an
// api_key is present but invalid), the chain stops and the handler
// returns 401 invalid_client. The specific error from the resolver is
// logged but NOT surfaced to the caller (to avoid leaking which
// resolver path matched).
func TestAuthorize_ResolverError(t *testing.T) {
	form, _ := authorizeBaseForm(t)
	form.Set("test_principal_reject", "true")
	resp := postAuthorize(t, form)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	body := decode(t, resp)
	assert.Equal(t, "invalid_client", body["error"])
	desc, _ := body["error_description"].(string)
	assert.Equal(t, "credential rejected", desc,
		"the resolver's specific error must not leak — handler returns a generic description")
}

// TestAuthorize_IssuedCodeShapeMatchesDecoder pins the issuance side
// of the contract more directly than the happy-path test: extract the
// minted JWT and parse it with the same HS256 + issuer args that
// /oauth2/token uses internally (decodeAuthCodeJWT). If issuance ever
// drifts from the decoder's expectations, this test surfaces it before
// the exchange test would.
func TestAuthorize_IssuedCodeShapeMatchesDecoder(t *testing.T) {
	form, _ := authorizeBaseForm(t)
	resp := postAuthorize(t, form)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusFound, resp.StatusCode)

	u, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	code := u.Query().Get("code")
	require.NotEmpty(t, code)

	tok, err := jwt.Parse([]byte(code),
		jwt.WithKey(jwa.HS256(), []byte(testHMACSecret)),
		jwt.WithValidate(true),
	)
	require.NoError(t, err, "minted code must verify under the same HMAC + issuer the decoder uses")

	iss, _ := tok.Issuer()
	sub, _ := tok.Subject()
	jti, _ := tok.JwtID()

	assert.Equal(t, testIssuer, iss, "iss claim must match cfg.Token.Issuer (AuthCodeIssuer defaults to it)")
	assert.Equal(t, "auth-code", sub, "sub must be the auth-code sentinel string")
	assert.NotEmpty(t, jti, "jti must be present — single-use enforcement at exchange depends on it")
}

// TestAuthorize_PKCERoundTrip pins the verifier→challenge round-trip
// works end-to-end: build a verifier, derive the challenge, post to
// /oauth2/authorize, exchange the resulting code with the same
// verifier. This is the integration-level counterpart to the unit
// test mintAuthCodeJWT_RoundTripsThroughDecoder.
func TestAuthorize_PKCERoundTrip(t *testing.T) {
	verifier := strings.Repeat("a", 64) // RFC 7636 allows 43-128
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	form := url.Values{
		"client_id":              {testCLIClientID},
		"redirect_uri":           {testRedirectURI},
		"response_type":          {"code"},
		"code_challenge":         {challenge},
		"code_challenge_method":  {"S256"},
		"test_principal_account": {testAccountID},
		"test_principal_project": {testProjectID},
		"test_principal_user":    {"user-pkce-round-trip"},
	}
	resp := postAuthorize(t, form)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusFound, resp.StatusCode)

	u, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	code := u.Query().Get("code")
	require.NotEmpty(t, code)

	exchangeResp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "authorization_code",
		"client_id":     testCLIClientID,
		"code":          code,
		"code_verifier": verifier,
		"redirect_uri":  testRedirectURI,
	}, nil)
	defer func() { _ = exchangeResp.Body.Close() }()
	require.Equal(t, http.StatusOK, exchangeResp.StatusCode)
}

// TestServerResolveAPIKey pins the public Server.ResolveAPIKey wrapper
// — the surface deployer-supplied PrincipalResolvers (and any other
// out-of-band consumer) use to authenticate an API key without going
// through /oauth2/token. Verifies the narrow APIKeyResolution
// projection carries the tenant + user context that an authorize-time
// resolver needs to build a *zeroid.Principal.
func TestServerResolveAPIKey(t *testing.T) {
	agent := registerAgent(t, uid("resolve-apikey-test-agent"))

	res, err := testZeroIDServer.ResolveAPIKey(context.Background(), agent.APIKey)
	require.NoError(t, err, "ResolveAPIKey must succeed for a freshly-minted api_key")
	require.NotNil(t, res)

	assert.Equal(t, testAccountID, res.AccountID,
		"AccountID must match the tenant the api_key was minted under")
	assert.Equal(t, testProjectID, res.ProjectID,
		"ProjectID must match the tenant the api_key was minted under")
	assert.NotEmpty(t, res.KeyID,
		"KeyID must be populated for audit/log attribution")
	// Scopes / UserID can be empty for a programmatically-registered
	// agent (registerAgent doesn't set them), but the fields must be
	// present and accessible — pin that contract.
	assert.NotNil(t, res.Scopes, "Scopes must be addressable (empty slice or populated, never nil-vs-missing)")
}

// TestServerResolveAPIKey_UnknownKey pins the rejection contract:
// looking up a non-existent api_key returns an error (which zeroid's
// /oauth2/authorize handler maps to 401 invalid_client). The exact
// error shape is a service.OAuthError — already covered by the
// /oauth2/authorize integration tests above; this test just pins the
// public Server.ResolveAPIKey wrapper does NOT swallow the rejection.
func TestServerResolveAPIKey_UnknownKey(t *testing.T) {
	res, err := testZeroIDServer.ResolveAPIKey(context.Background(), "zid_sk_does_not_exist_anywhere_in_db")
	require.Error(t, err, "unknown api_key must return an error")
	require.Nil(t, res, "no resolution on error path")
}
