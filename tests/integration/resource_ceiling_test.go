package integration_test

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// End-to-end contract for the consented resource ceiling carried on the
// authorization code (CAP-IDN-027, zeroid#327, ADR 0037).
//
// The ceiling is the `rsc` claim on the auth-code JWT — a signed claim rather
// than a database row, because auth codes are stateless and `auth_codes` is a
// replay-consumption ledger written at redemption, so no code row exists at
// authorization time to persist onto. `scp` (granted scopes) is the precedent.
//
// These drive the real HTTP endpoint against a real database because the thing
// under test is what lands in the signed JWT after a full exchange, which the
// service-level unit tests cannot see.

// buildAuthCodeWithResource mints an auth code carrying a `rsc` ceiling claim
// alongside the usual shape.
//
// Deliberately a separate helper rather than a new parameter on buildAuthCode:
// every existing caller wants a code with NO ceiling, and that case has to keep
// working untouched — an absent ceiling means "the client may still bind at the
// token endpoint", which is the pre-CAP-IDN-027 behaviour CAP-IDN-026 defines
// and which this change must not regress.
func buildAuthCodeWithResource(t *testing.T, clientID, userID, redirectURI, codeChallenge string, scopes, resources []string) string {
	t.Helper()
	now := time.Now()
	tok, err := jwt.NewBuilder().
		Issuer(testIssuer).
		Subject("auth-code").
		IssuedAt(now).
		Expiration(now.Add(5*time.Minute)).
		Claim("cid", clientID).
		Claim("uid", userID).
		Claim("aid", testAccountID).
		Claim("pid", testProjectID).
		Claim("cc", codeChallenge).
		Claim("ruri", redirectURI).
		Claim("scp", scopes).
		// Emitted as an array even though the authorize leg caps the ceiling at
		// one value. Cardinality is a constant, not a shape (ADR 0037 D2), so
		// raising the cap must not change the claim's serialization.
		Claim("rsc", resources).
		Build()
	require.NoError(t, err)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256(), []byte(testHMACSecret)))
	require.NoError(t, err)
	return string(signed)
}

// TestResourceCeiling_AuthorizeEndpointRecordsTheCeiling drives the REAL
// /oauth2/authorize endpoint rather than synthesizing a code, which is what
// zeroid#327 is actually about: the endpoint used to read `resource` and throw
// it away.
//
// The other tests in this file mint their codes with buildAuthCodeWithResource,
// so they prove that a code carrying `rsc` is honoured correctly — but they
// would all still pass if /oauth2/authorize never wrote the claim in the first
// place. This is the test that closes that gap, end to end: consent names one
// resource, the token request names none, and the access token comes back bound.
func TestResourceCeiling_AuthorizeEndpointRecordsTheCeiling(t *testing.T) {
	form, verifier := authorizeBaseForm(t)
	form.Set("resource", mcpGithub)

	resp := postAuthorize(t, form)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusFound, resp.StatusCode,
		"a valid resource must not break the authorize flow")

	u, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	code := u.Query().Get("code")
	require.NotEmpty(t, code)

	// Deliberately NO `resource` on the token request. This is row 3 of the
	// table in zeroid#327 — the one that used to return a 200 with an unbound
	// token and no error anywhere.
	tokenResp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "authorization_code",
		"client_id":     testCLIClientID,
		"code":          code,
		"code_verifier": verifier,
		"redirect_uri":  testRedirectURI,
	}, nil)
	require.Equal(t, http.StatusOK, tokenResp.StatusCode)

	// decodeJWTPayload (raw base64 JSON) rather than decodeJWTUnsafe (jwx):
	// audienceOf normalizes the raw `string`-or-`[]any` shapes, whereas jwx
	// returns a types.StringList for registered claims like `aud`.
	claims := decodeJWTPayload(t, decode(t, tokenResp)["access_token"].(string))
	assert.Equal(t, []string{mcpGithub}, resourceClaimOf(t, claims),
		"the consented resource must reach the token's `resource` claim through the "+
			"authorization code alone — this is the whole of zeroid#327")
	assert.Equal(t, []string{mcpGithub}, audienceOf(t, claims),
		"and `aud` must be narrowed to it, per RFC 8707 §2")
}

// TestResourceCeiling_AuthorizeEndpointRejectsMultipleResources pins the
// cardinality cap at the endpoint that enforces it.
//
// A multi-valued ceiling is what makes a multi-audience access token
// expressible, so the cap is the control, not a convenience. Asserted through
// the real endpoint because the cap only exists on this leg — the token
// endpoint still accepts up to maxResourceIndicators.
func TestResourceCeiling_AuthorizeEndpointRejectsMultipleResources(t *testing.T) {
	form, _ := authorizeBaseForm(t)
	form["resource"] = []string{mcpGithub, mcpSlack}

	resp := postAuthorize(t, form)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"two consented resources must be refused on the authorize leg")
	assert.Equal(t, "invalid_target", decode(t, resp)["error"])
}

// TestResourceCeiling_AuthorizeEndpointRejectsMalformedResource proves the
// §2 syntax rules are applied at authorize and not deferred to redemption.
//
// Deferring would be the worse failure: the client completes a full browser
// consent trip and only then discovers, at the token endpoint, that it holds a
// code it can never exchange.
func TestResourceCeiling_AuthorizeEndpointRejectsMalformedResource(t *testing.T) {
	form, _ := authorizeBaseForm(t)
	form.Set("resource", "/mcp/github") // relative, not an absolute URI

	resp := postAuthorize(t, form)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_target", decode(t, resp)["error"])
}

// TestResourceCeiling_SurvivesTwoRotations is the assertion the whole feature
// rests on.
//
// The ceiling is copied onto the refresh row and then forward onto each
// successor row, field-by-field, in RotateRefreshToken. A test that rotates
// ONCE passes on an implementation that seeds the ceiling at issuance and drops
// it on the next rotation — the exact bug the existing code comments call out
// for mission_id and audience ("would survive the first refresh … but be lost
// on the second rotation"). The second rotation is what proves the copy.
//
// Getting this wrong is not a degraded feature, it is a silently UNBOUND token:
// INV-IDN-006 keys on the presence of the `resource` claim and passes the
// request through to detectors and Cedar unchanged when it is absent. So a
// dropped ceiling yields a token honoured at every MCP server in the tenant,
// with no error anywhere — precisely what zeroid#327 exists to close.
func TestResourceCeiling_SurvivesTwoRotations(t *testing.T) {
	// ── Step 1: redeem a code carrying a ceiling, WITHOUT `resource` on the
	// token request. The access token must still bind, from the code's ceiling.
	verifier, challenge := buildPKCEPair(t)
	code := buildAuthCodeWithResource(t, testMCPClientID, "user-ceiling-rt",
		testRedirectURI, challenge, []string{"data:read"}, []string{mcpGithub})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "authorization_code",
		"client_id":     testMCPClientID,
		"code":          code,
		"code_verifier": verifier,
		"redirect_uri":  testRedirectURI,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	initial := decode(t, resp)

	assert.Equal(t, []string{mcpGithub},
		resourceClaimOf(t, decodeJWTUnsafe(t, initial["access_token"].(string))),
		"a token request that omits `resource` must bind from the code's ceiling — "+
			"otherwise a client that sent `resource` only at /oauth2/authorize gets an unbound token")

	// A resource-bound exchange must now be issued a refresh token. Suppressing
	// it was correct only while the binding could not survive rotation; keeping
	// the suppression is what sent a binding client to a browser every hour and
	// made NOT binding the path of least resistance (CAP-IDN-026, as amended).
	refreshToken, ok := initial["refresh_token"].(string)
	require.True(t, ok, "a resource-bound authorization_code exchange must return a refresh token")
	require.NotEmpty(t, refreshToken)

	// ── Step 2: first rotation, `resource` omitted → re-stamps the ceiling.
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
		"client_id":     testMCPClientID,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	refreshed := decode(t, resp)

	assert.Equal(t, []string{mcpGithub},
		resourceClaimOf(t, decodeJWTUnsafe(t, refreshed["access_token"].(string))),
		"a refresh omitting `resource` must re-stamp the single-valued ceiling")

	refreshToken2, ok := refreshed["refresh_token"].(string)
	require.True(t, ok, "rotation must return the successor refresh token")

	// ── Step 3: second rotation → the ceiling must STILL hold. This is the
	// assertion that distinguishes "copied onto every successor row" from
	// "seeded once at issuance".
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken2,
		"client_id":     testMCPClientID,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	refreshed2 := decode(t, resp)

	assert.Equal(t, []string{mcpGithub},
		resourceClaimOf(t, decodeJWTUnsafe(t, refreshed2["access_token"].(string))),
		"the resource ceiling must survive a SECOND rotation — proves it is copied onto "+
			"the successor row, not just seeded once. Losing it here yields an unbound "+
			"token that INV-IDN-006 honours at every MCP server in the tenant")
}

// TestResourceCeiling_TokenRequestCannotEscapeCeiling pins the direction that
// makes the ceiling meaningful: the client SELECTS from what was consented and
// can never add to it.
//
// Under the single-value cap this degenerates to equality, but it is written
// against the ceiling rather than against a hardcoded single value so it keeps
// its meaning when the cap moves (ADR 0037 D2).
func TestResourceCeiling_TokenRequestCannotEscapeCeiling(t *testing.T) {
	verifier, challenge := buildPKCEPair(t)
	code := buildAuthCodeWithResource(t, testMCPClientID, "user-ceiling-escape",
		testRedirectURI, challenge, []string{"data:read"}, []string{mcpGithub})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "authorization_code",
		"client_id":     testMCPClientID,
		"code":          code,
		"code_verifier": verifier,
		"redirect_uri":  testRedirectURI,
		// Not the consented resource. The human approved github; this asks for slack.
		"resource": mcpSlack,
	}, nil)

	require.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"a token request naming a resource outside the code's ceiling must be rejected")
	body := decode(t, resp)
	assert.Equal(t, "invalid_target", body["error"],
		"RFC 8707 §2 names invalid_target for a resource the AS will not honour")
}

// TestResourceCeiling_AbsentCeilingStillBindsAtToken guards the regression that
// would be easiest to introduce: a client that sends `resource` ONLY at the
// token request (no ceiling on the code) must keep working exactly as it does
// today.
//
// No ceiling is needed to permit this. A resource binding only ever NARROWS —
// it grants no authority the grant did not already carry — so there is nothing
// for a ceiling to protect against here. Rejecting this shape would break every
// existing CAP-IDN-026 caller.
func TestResourceCeiling_AbsentCeilingStillBindsAtToken(t *testing.T) {
	verifier, challenge := buildPKCEPair(t)
	code := buildAuthCode(t, testMCPClientID, "user-no-ceiling",
		testRedirectURI, challenge, []string{"data:read"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "authorization_code",
		"client_id":     testMCPClientID,
		"code":          code,
		"code_verifier": verifier,
		"redirect_uri":  testRedirectURI,
		"resource":      mcpGithub,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	assert.Equal(t, []string{mcpGithub},
		resourceClaimOf(t, decodeJWTUnsafe(t, decode(t, resp)["access_token"].(string))),
		"a code with no ceiling must still allow the token request to bind (CAP-IDN-026)")
}
