package integration_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun/dialect/pgdialect"
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

// TestResourceCeiling_AuthorizeGETRecordsTheCeiling covers the same path over
// GET, which is the leg that actually matters in the field.
//
// A browser reaches /oauth2/authorize with a GET, and that is exactly what the
// reference MCP SDK builds — it constructs an authorization URL with `resource`
// in the query string. The handler reads protocol parameters from a DIFFERENT
// source per method (query on GET, body on POST, never a merge of the two), so
// the POST test above does not exercise the code path a real client takes.
func TestResourceCeiling_AuthorizeGETRecordsTheCeiling(t *testing.T) {
	query, verifier := authorizeGETQuery(t)
	query.Set("resource", mcpGithub)

	resp := getAuthorize(t, query, principalHeaders())
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusFound, resp.StatusCode,
		"a valid resource must not break the GET authorize flow")

	u, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	code := u.Query().Get("code")
	require.NotEmpty(t, code)

	tokenResp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "authorization_code",
		"client_id":     testCLIClientID,
		"code":          code,
		"code_verifier": verifier,
		"redirect_uri":  testRedirectURI,
	}, nil)
	require.Equal(t, http.StatusOK, tokenResp.StatusCode)

	claims := decodeJWTPayload(t, decode(t, tokenResp)["access_token"].(string))
	assert.Equal(t, []string{mcpGithub}, resourceClaimOf(t, claims),
		"a resource consented over GET must bind the token just as it does over POST")
}

// TestResourceCeiling_AuthorizePOSTIgnoresQueryResource extends the existing
// parameter-smuggling discipline (TestAuthorizePOST_QueryParamsAreNotRead) to
// `resource`.
//
// The handler reads exactly one source per method. `resource` is read as a
// repeatable parameter — `values["resource"]` rather than `.Get` — so it is the
// one parameter whose plumbing differs from the scalars that test covers, and
// worth pinning separately: a merged view (r.Form) would let a caller put one
// resource in the body and another in the query, with whichever the handler
// happened to read becoming the consented ceiling.
//
// Not an escalation either way — a binding only narrows — but the ceiling is
// what the consent screen will display, so it must come from one place.
func TestResourceCeiling_AuthorizePOSTIgnoresQueryResource(t *testing.T) {
	form, verifier := authorizeBaseForm(t)
	// Body names nothing; the query tries to smuggle a ceiling in.
	req, err := http.NewRequestWithContext(context.Background(),
		http.MethodPost,
		testServer.URL+"/oauth2/authorize?resource="+url.QueryEscape(mcpSlack),
		strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusFound, resp.StatusCode)

	u, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	code := u.Query().Get("code")
	require.NotEmpty(t, code)

	tokenResp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "authorization_code",
		"client_id":     testCLIClientID,
		"code":          code,
		"code_verifier": verifier,
		"redirect_uri":  testRedirectURI,
	}, nil)
	require.Equal(t, http.StatusOK, tokenResp.StatusCode)

	claims := decodeJWTPayload(t, decode(t, tokenResp)["access_token"].(string))
	assert.Nil(t, resourceClaimOf(t, claims),
		"a `resource` present only in the query string of a POST must not become "+
			"the consented ceiling — the body is the single source on POST")
}

// TestResourceCeiling_SurvivesInteractiveLoginRedirect is the regression test
// for the worst bug found in review of this change.
//
// redirectToInteractiveLogin rebuilds return_to from an allow-list of validated
// parameters. `resource` was not on it, while `state` and `scope` were — so the
// consented ceiling was validated on the pre-login pass and then silently
// dropped, and the resumed request minted a code with no `rsc` claim. The
// resulting access token carried no `resource` claim, which Shield treats as
// "not resource-bound" and honours at every MCP server in the tenant.
//
// It was the COMMON path, not an edge: the first browser visit of any flow on a
// deployment with an interactive login surface bounces through here.
func TestResourceCeiling_SurvivesInteractiveLoginRedirect(t *testing.T) {
	query, _ := authorizeGETQuery(t)
	query.Set("resource", mcpGithub)

	resp := getAuthorize(t, query, interactionHeaders())
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusFound, resp.StatusCode)

	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	returnTo := loc.Query().Get("return_to")
	require.NotEmpty(t, returnTo)

	rt, err := url.Parse(returnTo)
	require.NoError(t, err)
	require.Equal(t, mcpGithub, rt.Query().Get("resource"),
		"the consented resource must survive the login round trip — dropping it "+
			"mints an unbound token on the primary browser path, with no error anywhere")
}

// TestResourceCeiling_ResumedAfterLoginStillBinds closes the loop on the test
// above: carrying the parameter is only worth anything if the RESUMED request
// still produces a bound token. Asserting the return_to query alone would pass
// even if the resumed pass mishandled it.
func TestResourceCeiling_ResumedAfterLoginStillBinds(t *testing.T) {
	query, verifier := authorizeGETQuery(t)
	query.Set("resource", mcpGithub)

	resp := getAuthorize(t, query, interactionHeaders())
	defer func() { _ = resp.Body.Close() }()
	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	rt, err := url.Parse(loc.Query().Get("return_to"))
	require.NoError(t, err)

	// Replay return_to's query as the resumed authorize, now with a principal —
	// which is what the login surface does once the human authenticates.
	resumed := getAuthorize(t, rt.Query(), principalHeaders())
	defer func() { _ = resumed.Body.Close() }()
	require.Equal(t, http.StatusFound, resumed.StatusCode)

	cb, err := url.Parse(resumed.Header.Get("Location"))
	require.NoError(t, err)
	code := cb.Query().Get("code")
	require.NotEmpty(t, code, "the resumed authorize must issue a code")

	tokenResp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "authorization_code",
		"client_id":     testCLIClientID,
		"code":          code,
		"code_verifier": verifier,
		"redirect_uri":  testRedirectURI,
	}, nil)
	require.Equal(t, http.StatusOK, tokenResp.StatusCode)

	claims := decodeJWTPayload(t, decode(t, tokenResp)["access_token"].(string))
	assert.Equal(t, []string{mcpGithub}, resourceClaimOf(t, claims),
		"a token issued after an interactive login must still carry the consented binding")
}

// TestResourceCeiling_WrongResourceDoesNotBurnTheCode pins that a rejected
// resource selection is a request-parameter error, not a spent code.
//
// The ceiling check has to run BEFORE single-use consumption, for the reason the
// code states about PKCE: an authorization code must not be burned by a request
// that failed on a value the client can simply correct. When the check sat after
// Consume, naming the wrong resource cost the user the entire browser leg — the
// retry got invalid_grant ("already used") and triggered token revocation.
func TestResourceCeiling_WrongResourceDoesNotBurnTheCode(t *testing.T) {
	verifier, challenge := buildPKCEPair(t)
	code := buildAuthCodeWithResource(t, testMCPClientID, uid("res-noburn"),
		testRedirectURI, challenge, []string{"data:read"}, []string{mcpGithub})

	exchange := func(resource any) *http.Response {
		body := map[string]any{
			"grant_type":    "authorization_code",
			"client_id":     testMCPClientID,
			"code":          code,
			"code_verifier": verifier,
			"redirect_uri":  testRedirectURI,
		}
		if resource != nil {
			body["resource"] = resource
		}
		return post(t, "/oauth2/token", body, nil)
	}

	// First: name a resource outside the ceiling. Rejected.
	bad := exchange(mcpSlack)
	require.Equal(t, http.StatusBadRequest, bad.StatusCode)
	assert.Equal(t, "invalid_target", decode(t, bad)["error"])
	_ = bad.Body.Close()

	// Then: the SAME code, corrected. Must still work.
	good := exchange(mcpGithub)
	require.Equal(t, http.StatusOK, good.StatusCode,
		"a resource that failed the ceiling check must not have consumed the code — "+
			"the client can correct the parameter, and burning the code costs the whole browser leg")

	claims := decodeJWTPayload(t, decode(t, good)["access_token"].(string))
	assert.Equal(t, []string{mcpGithub}, resourceClaimOf(t, claims))
	_ = good.Body.Close()
}

// TestResourceCeiling_MultiResourceBindingGetsNoRefreshToken pins the
// single-valued-ceiling invariant at the one place it could be violated.
//
// The authorize leg caps the ceiling at one, but a token-only binding
// (CAP-IDN-026) passes through the token endpoint's cap of eight. Seeding a
// refresh family from that would make multi-audience tokens durable for the
// family's life AND make re-targeting expressible — the client could alternate
// which value it selects on each rotation. That directly contradicts the
// reasoning used to retire the blanket `resource`-on-refresh rejection.
//
// So this shape gets no refresh token, exactly as it did before CAP-IDN-027.
// The access token is still bound to both resources; only the long-lived half
// is withheld.
func TestResourceCeiling_MultiResourceBindingGetsNoRefreshToken(t *testing.T) {
	verifier, challenge := buildPKCEPair(t)
	// No ceiling on the code — this is the CAP-IDN-026 token-only binding path.
	code := buildAuthCode(t, testMCPClientID, uid("res-multi"),
		testRedirectURI, challenge, []string{"data:read"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "authorization_code",
		"client_id":     testMCPClientID,
		"code":          code,
		"code_verifier": verifier,
		"redirect_uri":  testRedirectURI,
		"resource":      []string{mcpGithub, mcpSlack},
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	token := decode(t, resp)

	assert.Empty(t, token["refresh_token"],
		"a multi-valued binding must not seed a refresh family: a durable multi-audience "+
			"ceiling would make re-targeting expressible across rotations")

	claims := decodeJWTPayload(t, token["access_token"].(string))
	assert.ElementsMatch(t, []string{mcpGithub, mcpSlack}, resourceClaimOf(t, claims),
		"the access token itself is still bound to everything requested")
}

// TestResourceCeiling_AudienceFamilyRefusesResource is the regression test for
// the audience/resource exclusivity hole that adding `refresh_token` to
// resourceSupportedGrants opened.
//
// `audience` and `resource` are mutually exclusive (CAP-IDN-026), but
// checkResourceAudienceExclusive compares two REQUEST parameters. On the refresh
// grant the audience comes from the stored family, so it could not see the
// conflict — and bindResourceOnIssue OVERWRITES issue.Audience, so a
// resource-bound refresh of an audience-profile family replaced the profile
// `aud` that rotation exists to preserve. The harness daemon validates `aud` on
// every message, so the client would have broken its own session, and the token
// would carry the profiled-audience-plus-resource-binding combination that
// CAP-IDN-026 states cannot exist.
//
// Rejected on a non-consuming peek, so a refused request does not burn the
// token — asserted below by rotating successfully afterwards.
func TestResourceCeiling_AudienceFamilyRefusesResource(t *testing.T) {
	trusted := map[string]string{testTrustedServiceHeader: "trusted-service"}

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":          "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token":       "external-principal-assertion",
		"account_id":          testAccountID,
		"project_id":          testProjectID,
		"user_id":             uid("res-aud-excl"),
		"audience":            "codeoid",
		"issue_refresh_token": true,
	}, trusted)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	refresh, ok := decode(t, resp)["refresh_token"].(string)
	require.True(t, ok, "the audience-profile exchange must return a refresh token")
	_ = resp.Body.Close()

	// Rotating this family with `resource` must be refused outright.
	bad := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": refresh,
		"client_id":     "codeoid",
		"resource":      mcpGithub,
	}, nil)
	require.Equal(t, http.StatusBadRequest, bad.StatusCode,
		"an audience-profile family must not be rotatable into a resource-bound token")
	assert.Equal(t, "invalid_request", decode(t, bad)["error"],
		"invalid_request, matching checkResourceAudienceExclusive: the request is "+
			"structurally incoherent rather than naming an unacceptable resource")
	_ = bad.Body.Close()

	// The refusal must not have consumed the token: the same refresh still
	// rotates, and the successor still carries the profile `aud` unchanged.
	good := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": refresh,
		"client_id":     "codeoid",
	}, nil)
	require.Equal(t, http.StatusOK, good.StatusCode,
		"the rejected request must not have burned the refresh token")
	out := decode(t, good)
	claims := decodeJWTPayload(t, out["access_token"].(string))
	assert.Equal(t, []string{"codeoid"}, audienceOf(t, claims),
		"the profile aud must survive rotation untouched")
	assert.Nil(t, resourceClaimOf(t, claims),
		"and the successor must carry no resource binding")
	_ = good.Body.Close()
}

// TestResourceCeiling_EmptyArrayIsRejectedByTheDatabase pins migration 044's
// CHECK constraint at the schema level.
//
// This test exists because the constraint was WRONG when first written, in a way
// only a real database reveals: it used `array_length(resource, 1) >= 1`, and
// array_length returns NULL rather than 0 for an empty array. `NULL >= 1` is
// NULL, the whole conjunction collapsed to NULL, and a CHECK evaluating to NULL
// is treated as SATISFIED — so the constraint permitted '{}', the single case it
// was added for. cardinality() returns 0 and compares normally.
//
// Why '{}' matters: every consumer keys on len(ceiling) == 0, so an empty array
// reads as "no ceiling" and permits binding to anything — the widening
// direction. bun's nullzero collapses only a NIL slice, so an empty non-nil
// slice would write '{}' rather than NULL, and this table's own rollback runbook
// puts an operator here with UPDATE statements.
func TestResourceCeiling_EmptyArrayIsRejectedByTheDatabase(t *testing.T) {
	ctx := context.Background()

	// pgdialect.Array is required for a raw-SQL bind: a bare []string is
	// serialized as JSON and Postgres rejects it as a malformed array literal.
	// The domain model gets this for free from its `array` bun tag.
	insert := func(t *testing.T, resource any) error {
		t.Helper()
		if s, ok := resource.([]string); ok {
			resource = pgdialect.Array(s)
		}
		_, err := testDB.ExecContext(ctx, `
			INSERT INTO refresh_tokens
				(token_hash, client_id, account_id, project_id, user_id, scopes,
				 family_id, state, expires_at, resource)
			VALUES (?, ?, ?, ?, ?, '', gen_random_uuid(), 'active', NOW() + INTERVAL '1 day', ?)`,
			"hash-"+uid("chk"), testMCPClientID, testAccountID, testProjectID,
			uid("chk-user"), resource)
		return err
	}

	t.Run("NULL is permitted — it means no binding", func(t *testing.T) {
		require.NoError(t, insert(t, nil))
	})

	t.Run("a populated ceiling is permitted", func(t *testing.T) {
		require.NoError(t, insert(t, []string{mcpGithub}))
	})

	t.Run("an empty array is refused", func(t *testing.T) {
		err := insert(t, []string{})
		require.Error(t, err,
			"'{}' must be refused by the database: it reads as \"no ceiling\" and so "+
				"widens what the family permits")
		assert.Contains(t, err.Error(), "refresh_tokens_resource_nonempty",
			"the CHECK constraint should be what rejects it")
	})

	t.Run("an empty-string element is refused", func(t *testing.T) {
		err := insert(t, []string{""})
		require.Error(t, err, "a token bound to the empty string is dead everywhere")
	})
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
