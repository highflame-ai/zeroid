package integration_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/url"
	"strings"
	"testing"

	zeroid "github.com/highflame-ai/zeroid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun/dialect/pgdialect"
)

// Regression coverage for the self-mint scope escalation: apiKeyGrant,
// clientCredentials and jwtBearer used to silently narrow an unauthorized
// requested scope down to an empty set and mint anyway. IssueCredential
// omits the `scopes` claim entirely when the granted set is empty
// (credential.go: `if len(req.Scopes) > 0`), and Shield's checkScopeCeiling
// deliberately treats an absent claim as "check not applicable" — a
// backward-compat allowance for tokens minted before the scopes feature
// existed. The two behaviors compose into an escalation: an identity with
// allowed_scopes=["tools:read"] that explicitly asked for "tools:execute"
// got a token Shield would enforce NOTHING against, rather than one it
// would deny call_tool on.
//
// The fix (requireGrantableScope in oauth.go) mirrors tokenExchange's
// existing "empty result -> invalid_scope" safety net, extended to the
// three grants that mint a token for the caller's own use.

// TestAPIKeyGrant_UnauthorizedScopeRequestRejected is the exact repro:
// an identity registered with allowed_scopes=["tools:read"] asks the
// api_key grant for "tools:execute" and must be refused outright, not
// handed a token with no scopes claim at all.
func TestAPIKeyGrant_UnauthorizedScopeRequestRejected(t *testing.T) {
	externalID := uid("apikey-scope-escalation")
	resp := post(t, adminPath("/agents/register"), map[string]any{
		"name":                 externalID,
		"external_id":          externalID,
		"sub_type":             "tool_agent",
		"trust_level":          "first_party",
		"created_by":           "test-user",
		"credential_policy_id": scopedPolicy(t, []string{"tools:read"}, adminHeaders()),
	}, adminHeaders())
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	reg := decode(t, resp)
	apiKey, _ := reg["api_key"].(string)
	require.NotEmpty(t, apiKey)

	tokenResp := post(t, "/oauth2/token", map[string]any{
		"grant_type": "api_key",
		"api_key":    apiKey,
		"scope":      "tools:execute",
	}, nil)
	require.Equal(t, http.StatusBadRequest, tokenResp.StatusCode,
		"requesting a scope outside allowed_scopes must be rejected, not silently minted with no scopes claim")
	body := decode(t, tokenResp)
	assert.Equal(t, "invalid_scope", body["error"])
}

// TestAPIKeyGrant_AuthorizedScopeRequestGranted pins the normal narrowing
// path: requesting a scope that IS in allowed_scopes still mints, and mints
// exactly that scope (not the full ceiling). Unaffected by the fix.
func TestAPIKeyGrant_AuthorizedScopeRequestGranted(t *testing.T) {
	externalID := uid("apikey-scope-ok")
	resp := post(t, adminPath("/agents/register"), map[string]any{
		"name":                 externalID,
		"external_id":          externalID,
		"sub_type":             "tool_agent",
		"trust_level":          "first_party",
		"created_by":           "test-user",
		"credential_policy_id": scopedPolicy(t, []string{"tools:read", "tools:execute"}, adminHeaders()),
	}, adminHeaders())
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	apiKey, _ := decode(t, resp)["api_key"].(string)
	require.NotEmpty(t, apiKey)

	tokenResp := post(t, "/oauth2/token", map[string]any{
		"grant_type": "api_key",
		"api_key":    apiKey,
		"scope":      "tools:read",
	}, nil)
	require.Equal(t, http.StatusOK, tokenResp.StatusCode)
	token := decode(t, tokenResp)
	assert.Equal(t, "tools:read", token["scope"], "scope should be capped at requested value")
}

// TestAPIKeyGrant_NoScopeRequestGetsFullCeiling pins the RFC 6749 §3.3
// default: omitting scope entirely still grants the full ceiling. The fix
// only rejects an EXPLICIT request that resolves to nothing — an absent
// request is untouched.
func TestAPIKeyGrant_NoScopeRequestGetsFullCeiling(t *testing.T) {
	externalID := uid("apikey-scope-default")
	resp := post(t, adminPath("/agents/register"), map[string]any{
		"name":                 externalID,
		"external_id":          externalID,
		"sub_type":             "tool_agent",
		"trust_level":          "first_party",
		"created_by":           "test-user",
		"credential_policy_id": scopedPolicy(t, []string{"tools:read", "tools:execute"}, adminHeaders()),
	}, adminHeaders())
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	apiKey, _ := decode(t, resp)["api_key"].(string)
	require.NotEmpty(t, apiKey)

	tokenResp := post(t, "/oauth2/token", map[string]any{
		"grant_type": "api_key",
		"api_key":    apiKey,
	}, nil)
	require.Equal(t, http.StatusOK, tokenResp.StatusCode)
	token := decode(t, tokenResp)
	scope, _ := token["scope"].(string)
	assert.Contains(t, scope, "tools:read")
	assert.Contains(t, scope, "tools:execute")
}

// TestClientCredentials_UnauthorizedScopeRequestRejected is the
// client_credentials sibling: a client registered with a non-empty but
// narrower scope set (as opposed to TestOAuthAuthzHardening_
// ScopelessClientCannotWiden's zero-scope case, which takes a separate
// explicit-deny branch and never reached intersectScopes) must refuse a
// request for a scope outside that set.
func TestClientCredentials_UnauthorizedScopeRequestRejected(t *testing.T) {
	agentID := uid("cc-scope-escalation")
	registerIdentity(t, agentID, []string{"data:read"})
	client := registerOAuthClient(t, agentID, []string{"data:read"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
		"scope":         "data:write",
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"requesting a scope outside the client's registered scopes must be rejected")
	body := decode(t, resp)
	assert.Equal(t, "invalid_scope", body["error"])
}

// TestJWTBearer_UnauthorizedScopeRequestRejected is the jwt_bearer sibling.
func TestJWTBearer_UnauthorizedScopeRequestRejected(t *testing.T) {
	agentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	agentID := uid("jwtb-scope-escalation")
	identity := registerIdentity(t, agentID, []string{"data:read"}, ecPublicKeyPEM(t, agentKey))
	assertion := buildAssertion(t, agentKey, identity.WIMSEURI)

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
		"assertion":  assertion,
		"scope":      "data:write",
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"jwt_bearer requesting a scope outside allowed_scopes must be rejected")
	body := decode(t, resp)
	assert.Equal(t, "invalid_scope", body["error"])
}

// TestAPIKeyGrant_ChainedCeilingDenialSurvivesReWidening is the exact repro
// for the class of bug the first pass of this fix missed: apiKeyGrant chains
// up to four ceilings (key scopes, key policy, identity policy, legacy
// identity.allowed_scopes). Composing them with plain intersectScopes let a
// real denial at an early step be reinterpreted by the NEXT step as "caller
// asked for nothing" and reset to that step's full (wider) ceiling —
// resurrecting a scope an earlier layer explicitly excluded, and even
// granting scopes that were never requested at all.
//
// Here: the API key's own scopes=["tools:read"] denies tools:execute at the
// first step. The identity's credential policy is wider
// (["tools:read","tools:execute","tools:admin"]). Before the fix, that
// denial reset at the policy step and the token minted with
// tools:execute AND tools:admin — the latter never even asked for.
func TestAPIKeyGrant_ChainedCeilingDenialSurvivesReWidening(t *testing.T) {
	identityPolicyID := createRichCredentialPolicy(t, map[string]any{
		"name":                 uid("chain-id-cp"),
		"allowed_grant_types":  []string{"api_key"},
		"allowed_scopes":       []string{"tools:read", "tools:execute", "tools:admin"},
		"max_delegation_depth": 1,
		"max_ttl_seconds":      3600,
	}, adminHeaders())

	identityID := registerIdentityWithPolicy(t, uid("chain-target"), identityPolicyID, "", nil, adminHeaders())

	headers := adminHeaders()
	headers["X-User-ID"] = "test-user"
	keyResp := post(t, adminPath("/api-keys"), map[string]any{
		"name": "chain-key",
		// Same policy as the identity (a subset of itself, so key creation's
		// own subset-invariant check passes trivially) — the point of this
		// test is the sk.Scopes-vs-policy CHAIN, not the policy check.
		"credential_policy_id": identityPolicyID,
		"identity_id":          identityID,
		"scopes":               []string{"tools:read"}, // the key's OWN, narrower restriction
	}, headers)
	require.Equal(t, http.StatusCreated, keyResp.StatusCode)
	apiKey, _ := decode(t, keyResp)["key"].(string)
	require.NotEmpty(t, apiKey)

	tokenResp := post(t, "/oauth2/token", map[string]any{
		"grant_type": "api_key",
		"api_key":    apiKey,
		"scope":      "tools:execute",
	}, nil)
	require.Equal(t, http.StatusBadRequest, tokenResp.StatusCode,
		"a denial at the key-scopes step must survive the identity-policy step, not be reinterpreted as an omitted request and reset to the policy's full scope set")
	body := decode(t, tokenResp)
	assert.Equal(t, "invalid_scope", body["error"])
}

// TestClientCredentials_IdentityPolicyNarrowsClientScopes covers the Oracle
// review comment on this PR: clientCredentials computed its grant from
// client.Scopes alone, never intersecting the linked identity's credential
// policy at this layer the way apiKeyGrant/jwtBearer do — so a request could
// pass this function's own check and only then get a differently-shaped
// hard rejection deeper inside IssueCredential's EnforcePolicy, for what is
// conceptually the identical failure the other two grants report as
// invalid_scope. The client here is registered wider than the identity's
// policy on purpose.
func TestClientCredentials_IdentityPolicyNarrowsClientScopes(t *testing.T) {
	identityPolicyID := createRichCredentialPolicy(t, map[string]any{
		"name":                 uid("cc-policy-cp"),
		"allowed_grant_types":  []string{"client_credentials"},
		"allowed_scopes":       []string{"tools:read"},
		"max_delegation_depth": 1,
		"max_ttl_seconds":      3600,
	}, adminHeaders())

	clientID := uid("cc-policy-client")
	registerIdentityWithPolicy(t, clientID, identityPolicyID, "", nil, adminHeaders())
	client := registerOAuthClient(t, clientID, []string{"tools:execute", "tools:read"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
		"scope":         "tools:execute",
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"a scope the client is registered for but the linked identity's credential policy excludes must be rejected by this grant, not just by a deeper, differently-shaped chokepoint check")
	body := decode(t, resp)
	assert.Equal(t, "invalid_scope", body["error"])
}

// TestAuthorizationCode_UnauthorizedScopeRequestRejected is the fourth grant
// path the first pass of this fix missed entirely: /oauth2/authorize's
// principal resolver narrows to a real denial, but IssueAuthCode's old
// "empty means no resolver-side narrowing" read reinterpreted that denial as
// an omitted request and substituted the OAuth CLIENT's entire registered
// scope surface — worse than the other three grants' bug, since it doesn't
// just omit the scopes claim, it actively widens to scopes (tools:admin
// here) the caller never asked for and the principal never held.
func TestAuthorizationCode_UnauthorizedScopeRequestRejected(t *testing.T) {
	clientID := uid("authz-code-scope-escalation")
	err := testZeroIDServer.EnsureClient(context.Background(), zeroid.OAuthClientConfig{
		ClientID:     clientID,
		Name:         clientID + "-test-client",
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"tools:read", "tools:execute", "tools:admin"},
		RedirectURIs: []string{testRedirectURI},
	})
	require.NoError(t, err)

	// The request is expected to fail before a code is ever issued, so
	// there is no verifier to redeem it with later.
	_, challenge := buildPKCEPair(t)
	form := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {testRedirectURI},
		"response_type":         {"code"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {"authz-code-scope-escalation-state"},
		"scope":                 {"tools:execute"},
		// Stub PrincipalResolver: the principal itself only holds tools:read,
		// so tools:execute is a real, explicit denial at the resolver layer —
		// not an omission.
		"test_principal_account": {testAccountID},
		"test_principal_project": {testProjectID},
		"test_principal_user":    {"user-authz-code-scope-test"},
		"test_principal_scopes":  {"tools:read"},
	}

	resp := postAuthorize(t, form)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"a scope the principal was denied must refuse the authorization code outright, not substitute the client's entire registered scope surface")
	body := decode(t, resp)
	assert.Equal(t, "invalid_scope", body["error"])
}

// TestAPIKeyGrant_WhitespaceOnlyScopeTreatedAsOmitted pins the fix to
// requireGrantableScope's raw-string-vs-parsed-emptiness mismatch: a
// whitespace-only scope parameter now parses to zero tokens (via
// parseScopeString/strings.Fields) exactly like an omitted one, everywhere
// that decision is made, so it can no longer produce a false rejection for
// an identity with no scope ceiling configured.
func TestAPIKeyGrant_WhitespaceOnlyScopeTreatedAsOmitted(t *testing.T) {
	externalID := uid("apikey-scope-whitespace")
	resp := post(t, adminPath("/agents/register"), map[string]any{
		"name":        externalID,
		"external_id": externalID,
		"sub_type":    "tool_agent",
		"trust_level": "first_party",
		"created_by":  "test-user",
		// No allowed_scopes: this identity has no scope ceiling of its own.
	}, adminHeaders())
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	apiKey, _ := decode(t, resp)["api_key"].(string)
	require.NotEmpty(t, apiKey)

	tokenResp := post(t, "/oauth2/token", map[string]any{
		"grant_type": "api_key",
		"api_key":    apiKey,
		"scope":      " ",
	}, nil)
	require.Equal(t, http.StatusOK, tokenResp.StatusCode,
		"a whitespace-only scope must be treated the same as an omitted one, not falsely rejected")
}

// TestClientCredentials_OmittedScopeNarrowedToEmptyRejected covers the gap
// requireGrantableScope leaves open on this grant: it permits an empty grant
// whenever the caller named no scope, but on client_credentials an empty set
// has a second meaning — the client's registered scopes and the identity
// policy's ceiling are disjoint, i.e. a denial. There is no identity or
// delegation fallback here, so nothing is grantable either way, and minting
// would hand back a token with NO scopes claim: exactly the
// "Shield enforces nothing" escalation this file exists to close, reached
// via the omitted-scope path instead of the explicit-request one.
func TestClientCredentials_OmittedScopeNarrowedToEmptyRejected(t *testing.T) {
	identityPolicyID := createRichCredentialPolicy(t, map[string]any{
		"name":                 uid("cc-disjoint-cp"),
		"allowed_grant_types":  []string{"client_credentials"},
		"allowed_scopes":       []string{"tools:read"},
		"max_delegation_depth": 1,
		"max_ttl_seconds":      3600,
	}, adminHeaders())

	clientID := uid("cc-disjoint-client")
	registerIdentityWithPolicy(t, clientID, identityPolicyID, "", nil, adminHeaders())
	// Registered scopes share nothing with the policy ceiling above.
	client := registerOAuthClient(t, clientID, []string{"data:read"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
		// scope deliberately omitted — the narrowing still resolves to nothing.
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"a client whose registered scopes are disjoint from the identity policy's ceiling must be refused, not handed a token with no scopes claim")
	body := decode(t, resp)
	assert.Equal(t, "invalid_scope", body["error"])
}

// TestAuthorize_WhitespaceOnlyScopeDoesNotWiden pins the handler side of the
// same raw-string-vs-parsed-emptiness mismatch as
// TestAPIKeyGrant_WhitespaceOnlyScopeTreatedAsOmitted. /oauth2/authorize used
// to branch on `req.Scope != ""` while IssueAuthCode and requireGrantableScope
// both branch on the PARSED scope, so `scope=" "` narrowed the principal away
// to an empty set here and then read as an omitted request one layer down —
// substituting the client's entire registered surface. The result was strictly
// wider than sending no scope at all.
func TestAuthorize_WhitespaceOnlyScopeDoesNotWiden(t *testing.T) {
	clientID := uid("authz-code-scope-whitespace")
	err := testZeroIDServer.EnsureClient(context.Background(), zeroid.OAuthClientConfig{
		ClientID:     clientID,
		Name:         clientID + "-test-client",
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"tools:read", "tools:admin"},
		RedirectURIs: []string{testRedirectURI},
	})
	require.NoError(t, err)

	verifier, challenge := buildPKCEPair(t)
	form := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {testRedirectURI},
		"response_type":         {"code"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {"authz-code-scope-whitespace-state"},
		"scope":                 {" "},
		// The principal holds tools:read only; tools:admin is the client's
		// registered scope that must never leak into the grant.
		"test_principal_account": {testAccountID},
		"test_principal_project": {testProjectID},
		"test_principal_user":    {"user-authz-code-whitespace-test"},
		"test_principal_scopes":  {"tools:read"},
	}

	resp := postAuthorize(t, form)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusFound, resp.StatusCode,
		"a whitespace-only scope must be treated as omitted, not as a request that narrows to nothing")
	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	code := loc.Query().Get("code")
	require.NotEmpty(t, code)

	tokenResp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "authorization_code",
		"client_id":     clientID,
		"code":          code,
		"code_verifier": verifier,
		"redirect_uri":  testRedirectURI,
	}, nil)
	require.Equal(t, http.StatusOK, tokenResp.StatusCode)
	scope, _ := decode(t, tokenResp)["scope"].(string)
	assert.Equal(t, "tools:read", scope,
		"the grant must stay at the principal's scopes; tools:admin is the client's registered scope and was never held or requested")
}

// The credential policy is the only scope ceiling. The identity row's
// deprecated allowed_scopes is refused on every write path and ignored if a
// pre-047 value is still stored, so it can never narrow, widen, or seed a
// grant.

// TestIdentityAllowedScopes_Refused: every path that writes an identity
// refuses a non-empty allowed_scopes with a 400 naming the replacement, so a
// caller cannot believe an identity is narrowed when it is not. An empty
// value is accepted: SDKs that send the field unset must keep working.
func TestIdentityAllowedScopes_Refused(t *testing.T) {
	assertRefused := func(t *testing.T, resp *http.Response) {
		t.Helper()
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		body := decode(t, resp)
		_ = resp.Body.Close()
		assert.Contains(t, body["detail"], "credential_policy_id", "the error names what to use instead")
	}

	t.Run("POST /identities", func(t *testing.T) {
		assertRefused(t, post(t, adminPath("/identities"), map[string]any{
			"external_id": uid("row-refused"), "owner_user_id": "user-test-owner",
			"allowed_scopes": []string{"tools:read"},
		}, adminHeaders()))
	})

	t.Run("POST /agents/register", func(t *testing.T) {
		ext := uid("row-refused-agent")
		assertRefused(t, post(t, adminPath("/agents/register"), map[string]any{
			"name": ext, "external_id": ext, "created_by": "test-user",
			"allowed_scopes": []string{"tools:read"},
		}, adminHeaders()))
	})

	t.Run("PATCH /identities/{id}", func(t *testing.T) {
		id := registerIdentity(t, uid("row-refused-update"), nil).ID
		assertRefused(t, doRequest(t, http.MethodPatch, adminPath("/identities/"+id), map[string]any{
			"allowed_scopes": []string{"tools:read"},
		}, adminHeaders()))
	})

	t.Run("an empty value is accepted", func(t *testing.T) {
		resp := post(t, adminPath("/identities"), map[string]any{
			"external_id": uid("row-empty"), "owner_user_id": "user-test-owner",
			"allowed_scopes": []string{},
		}, adminHeaders())
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		body := decode(t, resp)
		_ = resp.Body.Close()
		assert.Empty(t, body["allowed_scopes"])
	})
}

// setStoredRowScopes writes allowed_scopes straight into the identity row, the
// way a release before 047 left it, since the API no longer accepts it.
func setStoredRowScopes(t *testing.T, identityID string, scopes []string) {
	t.Helper()
	_, err := testDB.NewUpdate().Table("identities").
		Set("allowed_scopes = ?", pgdialect.Array(scopes)).
		Where("id = ?", identityID).
		Exec(context.Background())
	require.NoError(t, err)
}

// TestAPIKeyGrant_StoredRowScopesAreIgnored: a stored row narrower than the
// identity's policy neither narrows an omitted-scope grant nor refuses an
// explicit one. Before, the row seeded the default and IssueCredential refused
// any scope outside it.
func TestAPIKeyGrant_StoredRowScopesAreIgnored(t *testing.T) {
	externalID := uid("apikey-row-ignored")
	resp := post(t, adminPath("/agents/register"), map[string]any{
		"name":                 externalID,
		"external_id":          externalID,
		"sub_type":             "code_agent",
		"created_by":           "test-user",
		"credential_policy_id": scopedPolicy(t, []string{"tools:read", "tools:execute"}, adminHeaders()),
	}, adminHeaders())
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	reg := decode(t, resp)
	apiKey, _ := reg["api_key"].(string)
	require.NotEmpty(t, apiKey)
	setStoredRowScopes(t, reg["identity"].(map[string]any)["id"].(string), []string{"tools:read"})

	tokenResp := post(t, "/oauth2/token", map[string]any{"grant_type": "api_key", "api_key": apiKey}, nil)
	require.Equal(t, http.StatusOK, tokenResp.StatusCode)
	scope, _ := decode(t, tokenResp)["scope"].(string)
	assert.ElementsMatch(t, []string{"tools:read", "tools:execute"}, strings.Fields(scope),
		"an omitted request gets the policy's scopes; the stored row narrows nothing")

	tokenResp = post(t, "/oauth2/token", map[string]any{"grant_type": "api_key", "api_key": apiKey, "scope": "tools:execute"}, nil)
	require.Equal(t, http.StatusOK, tokenResp.StatusCode, "a scope the policy permits is granted whatever the row says")
	assert.Equal(t, "tools:execute", decode(t, tokenResp)["scope"])
}

// TestClientCredentials_StoredRowScopesAreIgnored is the client_credentials
// sibling, which also exercises IssueCredential's former row subset check.
func TestClientCredentials_StoredRowScopesAreIgnored(t *testing.T) {
	agentID := uid("cc-row-ignored")
	id := registerIdentity(t, agentID, []string{"data:read", "data:write"}).ID
	setStoredRowScopes(t, id, []string{"data:read"})
	client := registerOAuthClient(t, agentID, []string{"data:read", "data:write"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
		"scope":         "data:write",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "data:write", decode(t, resp)["scope"])
}

// TestTokenExchange_StoredActorRowScopesAreIgnored: the actor's ceiling is its
// credential policy alone. A stored row on the actor no longer drops a scope
// the policy permits from the delegation.
func TestTokenExchange_StoredActorRowScopesAreIgnored(t *testing.T) {
	orchID := uid("tx-row-orch")
	registerIdentity(t, orchID, []string{"data:read", "data:write"})
	orchClient := registerOAuthClient(t, orchID, []string{"data:read", "data:write"})
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     orchClient.ClientID,
		"client_secret": orchClient.ClientSecret,
		"scope":         "data:read data:write",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	orchToken := decode(t, resp)["access_token"].(string)

	actorKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	actorExternalID := uid("tx-row-actor")
	actorID := registerIdentityWithPolicy(t, actorExternalID, "",
		ecPublicKeyPEM(t, actorKey), []string{"data:read", "data:write"}, adminHeaders())
	setStoredRowScopes(t, actorID, []string{"data:read"})
	actorURI := fetchIdentityWIMSEByExternalID(t, actorExternalID)

	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": orchToken,
		"actor_token":   buildAssertion(t, actorKey, actorURI),
		"scope":         "data:read data:write",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.ElementsMatch(t, []string{"data:read", "data:write"}, strings.Fields(decode(t, resp)["scope"].(string)))
}
