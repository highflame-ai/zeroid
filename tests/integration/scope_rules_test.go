package integration_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	zeroid "github.com/highflame-ai/zeroid"
	"github.com/highflame-ai/zeroid/internal/telemetry"
)

// The stricter scope rules, counted in shadow mode (docs/scope-ceilings.md,
// "Stricter scope rules"). Every test here runs one request with the mode off
// and the same request in shadow, and checks that the two answers are the
// same while shadow records what the rules would change. No test calls
// t.Parallel(), so swapping the shared server's mode, counter and logger is
// safe.

const scopeRuleMsg = "scope_rule_would_change"

// scopeRuleCapture collects the shadow count's records for one test.
type scopeRuleCapture struct {
	reader *sdkmetric.ManualReader
	logs   *serverLog
}

// captureScopeRules swaps the scope-rules counter and the server log for
// capturing ones until the test ends.
func captureScopeRules(t *testing.T) *scopeRuleCapture {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	counter, err := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).
		Meter("test").Int64Counter("zeroid.scope.rule_would_change")
	require.NoError(t, err)
	orig := telemetry.ScopeRuleWouldChange
	telemetry.ScopeRuleWouldChange = counter
	t.Cleanup(func() { telemetry.ScopeRuleWouldChange = orig })
	return &scopeRuleCapture{reader: reader, logs: captureServerLog(t)}
}

// lines returns the scope_rule_would_change log lines.
func (c *scopeRuleCapture) lines(t *testing.T) []map[string]any {
	t.Helper()
	return c.logs.find(t, scopeRuleMsg, nil)
}

// counts returns the counter's total per "rule/grant_type".
func (c *scopeRuleCapture) counts(t *testing.T) map[string]int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	require.NoError(t, c.reader.Collect(context.Background(), &rm))
	out := map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				continue
			}
			for _, dp := range sum.DataPoints {
				rule, _ := dp.Attributes.Value("rule")
				grant, _ := dp.Attributes.Value("grant_type")
				out[rule.AsString()+"/"+grant.AsString()] += dp.Value
			}
		}
	}
	return out
}

// setScopeRules sets the shared server's mode, and turns it off when the test
// ends.
func setScopeRules(t *testing.T, mode zeroid.ScopeRulesMode) {
	t.Helper()
	require.NoError(t, testZeroIDServer.SetScopeRulesMode(mode))
	t.Cleanup(func() {
		require.NoError(t, testZeroIDServer.SetScopeRulesMode(zeroid.ScopeRulesModeOff))
	})
}

// joseHeader decodes a compact JWS's protected header.
func joseHeader(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	var hdr map[string]any
	require.NoError(t, json.Unmarshal(raw, &hdr))
	return hdr
}

// perMintClaims differ on every token whatever the mode.
var perMintClaims = []string{"jti", "iat", "exp", "nbf", "mission_id"}

// tokenOutcome reduces a /oauth2/token response to everything the mode must
// not change: the status, every body member, and the access token's header
// and claims, less what differs on every mint (perMintClaims, the response's
// own jti and iat, and the refresh token's value, whose presence is kept).
func tokenOutcome(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	out := map[string]any{"status": resp.StatusCode}
	for k, v := range decode(t, resp) {
		switch k {
		case "jti", "iat":
		case "refresh_token":
			out[k] = v != ""
		case "access_token":
			token, _ := v.(string)
			claims := decodeJWTPayload(t, token)
			for _, c := range perMintClaims {
				delete(claims, c)
			}
			out["access_token.header"] = joseHeader(t, token)
			out["access_token.claims"] = claims
		default:
			out[k] = v
		}
	}
	return out
}

// offThenShadow runs the same request with the mode off and in shadow, checks
// the two outcomes are identical, and returns the shadow run's records.
// request must make one equivalent request each time it is called.
func offThenShadow(t *testing.T, request func(t *testing.T) *http.Response) (map[string]any, *scopeRuleCapture) {
	t.Helper()
	off := tokenOutcome(t, request(t))

	setScopeRules(t, zeroid.ScopeRulesModeShadow)
	records := captureScopeRules(t)
	shadow := tokenOutcome(t, request(t))

	assert.Equal(t, off, shadow, "shadow must answer exactly as off does")
	return shadow, records
}

// scopeRuleLine returns the single record logged, failing unless there is
// exactly one.
func scopeRuleLine(t *testing.T, records *scopeRuleCapture) map[string]any {
	t.Helper()
	lines := records.lines(t)
	require.Len(t, lines, 1, "exactly one rule change recorded, got %v", lines)
	return lines[0]
}

// TestScopeRulesShadow_OmittedRequest (rule A): a request that names no scope
// would be issued none, where today it gets the client's registered scopes.
func TestScopeRulesShadow_OmittedRequest(t *testing.T) {
	t.Run("client_credentials gets the client's scopes", func(t *testing.T) {
		tn := newTenant(t, "")
		extID := uid("sr-a-cc")
		tn.register(t, extID, tn.policy(t, nil), "", nil)
		client := registerOAuthClient(t, extID, []string{"sr:read", "sr:write"})
		request := func(t *testing.T) *http.Response {
			return post(t, "/oauth2/token", map[string]any{
				"grant_type":    "client_credentials",
				"account_id":    tn.account,
				"project_id":    tn.project,
				"client_id":     client.ClientID,
				"client_secret": client.ClientSecret,
			}, nil)
		}

		outcome, records := offThenShadow(t, request)
		require.Equal(t, http.StatusOK, outcome["status"])
		assert.Equal(t, "sr:read sr:write", outcome["scope"], "precondition: today an omitted scope gets the client's list")

		line := scopeRuleLine(t, records)
		assert.Equal(t, "omitted_request", line["rule"])
		assert.Equal(t, "client_credentials", line["grant_type"])
		assert.Equal(t, client.ClientID, line["client_id"])
		assert.NotEmpty(t, line["identity_id"])
		assert.Equal(t, tn.account, line["account_id"])
		assert.Equal(t, tn.project, line["project_id"])
		assert.Equal(t, []any{}, line["requested_scopes"])
		assert.Equal(t, "issued", line["today"])
		assert.Equal(t, []any{"sr:read", "sr:write"}, line["today_scopes"])
		assert.Equal(t, "issued", line["would"])
		assert.Equal(t, []any{}, line["would_scopes"])
		assert.Equal(t, map[string]int64{"omitted_request/client_credentials": 1}, records.counts(t))
	})

	t.Run("an authorization request gets the client's scopes in its code", func(t *testing.T) {
		clientID := uid("sr-a-code")
		resp := post(t, adminPath("/oauth/clients"), map[string]any{
			"client_id":     clientID,
			"name":          clientID,
			"confidential":  false,
			"grant_types":   []string{"authorization_code"},
			"redirect_uris": []string{testRedirectURI},
			"scopes":        []string{"sr:read", "sr:write"},
		}, nil)
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		_ = resp.Body.Close()

		// authorize posts an authorization request naming no scope and returns
		// what the mode must not change about the answer: the status, where it
		// redirects, and the code's claims less its per-mint ones and the
		// request's own PKCE challenge.
		authorize := func() (map[string]any, string, string) {
			form, verifier := authorizeBaseForm(t)
			form.Set("client_id", clientID)
			resp := postAuthorize(t, form)
			defer func() { _ = resp.Body.Close() }()
			require.Equal(t, http.StatusFound, resp.StatusCode)
			loc, err := url.Parse(resp.Header.Get("Location"))
			require.NoError(t, err)
			code := loc.Query().Get("code")
			claims := decodeJWTPayload(t, code)
			for _, c := range append([]string{"cc"}, perMintClaims...) {
				delete(claims, c)
			}
			return map[string]any{
				"status":   resp.StatusCode,
				"redirect": loc.Scheme + "://" + loc.Host + loc.Path,
				"state":    loc.Query().Get("state"),
				"code":     claims,
			}, code, verifier
		}

		off, _, _ := authorize()
		setScopeRules(t, zeroid.ScopeRulesModeShadow)
		records := captureScopeRules(t)
		shadow, code, verifier := authorize()
		assert.Equal(t, off, shadow, "shadow must answer the authorization request exactly as off does")
		assert.Equal(t, []any{"sr:read", "sr:write"}, shadow["code"].(map[string]any)["scp"], "precondition: today the code carries the client's list")

		line := scopeRuleLine(t, records)
		assert.Equal(t, "omitted_request", line["rule"])
		assert.Equal(t, "authorization_code", line["grant_type"])
		assert.Equal(t, clientID, line["client_id"])
		assert.Equal(t, testAccountID, line["account_id"])
		assert.Equal(t, []any{"sr:read", "sr:write"}, line["today_scopes"])
		assert.Equal(t, []any{}, line["would_scopes"])

		// Redeeming the code changes nothing more: the client was registered
		// through the admin API, so its scopes are a listing.
		tokenResp := post(t, "/oauth2/token", map[string]any{
			"grant_type":    "authorization_code",
			"client_id":     clientID,
			"code":          code,
			"code_verifier": verifier,
			"redirect_uri":  testRedirectURI,
		}, nil)
		require.Equal(t, http.StatusOK, tokenResp.StatusCode)
		_ = tokenResp.Body.Close()
		assert.Len(t, records.lines(t), 1, "the redemption records nothing of its own")
		assert.Equal(t, map[string]int64{"omitted_request/authorization_code": 1}, records.counts(t))
	})
}

// TestScopeRulesShadow_Listing (rule B): a scope is issued only when a ceiling
// the deployer controls lists it. Today an empty ceiling places no
// restriction, so an unlisted scope is granted.
func TestScopeRulesShadow_Listing(t *testing.T) {
	t.Run("api_key with no ceiling anywhere", func(t *testing.T) {
		tn := newTenant(t, "")
		reg := registerAgentInTenant(t, uid("sr-b-ak"), tn.headers)
		request := func(t *testing.T) *http.Response {
			return post(t, "/oauth2/token", map[string]any{
				"grant_type": "api_key",
				"api_key":    reg.APIKey,
				"scope":      "sr:manage",
			}, nil)
		}

		outcome, records := offThenShadow(t, request)
		require.Equal(t, http.StatusOK, outcome["status"])
		assert.Equal(t, "sr:manage", outcome["scope"], "precondition: today an unlisted scope is granted")

		line := scopeRuleLine(t, records)
		assert.Equal(t, "listing", line["rule"])
		assert.Equal(t, "api_key", line["grant_type"])
		assert.Equal(t, reg.AgentID, line["identity_id"])
		assert.Equal(t, "", line["client_id"], "an API key is not an OAuth client")
		assert.Equal(t, tn.account, line["account_id"])
		assert.Equal(t, []any{"sr:manage"}, line["requested_scopes"])
		assert.Equal(t, []any{"sr:manage"}, line["today_scopes"])
		assert.Equal(t, []any{"sr:manage"}, line["unlisted_scopes"])
		assert.Equal(t, "refused", line["would"])
		assert.Equal(t, "invalid_scope", line["would_code"])
		assert.Equal(t, map[string]int64{"listing/api_key": 1}, records.counts(t))
	})

	t.Run("authorization_code for a client that registered no scopes", func(t *testing.T) {
		user := uid("sr-b-user")
		request := func(t *testing.T) *http.Response {
			verifier, challenge := buildPKCEPair(t)
			return post(t, "/oauth2/token", map[string]any{
				"grant_type":    "authorization_code",
				"client_id":     testCLIClientID,
				"code":          buildAuthCode(t, testCLIClientID, user, testRedirectURI, challenge, []string{"sr:read"}),
				"code_verifier": verifier,
				"redirect_uri":  testRedirectURI,
			}, nil)
		}

		outcome, records := offThenShadow(t, request)
		require.Equal(t, http.StatusOK, outcome["status"])

		line := scopeRuleLine(t, records)
		assert.Equal(t, "listing", line["rule"])
		assert.Equal(t, "authorization_code", line["grant_type"])
		assert.Equal(t, testCLIClientID, line["client_id"])
		assert.Equal(t, "", line["identity_id"], "the client links no identity")
		assert.Equal(t, []any{"sr:read"}, line["unlisted_scopes"])
		assert.Equal(t, "refused", line["would"])
	})
}

// TestScopeRulesShadow_AllOrNothing (rule C): a request that is narrowed today
// would be refused whole, and a delegation that names no scope, refused
// today, would be issued none.
func TestScopeRulesShadow_AllOrNothing(t *testing.T) {
	tn := newTenant(t, "")
	scopes := []string{"sr:a", "sr:b", "sr:c"}
	parent, _ := tn.workloadRoot(t, tn.policy(t, scopes), []string{"sr:a", "sr:b"})
	// The actor's policy caps its tokens below the parent's remaining
	// lifetime, so the delegated token's lifetime is the same in both runs
	// rather than clamped to the parent's expiry.
	actorPolicy := tn.policyWith(t, scopes, map[string]any{"max_ttl_seconds": 600})
	key := generateKey(t)
	actor := tn.register(t, uid("sr-c-actor"), actorPolicy, ecPublicKeyPEM(t, key), scopes)
	exchange := func(scope string) func(t *testing.T) *http.Response {
		return func(t *testing.T) *http.Response {
			body := map[string]any{
				"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
				"subject_token": parent,
				"actor_token":   buildAssertion(t, key, actor),
			}
			if scope != "" {
				body["scope"] = scope
			}
			return post(t, "/oauth2/token", body, nil)
		}
	}

	t.Run("a narrowed delegation is refused whole", func(t *testing.T) {
		outcome, records := offThenShadow(t, exchange("sr:a sr:b sr:c"))
		require.Equal(t, http.StatusOK, outcome["status"])
		assert.Equal(t, "sr:a sr:b", outcome["scope"], "precondition: today the scope the parent lacks is dropped")

		line := scopeRuleLine(t, records)
		assert.Equal(t, "all_or_nothing", line["rule"])
		assert.Equal(t, "token_exchange", line["grant_type"])
		assert.NotEmpty(t, line["identity_id"])
		assert.NotEmpty(t, line["client_id"], "the actor is the client a delegated token is issued to")
		assert.Equal(t, []any{"sr:a", "sr:b", "sr:c"}, line["requested_scopes"])
		assert.Equal(t, []any{"sr:a", "sr:b"}, line["today_scopes"])
		assert.Equal(t, "refused", line["would"])
		assert.Equal(t, "invalid_scope", line["would_code"])
		assert.Equal(t, map[string]int64{"all_or_nothing/token_exchange": 1}, records.counts(t))
	})

	t.Run("a delegation that names no scope is issued none", func(t *testing.T) {
		outcome, records := offThenShadow(t, exchange(""))
		require.Equal(t, http.StatusBadRequest, outcome["status"])
		assert.Equal(t, "invalid_scope", outcome["error"], "precondition: today it is refused")

		line := scopeRuleLine(t, records)
		assert.Equal(t, "all_or_nothing", line["rule"])
		assert.Equal(t, "token_exchange", line["grant_type"])
		assert.Equal(t, "refused", line["today"])
		assert.Equal(t, "invalid_scope", line["today_code"])
		assert.Equal(t, "issued", line["would"])
		assert.Equal(t, []any{}, line["would_scopes"])
	})
}

// TestScopeRulesShadow_OneCode (rule D): every scope refusal would answer
// invalid_scope. Today a scope outside the governing policy is refused with
// policy_violation.
func TestScopeRulesShadow_OneCode(t *testing.T) {
	tn := newTenant(t, "")
	policyID := tn.policy(t, []string{"sr:read"})
	identityID := registerIdentityWithPolicy(t, uid("sr-d-app"), policyID, "", nil, tn.headers)
	user := uid("sr-d-user")
	// The exchange verifies its subject_token: a token this server issued for
	// the tenant and person the request names.
	subject := personToken(t, tn.account, tn.project, user)
	request := func(t *testing.T) *http.Response {
		return post(t, "/oauth2/token", map[string]any{
			"grant_type":     "urn:ietf:params:oauth:grant-type:token-exchange",
			"subject_token":  subject,
			"account_id":     tn.account,
			"project_id":     tn.project,
			"user_id":        user,
			"application_id": identityID,
			"scope":          "sr:read sr:write",
		}, map[string]string{testTrustedServiceHeader: "trusted-service"})
	}

	outcome, records := offThenShadow(t, request)
	require.Equal(t, http.StatusBadRequest, outcome["status"])
	assert.Equal(t, "policy_violation", outcome["error"], "precondition: today the policy refusal has its own code")

	line := scopeRuleLine(t, records)
	assert.Equal(t, "one_code", line["rule"])
	assert.Equal(t, "external_principal", line["grant_type"])
	assert.Equal(t, identityID, line["identity_id"])
	assert.Equal(t, tn.account, line["account_id"])
	assert.Equal(t, tn.project, line["project_id"])
	assert.Equal(t, []any{"sr:read", "sr:write"}, line["requested_scopes"])
	assert.Equal(t, "refused", line["today"])
	assert.Equal(t, "policy_violation", line["today_code"])
	assert.Equal(t, "refused", line["would"])
	assert.Equal(t, "invalid_scope", line["would_code"])
	assert.NotContains(t, line, "user_id", "the record names no person")
	assert.Equal(t, map[string]int64{"one_code/external_principal": 1}, records.counts(t))
}

// TestScopeRulesShadow_NoChange: a request every stricter rule would answer
// the same way records nothing.
func TestScopeRulesShadow_NoChange(t *testing.T) {
	tn := newTenant(t, "")
	extID := uid("sr-none")
	tn.register(t, extID, tn.policy(t, nil), "", nil)
	client := registerOAuthClient(t, extID, []string{"sr:read", "sr:write"})
	request := func(t *testing.T) *http.Response {
		return post(t, "/oauth2/token", map[string]any{
			"grant_type":    "client_credentials",
			"account_id":    tn.account,
			"project_id":    tn.project,
			"client_id":     client.ClientID,
			"client_secret": client.ClientSecret,
			"scope":         "sr:read",
		}, nil)
	}

	outcome, records := offThenShadow(t, request)
	require.Equal(t, http.StatusOK, outcome["status"])
	assert.Equal(t, "sr:read", outcome["scope"])
	assert.Empty(t, records.lines(t), "named, listed by the admin-registered client, not narrowed")
	assert.Empty(t, records.counts(t))
}

// TestScopeRulesShadow_OffRecordsNothing: with the mode off, a request the
// rules would change records nothing.
func TestScopeRulesShadow_OffRecordsNothing(t *testing.T) {
	records := captureScopeRules(t)
	tn := newTenant(t, "")
	reg := registerAgentInTenant(t, uid("sr-off-ak"), tn.headers)
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type": "api_key",
		"api_key":    reg.APIKey,
		"scope":      "sr:manage",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()
	assert.Empty(t, records.lines(t))
	assert.Empty(t, records.counts(t))
}

// TestScopeRulesShadow_ReservedScopes: a reserved scope is governed by the
// reserved-scope rules and the deployer's authorizer, not by ceilings. Rule A
// keeps it as the key's own scope, rules B and C never judge it, and a request
// the reserved-scope rules refuse records nothing.
func TestScopeRulesShadow_ReservedScopes(t *testing.T) {
	status, _, key := createProductKey(t, "test-user", []string{"data:read", testReservedScope}, true)
	require.Equal(t, http.StatusCreated, status)
	keyGrant := func(scope string) func(t *testing.T) *http.Response {
		return func(t *testing.T) *http.Response {
			body := map[string]any{"grant_type": "api_key", "api_key": key}
			if scope != "" {
				body["scope"] = scope
			}
			return post(t, "/oauth2/token", body, nil)
		}
	}

	t.Run("an omitted request keeps the key's reserved scope", func(t *testing.T) {
		outcome, records := offThenShadow(t, keyGrant(""))
		require.Equal(t, http.StatusOK, outcome["status"])
		assert.Equal(t, "data:read "+testReservedScope, outcome["scope"], "precondition: the key's scopes, issued without asking")
		assert.Empty(t, records.lines(t))
		assert.Empty(t, records.counts(t))
	})

	t.Run("a request naming the reserved scope is issued it", func(t *testing.T) {
		outcome, records := offThenShadow(t, keyGrant(testReservedScope))
		require.Equal(t, http.StatusOK, outcome["status"])
		assert.Equal(t, testReservedScope, outcome["scope"])
		assert.Empty(t, records.lines(t))
	})

	t.Run("refusals by the reserved-scope rules record nothing", func(t *testing.T) {
		status, _, unlisted := createProductKey(t, "test-user", nil, false)
		require.Equal(t, http.StatusCreated, status)
		status, _, demoted := createProductKey(t, testDemotedUser, []string{testReservedScope}, true)
		require.Equal(t, http.StatusCreated, status)
		for name, tc := range map[string]struct{ key, code string }{
			"a key that does not list it": {unlisted, "invalid_scope"},
			"the authorizer refuses":      {demoted, "invalid_grant"},
		} {
			t.Run(name, func(t *testing.T) {
				outcome, records := offThenShadow(t, func(t *testing.T) *http.Response {
					return post(t, "/oauth2/token", map[string]any{
						"grant_type": "api_key", "api_key": tc.key, "scope": testReservedScope,
					}, nil)
				})
				require.Equal(t, http.StatusBadRequest, outcome["status"])
				assert.Equal(t, tc.code, outcome["error"])
				assert.Empty(t, records.lines(t))
			})
		}
	})

	// A token carrying the reserved scope, delegated to an actor whose own
	// ceilings allow data:read and, for the second actor, the reserved scope.
	code, body := exchangeKey(t, key, "")
	require.Equal(t, http.StatusOK, code, "%v", body)
	root := body["access_token"].(string)
	tn := hrdTenant{account: testAccountID, project: testProjectID, headers: adminHeaders()}
	delegate := func(actorScopes []string, scope string) func(t *testing.T) *http.Response {
		// The actor's tokens live less than the root's remaining lifetime, so
		// both runs answer the same expires_in.
		policyID := tn.policyWith(t, actorScopes, map[string]any{"max_ttl_seconds": 30})
		k := generateKey(t)
		wimse := tn.register(t, uid("sr-rs-actor"), policyID, ecPublicKeyPEM(t, k), actorScopes)
		return func(t *testing.T) *http.Response {
			return post(t, "/oauth2/token", map[string]any{
				"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
				"subject_token": root,
				"actor_token":   buildAssertion(t, k, wimse),
				"scope":         scope,
			}, nil)
		}
	}

	t.Run("an exchange refused for naming the reserved scope records nothing", func(t *testing.T) {
		outcome, records := offThenShadow(t, delegate([]string{"data:read", testReservedScope}, testReservedScope))
		require.Equal(t, http.StatusBadRequest, outcome["status"])
		assert.Equal(t, "insufficient_scope", outcome["error"], "precondition: today the chokepoint's own code")
		assert.Empty(t, records.lines(t), "the reserved-scope rules refused it, not a ceiling")
		assert.Empty(t, records.counts(t))
	})

	t.Run("an exchange whose ceiling drops the reserved scope is not narrowed", func(t *testing.T) {
		outcome, records := offThenShadow(t, delegate([]string{"data:read"}, "data:read "+testReservedScope))
		require.Equal(t, http.StatusOK, outcome["status"])
		assert.Equal(t, "data:read", outcome["scope"], "precondition: today the reserved scope is dropped")
		assert.Empty(t, records.lines(t))
		assert.Empty(t, records.counts(t))
	})
}

// TestScopeRulesShadow_InternalServiceGrants: the on-behalf exchange and the
// asserted-tenant grant are open only to the deployment's own services, refuse
// a scope parameter with invalid_scope and issue no scopes, so they record
// nothing. A session broker's external-principal exchange is evaluated like
// any other.
func TestScopeRulesShadow_InternalServiceGrants(t *testing.T) {
	gw := gateway(t)
	jb := jobs(t)
	tn := newTenant(t, "")
	subject := brokerSession(t, testAccountID, testProjectID, uid("sr-obo"), nil)["access_token"].(string)

	for name, tc := range map[string]struct {
		body   func() map[string]any
		client svcClient
	}{
		"on-behalf exchange": {client: gw, body: func() map[string]any { return onBehalf(subject, receiverResource) }},
		"asserted-tenant grant": {client: jb, body: func() map[string]any {
			return map[string]any{
				"grant_type": assertedGrant, "account_id": tn.account, "project_id": tn.project, "resource": receiverResource,
			}
		}},
	} {
		t.Run(name, func(t *testing.T) {
			outcome, records := offThenShadow(t, func(t *testing.T) *http.Response {
				return post(t, "/oauth2/token", tc.client.auth(t, tc.body()), nil)
			})
			require.Equal(t, http.StatusOK, outcome["status"])
			assert.NotContains(t, outcome["access_token.claims"], "scopes")
			assert.Empty(t, records.lines(t))

			outcome, records = offThenShadow(t, func(t *testing.T) *http.Response {
				body := tc.body()
				body["scope"] = "sr:read"
				return post(t, "/oauth2/token", tc.client.auth(t, body), nil)
			})
			require.Equal(t, http.StatusBadRequest, outcome["status"])
			assert.Equal(t, "invalid_scope", outcome["error"])
			assert.Empty(t, records.lines(t))
			assert.Empty(t, records.counts(t))
		})
	}

	t.Run("a session broker's exchange is evaluated", func(t *testing.T) {
		policyID := tn.policy(t, []string{"sr:read"})
		identityID := registerIdentityWithPolicy(t, uid("sr-broker-app"), policyID, "", nil, tn.headers)
		user := uid("sr-broker-user")
		personSubject := personToken(t, tn.account, tn.project, user)
		outcome, records := offThenShadow(t, func(t *testing.T) *http.Response {
			body := brokerExchange(personSubject, tn.account, tn.project, user)
			body["application_id"] = identityID
			body["scope"] = "sr:read sr:write"
			return post(t, "/oauth2/token", broker(t).auth(t, body), nil)
		})
		require.Equal(t, http.StatusBadRequest, outcome["status"])
		assert.Equal(t, "policy_violation", outcome["error"])

		line := scopeRuleLine(t, records)
		assert.Equal(t, "one_code", line["rule"])
		assert.Equal(t, "external_principal", line["grant_type"])
		assert.Equal(t, testBrokerClient, line["client_id"])
		assert.Equal(t, identityID, line["identity_id"])
	})
}
