package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	zeroid "github.com/highflame-ai/zeroid"
)

// The stricter scope rules, enforced (docs/scope-ceilings.md, "Stricter scope
// rules"). Every test runs one request with the mode off, in shadow and in
// enforce: off and shadow must answer identically, as in the shadow suite;
// enforce must give the stricter rules' answer and record it with
// mode=enforce, judging the request exactly as shadow judged it. No test calls
// t.Parallel(), so switching a server's mode is safe.

// enforceRun is one request's answers under the three modes.
type enforceRun struct {
	// today is the answer with the mode off, which shadow repeats.
	today map[string]any
	// enforced is the answer in enforce mode.
	enforced map[string]any
	// shadowRecords and records are what shadow and enforce recorded.
	shadowRecords, records *scopeRuleCapture
}

// runModes makes one request with srv's mode off, in shadow (checking the two
// answers are identical) and in enforce, and leaves the mode off when the test
// ends. outcome must make one equivalent request each time it is called and
// reduce the answer to what the mode must not change. It starts from off
// whatever an earlier run in the same test left the mode at.
func runModes(t *testing.T, srv *zeroid.Server, outcome func(t *testing.T) map[string]any) enforceRun {
	t.Helper()
	require.NoError(t, srv.SetScopeRulesMode(zeroid.ScopeRulesModeOff))
	t.Cleanup(func() { require.NoError(t, srv.SetScopeRulesMode(zeroid.ScopeRulesModeOff)) })
	off := outcome(t)

	require.NoError(t, srv.SetScopeRulesMode(zeroid.ScopeRulesModeShadow))
	shadowRecords := captureScopeRules(t)
	shadow := outcome(t)
	assert.Equal(t, off, shadow, "shadow must answer exactly as off does")

	require.NoError(t, srv.SetScopeRulesMode(zeroid.ScopeRulesModeEnforce))
	records := captureScopeRules(t)
	run := enforceRun{today: off, enforced: outcome(t), shadowRecords: shadowRecords, records: records}
	sameJudgement(t, run)
	return run
}

// offShadowEnforce is runModes on the shared server for a request to it.
func offShadowEnforce(t *testing.T, request func(t *testing.T) *http.Response) enforceRun {
	t.Helper()
	return runModes(t, testZeroIDServer, func(t *testing.T) map[string]any { return tokenOutcome(t, request(t)) })
}

// judgement is what a record says was judged: everything but the mode and the
// outcome the rule gave. Shadow and enforce must agree on it.
func judgement(lines []map[string]any) []map[string]any {
	var out []map[string]any
	for _, l := range lines {
		j := map[string]any{}
		for k, v := range l {
			switch k {
			case "mode", "would", "would_scopes", "would_code", "time", "level":
			default:
				j[k] = v
			}
		}
		out = append(out, j)
	}
	return out
}

// sameJudgement checks enforce recorded exactly the rules shadow recorded,
// against the same outcome today, and that every enforce record says enforce.
func sameJudgement(t *testing.T, run enforceRun) {
	t.Helper()
	enforced := run.records.lines(t)
	assert.Equal(t, judgement(run.shadowRecords.lines(t)), judgement(enforced), "enforce judges the request exactly as shadow does")
	for _, l := range enforced {
		assert.Equal(t, "enforce", l["mode"])
	}
	assert.Equal(t, run.shadowRecords.counts(t), run.records.counts(t), "enforce counts each rule shadow counts")
}

// requireInvalidScope checks an answer is RFC 6749 §5.2 invalid_scope with
// description desc, and carries no token.
func requireInvalidScope(t *testing.T, outcome map[string]any, desc string) {
	t.Helper()
	require.Equal(t, http.StatusBadRequest, outcome["status"], "outcome=%v", outcome)
	assert.Equal(t, "invalid_scope", outcome["error"])
	assert.Equal(t, desc, outcome["error_description"])
	assert.NotContains(t, outcome, "access_token.claims")
}

// requireNoScopes checks an answer is a token with no scope at all: no scope
// member in the response and no scopes or scope claim in the token.
func requireNoScopes(t *testing.T, outcome map[string]any) {
	t.Helper()
	require.Equal(t, http.StatusOK, outcome["status"], "outcome=%v", outcome)
	assert.NotContains(t, outcome, "scope")
	claims, ok := outcome["access_token.claims"].(map[string]any)
	require.True(t, ok, "outcome=%v", outcome)
	assert.NotContains(t, claims, "scopes")
	assert.NotContains(t, claims, "scope")
}

// enforceLine returns the single record enforce mode made, checking its mode.
func enforceLine(t *testing.T, records *scopeRuleCapture) map[string]any {
	t.Helper()
	line := scopeRuleLine(t, records)
	assert.Equal(t, "enforce", line["mode"])
	return line
}

// apiKeyFor creates an API key for identityID in tn with scopes, and returns
// it.
func apiKeyFor(t *testing.T, tn hrdTenant, identityID string, scopes []string) string {
	t.Helper()
	body := map[string]any{"name": uid("sre-key"), "identity_id": identityID}
	if scopes != nil {
		body["scopes"] = scopes
	}
	resp := post(t, adminPath("/api-keys"), body, tn.headers)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	key, _ := decode(t, resp)["key"].(string)
	require.NotEmpty(t, key)
	return key
}

// apiKeyRequest exchanges key for a token naming scope ("" names none).
func apiKeyRequest(key, scope string) func(t *testing.T) *http.Response {
	return func(t *testing.T) *http.Response {
		body := map[string]any{"grant_type": "api_key", "api_key": key}
		if scope != "" {
			body["scope"] = scope
		}
		return post(t, "/oauth2/token", body, nil)
	}
}

// clientCredentialsRequest asks for a client_credentials token in tn naming
// scope ("" names none).
func clientCredentialsRequest(tn hrdTenant, client oauthClientResp, scope string) func(t *testing.T) *http.Response {
	return func(t *testing.T) *http.Response {
		body := map[string]any{
			"grant_type": "client_credentials", "account_id": tn.account, "project_id": tn.project,
			"client_id": client.ClientID, "client_secret": client.ClientSecret,
		}
		if scope != "" {
			body["scope"] = scope
		}
		return post(t, "/oauth2/token", body, nil)
	}
}

// authorizeCode posts an authorization request for clientID naming scope (""
// names none) and returns the redirect's query and the PKCE verifier.
func authorizeCode(t *testing.T, clientID, scope string) (url.Values, string) {
	t.Helper()
	form, verifier := authorizeBaseForm(t)
	form.Set("client_id", clientID)
	if scope != "" {
		form.Set("scope", scope)
	}
	resp := postAuthorize(t, form)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	return loc.Query(), verifier
}

// codeClaims are an authorization code's claims less what differs on every
// code.
func codeClaims(t *testing.T, code string) map[string]any {
	t.Helper()
	claims := decodeJWTPayload(t, code)
	for _, c := range append([]string{"cc"}, perMintClaims...) {
		delete(claims, c)
	}
	return claims
}

// authorizeOutcome posts an authorization request for clientID naming scope
// ("" names none) and reduces the answer to what the mode must not change:
// the redirect's state and code claims, or the refusal.
func authorizeOutcome(t *testing.T, clientID, scope string) map[string]any {
	t.Helper()
	form, _ := authorizeBaseForm(t)
	form.Set("client_id", clientID)
	if scope != "" {
		form.Set("scope", scope)
	}
	resp := postAuthorize(t, form)
	if resp.StatusCode != http.StatusFound {
		return tokenOutcome(t, resp)
	}
	defer func() { _ = resp.Body.Close() }()
	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	return map[string]any{"status": resp.StatusCode, "state": loc.Query().Get("state"), "code": codeClaims(t, loc.Query().Get("code"))}
}

// authCodeClient registers a public authorization_code client through the
// admin API, whose registered scopes are a listing, with scopes.
func authCodeClient(t *testing.T, scopes []string, grants ...string) string {
	t.Helper()
	clientID := uid("sre-ac")
	resp := post(t, adminPath("/oauth/clients"), map[string]any{
		"client_id":     clientID,
		"name":          clientID,
		"confidential":  false,
		"grant_types":   append([]string{"authorization_code"}, grants...),
		"redirect_uris": []string{testRedirectURI},
		"scopes":        scopes,
	}, nil)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	_ = resp.Body.Close()
	return clientID
}

// redeemCode redeems an authorization code built for clientID and user with
// scopes.
func redeemCode(clientID, user string, scopes []string) func(t *testing.T) *http.Response {
	return func(t *testing.T) *http.Response {
		verifier, challenge := buildPKCEPair(t)
		return post(t, "/oauth2/token", map[string]any{
			"grant_type":    "authorization_code",
			"client_id":     clientID,
			"code":          buildAuthCode(t, clientID, user, testRedirectURI, challenge, scopes),
			"code_verifier": verifier,
			"redirect_uri":  testRedirectURI,
		}, nil)
	}
}

// refreshFamily redeems a code for clientID with the mode off and returns the
// refresh token it is issued.
func refreshFamily(t *testing.T, clientID, user string, scopes []string) string {
	t.Helper()
	resp := redeemCode(clientID, user, scopes)(t)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	rt, _ := decode(t, resp)["refresh_token"].(string)
	require.NotEmpty(t, rt)
	return rt
}

// refreshOutcome presents a refresh token for clientID.
func refreshOutcome(t *testing.T, clientID, rt string) map[string]any {
	t.Helper()
	return tokenOutcome(t, post(t, "/oauth2/token", map[string]any{
		"grant_type": "refresh_token", "refresh_token": rt, "client_id": clientID,
	}, nil))
}

// refreshFamilies starts three refresh families of one shape, for one user, so
// each mode can refresh its own (a refresh token is single-use).
func refreshFamilies(t *testing.T, clientID, user string, scopes []string) []string {
	t.Helper()
	var families []string
	for range 3 {
		families = append(families, refreshFamily(t, clientID, user, scopes))
	}
	return families
}

// refreshModes refreshes three families of one shape, one with the mode off,
// one in shadow (checking the answers are identical) and one in enforce.
func refreshModes(t *testing.T, clientID string, families []string) enforceRun {
	t.Helper()
	require.Len(t, families, 3)
	i := 0
	return runModes(t, testZeroIDServer, func(t *testing.T) map[string]any {
		defer func() { i++ }()
		return refreshOutcome(t, clientID, families[i])
	})
}

// TestScopeRulesEnforce_OmittedRequest (rule A): a request that names no scope
// is issued only an API key's stored scopes or an audience profile's, and
// otherwise none, where today it gets a default. A request today's rules refuse
// stays refused.
func TestScopeRulesEnforce_OmittedRequest(t *testing.T) {
	t.Run("client_credentials is issued none, not the client's scopes", func(t *testing.T) {
		tn := newTenant(t, "")
		extID := uid("sre-a-cc")
		tn.register(t, extID, tn.policy(t, nil), "", nil)
		client := registerOAuthClient(t, extID, []string{"sr:read", "sr:write"})
		run := offShadowEnforce(t, clientCredentialsRequest(tn, client, ""))
		require.Equal(t, http.StatusOK, run.today["status"])
		assert.Equal(t, "sr:read sr:write", run.today["scope"], "precondition: today an omitted scope gets the client's list")

		requireNoScopes(t, run.enforced)
		line := enforceLine(t, run.records)
		assert.Equal(t, "omitted_request", line["rule"])
		assert.Equal(t, "client_credentials", line["grant_type"])
		assert.Equal(t, client.ClientID, line["client_id"])
		assert.Equal(t, "issued", line["today"])
		assert.Equal(t, []any{"sr:read", "sr:write"}, line["today_scopes"])
		assert.Equal(t, "issued", line["would"])
		assert.Equal(t, []any{}, line["would_scopes"])
		assert.Equal(t, map[string]int64{"omitted_request/client_credentials": 1}, run.records.counts(t))
	})

	t.Run("jwt_bearer is issued none, not the identity's ceiling", func(t *testing.T) {
		tn := newTenant(t, "")
		key := generateKey(t)
		wimse := tn.register(t, uid("sre-a-jb"), "", ecPublicKeyPEM(t, key), []string{"sr:read"})
		run := offShadowEnforce(t, func(t *testing.T) *http.Response {
			return post(t, "/oauth2/token", map[string]any{
				"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
				"assertion":  buildAssertion(t, key, wimse),
			}, nil)
		})
		require.Equal(t, http.StatusOK, run.today["status"])
		assert.Equal(t, "sr:read", run.today["scope"], "precondition: today an omitted scope gets allowed_scopes")

		requireNoScopes(t, run.enforced)
		line := enforceLine(t, run.records)
		assert.Equal(t, "omitted_request", line["rule"])
		assert.Equal(t, "jwt_bearer", line["grant_type"])
	})

	t.Run("api_key: a key with stored scopes keeps them, a key without is issued none", func(t *testing.T) {
		tn := newTenant(t, "")
		identityID := registerIdentityWithPolicy(t, uid("sre-a-ak"), "", "", []string{"sr:read", "sr:write"}, tn.headers)

		run := offShadowEnforce(t, apiKeyRequest(apiKeyFor(t, tn, identityID, []string{"sr:read"}), ""))
		require.Equal(t, http.StatusOK, run.today["status"])
		assert.Equal(t, "sr:read", run.today["scope"])
		assert.Equal(t, run.today, run.enforced, "rule A keeps the scopes stored on the key")
		assert.Empty(t, run.records.lines(t))

		run = offShadowEnforce(t, apiKeyRequest(apiKeyFor(t, tn, identityID, nil), ""))
		require.Equal(t, http.StatusOK, run.today["status"])
		assert.Equal(t, "sr:read sr:write", run.today["scope"], "precondition: today a key without scopes gets the identity's ceiling")
		requireNoScopes(t, run.enforced)
		assert.Equal(t, "omitted_request", enforceLine(t, run.records)["rule"])
	})

	t.Run("an authorization request gets a code with no scopes, and its token none", func(t *testing.T) {
		clientID := authCodeClient(t, []string{"sr:read", "sr:write"})
		run := runModes(t, testZeroIDServer, func(t *testing.T) map[string]any {
			return authorizeOutcome(t, clientID, "")
		})
		require.Equal(t, http.StatusFound, run.today["status"])
		assert.Equal(t, []any{"sr:read", "sr:write"}, run.today["code"].(map[string]any)["scp"], "precondition: today the code carries the client's list")
		require.Equal(t, http.StatusFound, run.enforced["status"])
		assert.NotContains(t, run.enforced["code"], "scp", "the code carries no scopes")
		line := enforceLine(t, run.records)
		assert.Equal(t, "omitted_request", line["rule"])
		assert.Equal(t, "authorization_code", line["grant_type"])
		assert.Equal(t, []any{"sr:read", "sr:write"}, line["today_scopes"])
		assert.Equal(t, []any{}, line["would_scopes"])

		// Redeem a code enforce issues: no scope, and nothing more recorded.
		query, verifier := authorizeCode(t, clientID, "")
		code := query.Get("code")
		require.NotEmpty(t, code)
		redeemed := tokenOutcome(t, post(t, "/oauth2/token", map[string]any{
			"grant_type": "authorization_code", "client_id": clientID, "code": code,
			"code_verifier": verifier, "redirect_uri": testRedirectURI,
		}, nil))
		requireNoScopes(t, redeemed)
		assert.Len(t, run.records.lines(t), 2, "the second authorization request is recorded; its redemption changes nothing more")
	})

	t.Run("refresh_token repeats its family's scopes", func(t *testing.T) {
		clientID := authCodeClient(t, []string{"sr:read"}, "refresh_token")
		run := refreshModes(t, clientID, refreshFamilies(t, clientID, uid("sre-a-rt"), []string{"sr:read"}))
		require.Equal(t, http.StatusOK, run.today["status"])
		assert.Equal(t, "sr:read", run.today["scope"])
		assert.Equal(t, run.today["scope"], run.enforced["scope"])
		assert.Empty(t, run.records.lines(t), "an omitted scope on refresh repeats the grant (RFC 6749 §6)")
	})

	t.Run("an omitted request today's rules refuse stays refused", func(t *testing.T) {
		// Disjoint ceilings: the default the request would get is empty, which
		// today's rules refuse rather than mint a token without a scopes claim.
		// Enforcement never turns that refusal into such a token.
		tn := newTenant(t, "")
		key := generateKey(t)
		policyID := tn.policyWith(t, []string{"sr:b"}, map[string]any{"allowed_grant_types": []string{"jwt_bearer"}})
		wimse := tn.register(t, uid("sre-a-disjoint"), policyID, ecPublicKeyPEM(t, key), []string{"sr:a"})
		run := offShadowEnforce(t, func(t *testing.T) *http.Response {
			return post(t, "/oauth2/token", map[string]any{
				"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
				"assertion":  buildAssertion(t, key, wimse),
			}, nil)
		})
		require.Equal(t, http.StatusBadRequest, run.today["status"])
		assert.Equal(t, "invalid_scope", run.today["error"])
		assert.Equal(t, run.today, run.enforced, "still refused, with today's answer: no scope was named")
		assert.Empty(t, run.records.lines(t), "the refusal's code is already invalid_scope, and it is not turned into a token")
	})

	t.Run("a client with no scopes, asked for none, stays refused with today's answer", func(t *testing.T) {
		tn := newTenant(t, "")
		extID := uid("sre-a-none")
		tn.register(t, extID, tn.policy(t, nil), "", nil)
		client := registerOAuthClient(t, extID, nil)
		run := offShadowEnforce(t, clientCredentialsRequest(tn, client, ""))
		require.Equal(t, http.StatusBadRequest, run.today["status"])
		assert.Equal(t, "invalid_scope", run.today["error"])
		assert.Equal(t, run.today, run.enforced, "no scope was named, so the description keeps today's")
		assert.Empty(t, run.records.lines(t))
	})
}

// newScopeRulesCIMDServer is a second server whose CIMD document fetcher
// reaches docClient's origin (see newCIMDZeroID), started with
// token.scope_rules set from the config.
func newScopeRulesCIMDServer(t *testing.T, docClient *http.Client, mode zeroid.ScopeRulesMode) (*zeroid.Server, string) {
	t.Helper()
	require.NoError(t, initFederationKeyMaterial())
	srv, err := zeroid.NewServer(zeroid.Config{
		Server:   zeroid.ServerConfig{Port: "0", Env: "test", ShutdownTimeoutSeconds: 5},
		Database: zeroid.DatabaseConfig{URL: sharedDBURL, MaxOpenConns: 5, MaxIdleConns: 2},
		Keys: zeroid.KeysConfig{
			PrivateKeyPath: fedKeyPaths.privPath, PublicKeyPath: fedKeyPaths.pubPath, KeyID: "sre-cimd-key-1",
			RSAPrivateKeyPath: fedKeyPaths.rsaPriv, RSAPublicKeyPath: fedKeyPaths.rsaPub, RSAKeyID: "sre-cimd-rsa-1",
		},
		Token: zeroid.TokenConfig{
			Issuer: cimdTestIssuer, DefaultTTL: 3600, MaxTTL: 90 * 24 * 3600,
			HMACSecret: testHMACSecret, AuthCodeIssuer: cimdTestIssuer,
			ScopeRules: string(mode),
		},
		CIMD:        zeroid.CIMDConfig{Enabled: true},
		Telemetry:   zeroid.TelemetryConfig{Enabled: false},
		Logging:     zeroid.LoggingConfig{Level: "warn"},
		WIMSEDomain: testWIMSE,
	}, zeroid.WithCIMDHTTPClient(docClient))
	require.NoError(t, err)
	srv.RegisterPrincipalResolver("sre-cimd-stub", func(_ context.Context, req *zeroid.AuthorizeRequest) (*zeroid.Principal, error) {
		if req.Form("test_principal_account") == "" {
			return nil, zeroid.ErrPrincipalNotApplicable
		}
		return &zeroid.Principal{AccountID: req.Form("test_principal_account"), UserID: req.Form("test_principal_user")}, nil
	})
	httpSrv := httptest.NewServer(srv.Router())
	t.Cleanup(httpSrv.Close)
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	return srv, httpSrv.URL
}

// TestScopeRulesEnforce_MetadataDocumentClient (rule A): an authorization
// request from a client identified by a metadata document, naming no scope,
// gets the document's scope today. A document's scope is the client's own
// request, never a listing, so enforce issues none. The server starts with
// token.scope_rules=enforce from its config.
func TestScopeRulesEnforce_MetadataDocumentClient(t *testing.T) {
	base, docClient := newCIMDDocumentOrigin(t, fmt.Sprintf(`{
		"client_id": "%%CLIENT_ID%%",
		"client_name": "scope rules document client",
		"redirect_uris": [%q],
		"grant_types": ["authorization_code"],
		"token_endpoint_auth_method": "none",
		"scope": "sr:read sr:write"
	}`, cimdTestRedirectURI))
	srv, srvURL := newScopeRulesCIMDServer(t, docClient, zeroid.ScopeRulesModeEnforce)
	clientID := base + "/.well-known/oauth-client"

	// authorize returns the code a request naming no scope gets, and its
	// verifier.
	authorize := func(t *testing.T) (string, string) {
		t.Helper()
		verifier, challenge := buildPKCEPair(t)
		resp := cimdAuthorize(t, srvURL, url.Values{
			"client_id": {clientID}, "redirect_uri": {cimdTestRedirectURI}, "response_type": {"code"},
			"code_challenge": {challenge}, "code_challenge_method": {"S256"},
			"test_principal_account": {"acct-sre-cimd"}, "test_principal_user": {"user-sre-cimd"},
		})
		require.Equal(t, http.StatusFound, resp.StatusCode)
		loc, err := url.Parse(resp.Header.Get("Location"))
		require.NoError(t, err)
		code := loc.Query().Get("code")
		require.NotEmpty(t, code, "location=%s", resp.Header.Get("Location"))
		return code, verifier
	}

	records := captureScopeRules(t)
	code, verifier := authorize(t)
	assert.NotContains(t, decodeJWTPayload(t, code), "scp", "enforce (from the config) issues no scopes")
	line := enforceLine(t, records)
	assert.Equal(t, "omitted_request", line["rule"])
	assert.Equal(t, []any{"sr:read", "sr:write"}, line["today_scopes"], "today the code carries the document's scope")
	tok := postFederation(t, srvURL, map[string]any{
		"grant_type": "authorization_code", "client_id": clientID, "code": code,
		"code_verifier": verifier, "redirect_uri": cimdTestRedirectURI,
	})
	require.Equal(t, http.StatusOK, tok.StatusCode, tok.RawBody)
	assert.NotContains(t, decodeJWTPayload(t, tok.AccessToken), "scopes")

	// Off and shadow answer alike: the code carries the document's scope.
	run := runModes(t, srv, func(t *testing.T) map[string]any {
		code, _ := authorize(t)
		return map[string]any{"code": codeClaims(t, code)}
	})
	assert.Equal(t, []any{"sr:read", "sr:write"}, run.today["code"].(map[string]any)["scp"])
	assert.NotContains(t, run.enforced["code"], "scp")
	assert.Equal(t, "omitted_request", enforceLine(t, run.records)["rule"])
}

// TestScopeRulesEnforce_Listing (rule B): a scope is issued only when a
// ceiling the deployer controls lists it. Today an empty ceiling restricts
// nothing, so a scope nothing lists is granted.
func TestScopeRulesEnforce_Listing(t *testing.T) {
	t.Run("api_key with no ceiling anywhere", func(t *testing.T) {
		tn := newTenant(t, "")
		reg := registerAgentInTenant(t, uid("sre-b-ak"), tn.headers)
		run := offShadowEnforce(t, apiKeyRequest(reg.APIKey, "sr:manage"))
		require.Equal(t, http.StatusOK, run.today["status"])
		assert.Equal(t, "sr:manage", run.today["scope"], "precondition: today an unlisted scope is granted")

		requireInvalidScope(t, run.enforced, `scope sr:manage is not granted: no scope ceiling an administrator controls lists it; `+
			`list it in the API key's scopes, the API key's credential policy's allowed_scopes, the identity's allowed_scopes `+
			`or the identity's credential policy's allowed_scopes`)
		line := enforceLine(t, run.records)
		assert.Equal(t, "listing", line["rule"])
		assert.Equal(t, "api_key", line["grant_type"])
		assert.Equal(t, "issued", line["today"])
		assert.Equal(t, []any{"sr:manage"}, line["today_scopes"])
		assert.Equal(t, []any{"sr:manage"}, line["unlisted_scopes"])
		assert.Equal(t, "refused", line["would"])
		assert.Equal(t, "invalid_scope", line["would_code"])
		assert.Equal(t, map[string]int64{"listing/api_key": 1}, run.records.counts(t))
	})

	t.Run("jwt_bearer for an identity no ceiling restricts", func(t *testing.T) {
		tn := newTenant(t, "")
		key := generateKey(t)
		wimse := tn.register(t, uid("sre-b-jb"), "", ecPublicKeyPEM(t, key), nil)
		request := func(scope string) func(t *testing.T) *http.Response {
			return func(t *testing.T) *http.Response {
				body := map[string]any{
					"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
					"assertion":  buildAssertion(t, key, wimse),
				}
				if scope != "" {
					body["scope"] = scope
				}
				return post(t, "/oauth2/token", body, nil)
			}
		}
		run := offShadowEnforce(t, request("sr:read"))
		require.Equal(t, http.StatusOK, run.today["status"])
		requireInvalidScope(t, run.enforced, `scope sr:read is not granted: no scope ceiling an administrator controls lists it; `+
			`list it in the identity's allowed_scopes or the identity's credential policy's allowed_scopes`)
		assert.Equal(t, "listing", enforceLine(t, run.records)["rule"])

		// Empty ceilings everywhere and nothing named: nothing is unlisted,
		// so today's token without a scopes claim stands.
		run = offShadowEnforce(t, request(""))
		requireNoScopes(t, run.today)
		assert.Equal(t, run.today, run.enforced)
		assert.Empty(t, run.records.lines(t))
	})

	t.Run("authorization_code for a client that registered no scopes", func(t *testing.T) {
		user := uid("sre-b-user")
		run := offShadowEnforce(t, redeemCode(testCLIClientID, user, []string{"sr:read"}))
		require.Equal(t, http.StatusOK, run.today["status"])
		// A client seeded by the operator (EnsureClient), not created through
		// the admin API, has registered scopes that are not a listing.
		requireInvalidScope(t, run.enforced, `scope sr:read is not granted: no scope ceiling an administrator controls applies to this request, so none lists it`)
		line := enforceLine(t, run.records)
		assert.Equal(t, "listing", line["rule"])
		assert.Equal(t, "authorization_code", line["grant_type"])
		assert.Equal(t, testCLIClientID, line["client_id"])
	})

	t.Run("authorization_code naming one listed and one unlisted scope is refused whole", func(t *testing.T) {
		clientID := authCodeClient(t, []string{"sr:read"})
		run := offShadowEnforce(t, redeemCode(clientID, uid("sre-b-mixed"), []string{"sr:read", "sr:write"}))
		require.Equal(t, http.StatusOK, run.today["status"])
		assert.Equal(t, "sr:read sr:write", run.today["scope"], "precondition: today the unlisted scope is issued too")

		requireInvalidScope(t, run.enforced, `scope sr:write is not granted: no scope ceiling an administrator controls lists it; `+
			`list it in the client's registered scopes`)
		line := enforceLine(t, run.records)
		assert.Equal(t, "listing", line["rule"])
		assert.Equal(t, []any{"sr:write"}, line["unlisted_scopes"])
		assert.Equal(t, "refused", line["would"], "rule C refuses what rule B alone would narrow")
		shadowLine := scopeRuleLine(t, run.shadowRecords)
		assert.Equal(t, []any{"sr:read"}, shadowLine["would_scopes"], "shadow judges rule B on its own")
	})

	t.Run("token exchange: the actor's ceilings list nothing", func(t *testing.T) {
		tn := newTenant(t, "")
		parent, _ := tn.workloadRoot(t, tn.policy(t, []string{"sr:a"}), []string{"sr:a"})
		key := generateKey(t)
		actor := tn.register(t, uid("sre-b-actor"), "", ecPublicKeyPEM(t, key), nil)
		run := offShadowEnforce(t, func(t *testing.T) *http.Response {
			return post(t, "/oauth2/token", map[string]any{
				"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
				"subject_token": parent,
				"actor_token":   buildAssertion(t, key, actor),
				"scope":         "sr:a",
			}, nil)
		})
		require.Equal(t, http.StatusOK, run.today["status"], "precondition: today the parent's scope is delegated")
		requireInvalidScope(t, run.enforced, `scope sr:a is not granted: no scope ceiling an administrator controls lists it; `+
			`list it in the identity's allowed_scopes or the identity's credential policy's allowed_scopes`)
		line := enforceLine(t, run.records)
		assert.Equal(t, "listing", line["rule"])
		assert.Equal(t, "token_exchange", line["grant_type"])
	})

	t.Run("trusted external-principal exchange with no application", func(t *testing.T) {
		tn := newTenant(t, "")
		user := uid("sre-b-user")
		subject := personToken(t, tn.account, tn.project, user)
		run := offShadowEnforce(t, func(t *testing.T) *http.Response {
			return post(t, "/oauth2/token", map[string]any{
				"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
				"subject_token": subject,
				"account_id":    tn.account,
				"project_id":    tn.project,
				"user_id":       user,
				"scope":         "sr:read",
			}, map[string]string{testTrustedServiceHeader: "trusted-service"})
		})
		require.Equal(t, http.StatusOK, run.today["status"])
		requireInvalidScope(t, run.enforced, `scope sr:read is not granted: no scope ceiling an administrator controls applies to this request, so none lists it`)
		assert.Equal(t, "external_principal", enforceLine(t, run.records)["grant_type"])
	})

	t.Run("refresh_token: a family's scope no ceiling lists is refused, and the refresh token survives", func(t *testing.T) {
		families := refreshFamilies(t, testMCPClientID, uid("sre-b-rt"), []string{"sr:read"})
		run := refreshModes(t, testMCPClientID, families)
		require.Equal(t, http.StatusOK, run.today["status"])
		// A client seeded by the operator (EnsureClient), not created through
		// the admin API, has registered scopes that are not a listing.
		requireInvalidScope(t, run.enforced, `scope sr:read is not granted: no scope ceiling an administrator controls applies to this request, so none lists it`)
		line := enforceLine(t, run.records)
		assert.Equal(t, "listing", line["rule"])
		assert.Equal(t, "refresh_token", line["grant_type"])

		// The refusal came after rotation and put the presented token back:
		// with the mode off again, the same token refreshes.
		require.NoError(t, testZeroIDServer.SetScopeRulesMode(zeroid.ScopeRulesModeOff))
		again := refreshOutcome(t, testMCPClientID, families[2])
		require.Equal(t, http.StatusOK, again["status"], "the refused refresh did not consume the token: %v", again)
		assert.Equal(t, "sr:read", again["scope"])
	})

	t.Run("CIBA poll for a client that registered no scopes", func(t *testing.T) {
		c := newConfidentialCIBAClient(t)
		run := offShadowEnforce(t, func(t *testing.T) *http.Response {
			resp := bcAuthorizeAs(t, c, map[string]any{"login_hint": "user-sre-ciba", "scope": "sr:read"})
			body := decode(t, resp)
			require.Equal(t, http.StatusOK, resp.StatusCode, "bc-authorize: %v", body)
			id := body["auth_req_id"].(string)
			approveInTenant(t, id, "user-sre-ciba", adminHeaders())
			return post(t, "/oauth2/token", map[string]any{
				"grant_type": zeroidGrantTypeCIBA, "auth_req_id": id, "client_id": c.ID, "client_secret": c.Secret,
			}, nil)
		})
		require.Equal(t, http.StatusOK, run.today["status"], "precondition: today a confidential client with no scopes is not restricted")
		requireInvalidScope(t, run.enforced, `scope sr:read is not granted: no scope ceiling an administrator controls lists it; `+
			`list it in the client's registered scopes`)
		line := enforceLine(t, run.records)
		assert.Equal(t, "listing", line["rule"])
		assert.Equal(t, zeroidGrantTypeCIBA, line["grant_type"])
	})

	t.Run("ID-token exchange: nothing the deployer controls lists the scope", func(t *testing.T) {
		f := newPersonGrantFederation(t)
		user := uid("sre-b-idt")
		run := runModes(t, f.srv, func(t *testing.T) map[string]any {
			now := time.Now()
			idToken := f.upstream.SignToken(t, map[string]any{
				"iss": f.iss, "aud": f.aud, "sub": user,
				"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
			})
			return federationOutcome(t, f.url, map[string]any{
				"grant_type":            "urn:ietf:params:oauth:grant-type:token-exchange",
				"subject_token":         idToken,
				"subject_token_type":    "urn:ietf:params:oauth:token-type:id_token",
				"client_id":             f.rp.ClientID,
				"client_assertion":      rpAssertion(t, f.rp),
				"client_assertion_type": clientAssertionType,
				"account_id":            f.cfg.AccountID,
				"project_id":            f.cfg.ProjectID,
				"scope":                 "pg:a",
			})
		})
		require.Equal(t, http.StatusOK, run.today["status"], "precondition: today the requested scope is issued; %v", run.today)
		requireInvalidScope(t, run.enforced, `scope pg:a is not granted: no scope ceiling an administrator controls lists it; `+
			`list it in the client's registered scopes or the tenant's default credential policy's allowed_scopes`)
		line := enforceLine(t, run.records)
		assert.Equal(t, "listing", line["rule"])
		assert.Equal(t, "external_id_token", line["grant_type"])
	})
}

// federationOutcome posts body to a federation server's token endpoint and
// reduces the answer as tokenOutcome does.
func federationOutcome(t *testing.T, baseURL string, body map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, baseURL+"/oauth2/token", bytes.NewReader(raw))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return tokenOutcome(t, resp)
}

// TestScopeRulesEnforce_AllOrNothing (rule C): a request is issued every scope
// it names or is refused whole, never narrowed silently. In delegation the
// subject token is one more ceiling, and a delegation that names no scope is
// issued none.
func TestScopeRulesEnforce_AllOrNothing(t *testing.T) {
	t.Run("delegation", func(t *testing.T) {
		tn := newTenant(t, "")
		scopes := []string{"sr:a", "sr:b", "sr:c"}
		parent, _ := tn.workloadRoot(t, tn.policy(t, scopes), []string{"sr:a", "sr:b"})
		actorPolicy := tn.policyWith(t, scopes, map[string]any{"max_ttl_seconds": 600})
		key := generateKey(t)
		actor := tn.register(t, uid("sre-c-actor"), actorPolicy, ecPublicKeyPEM(t, key), scopes)
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

		t.Run("a narrowed delegation is refused whole, naming the subject token", func(t *testing.T) {
			run := offShadowEnforce(t, exchange("sr:a sr:b sr:c"))
			require.Equal(t, http.StatusOK, run.today["status"])
			assert.Equal(t, "sr:a sr:b", run.today["scope"], "precondition: today the scope the parent lacks is dropped")
			requireInvalidScope(t, run.enforced, `scope sr:c is not granted: the subject token's scopes must list it`)
			line := enforceLine(t, run.records)
			assert.Equal(t, "all_or_nothing", line["rule"])
			assert.Equal(t, []any{"sr:a", "sr:b"}, line["today_scopes"])
			assert.Equal(t, "refused", line["would"])
		})

		t.Run("a delegation that names no scope is issued none", func(t *testing.T) {
			run := offShadowEnforce(t, exchange(""))
			require.Equal(t, http.StatusBadRequest, run.today["status"])
			assert.Equal(t, "invalid_scope", run.today["error"], "precondition: today it is refused")

			requireNoScopes(t, run.enforced)
			claims := run.enforced["access_token.claims"].(map[string]any)
			assert.Equal(t, "token_exchange", claims["grant_type"])
			assert.NotEmpty(t, claims["act"], "the delegation is issued, with its actor chain")
			line := enforceLine(t, run.records)
			assert.Equal(t, "all_or_nothing", line["rule"])
			assert.Equal(t, "token_exchange", line["grant_type"])
			assert.Equal(t, "refused", line["today"])
			assert.Equal(t, "invalid_scope", line["today_code"])
			assert.Equal(t, "issued", line["would"])
			assert.Equal(t, []any{}, line["would_scopes"])
		})

		t.Run("a delegation the subject token cannot cover stays refused", func(t *testing.T) {
			run := offShadowEnforce(t, exchange("sr:c"))
			require.Equal(t, http.StatusBadRequest, run.today["status"])
			assert.Equal(t, "invalid_scope", run.today["error"])
			requireInvalidScope(t, run.enforced, `scope sr:c is not granted: the subject token's scopes must list it`)
			assert.Empty(t, run.records.lines(t), "already invalid_scope, and named: nothing to change but the description")
		})
	})

	t.Run("client_credentials narrowed by the identity's ceiling is refused whole", func(t *testing.T) {
		tn := newTenant(t, "")
		extID := uid("sre-c-cc")
		tn.register(t, extID, tn.policy(t, nil), "", []string{"sr:read"})
		client := registerOAuthClient(t, extID, []string{"sr:read", "sr:write"})
		run := offShadowEnforce(t, clientCredentialsRequest(tn, client, "sr:read sr:write"))
		require.Equal(t, http.StatusOK, run.today["status"])
		assert.Equal(t, "sr:read", run.today["scope"], "precondition: today the identity's ceiling narrows the request")
		requireInvalidScope(t, run.enforced, `scope sr:write is not granted: the identity's allowed_scopes must list it`)
		assert.Equal(t, "all_or_nothing", enforceLine(t, run.records)["rule"])
	})

	t.Run("api_key naming a scope the key does not hold is refused whole", func(t *testing.T) {
		tn := newTenant(t, "")
		identityID := registerIdentityWithPolicy(t, uid("sre-c-ak"), "", "", nil, tn.headers)
		run := offShadowEnforce(t, apiKeyRequest(apiKeyFor(t, tn, identityID, []string{"sr:read"}), "sr:read sr:admin"))
		require.Equal(t, http.StatusOK, run.today["status"])
		assert.Equal(t, "sr:read", run.today["scope"])
		requireInvalidScope(t, run.enforced, `scope sr:admin is not granted: the API key's scopes must list it`)
		assert.Equal(t, "all_or_nothing", enforceLine(t, run.records)["rule"])
	})

	t.Run("an authorization request the client's scopes narrow is refused at authorize", func(t *testing.T) {
		clientID := authCodeClient(t, []string{"sr:read"})
		const refusal = `scope sr:write is not granted: the client's registered scopes must list it`

		// The POST leg answers its callers in JSON.
		run := runModes(t, testZeroIDServer, func(t *testing.T) map[string]any {
			return authorizeOutcome(t, clientID, "sr:read sr:write")
		})
		require.Equal(t, http.StatusFound, run.today["status"])
		assert.Equal(t, []any{"sr:read"}, run.today["code"].(map[string]any)["scp"], "precondition: today the code is narrowed")
		requireInvalidScope(t, run.enforced, refusal)
		line := enforceLine(t, run.records)
		assert.Equal(t, "all_or_nothing", line["rule"])
		assert.Equal(t, "authorization_code", line["grant_type"])
		assert.Equal(t, []any{"sr:read"}, line["today_scopes"])
		assert.Equal(t, "refused", line["would"])

		// The browser leg (GET) is refused by redirect (RFC 6749 §4.1.2.1),
		// with the same code.
		setScopeRules(t, zeroid.ScopeRulesModeEnforce)
		records := captureScopeRules(t)
		getQuery, _ := authorizeGETQuery(t)
		getQuery.Set("client_id", clientID)
		getQuery.Set("scope", "sr:read sr:write")
		resp := getAuthorize(t, getQuery, principalHeaders())
		require.Equal(t, http.StatusFound, resp.StatusCode)
		loc, err := url.Parse(resp.Header.Get("Location"))
		_ = resp.Body.Close()
		require.NoError(t, err)
		assert.Empty(t, loc.Query().Get("code"))
		assert.Equal(t, "invalid_scope", loc.Query().Get("error"))
		assert.Equal(t, refusal, loc.Query().Get("error_description"))
		assert.Equal(t, "get-state-abc", loc.Query().Get("state"))
		line = enforceLine(t, records)
		assert.Equal(t, "all_or_nothing", line["rule"])
		assert.Equal(t, "refused", line["would"])
	})

	t.Run("a refresh a person's ceiling narrows is refused, and the refresh token survives", func(t *testing.T) {
		clientID := authCodeClient(t, []string{"pg:a", "pg:b"}, "refresh_token")
		user := uid("sre-c-p")
		families := refreshFamilies(t, clientID, user, []string{"pg:a", "pg:b"})
		grants := installPersonGrants(t, zeroid.PersonGrantModeEnforce, testZeroIDServer)
		grants.set(user, &zeroid.PersonGrant{Scopes: []string{"pg:a"}}, nil)

		run := refreshModes(t, clientID, families)
		require.Equal(t, http.StatusOK, run.today["status"])
		assert.Equal(t, "pg:a", run.today["scope"], "precondition: today the person's ceiling narrows the refresh")
		requireInvalidScope(t, run.enforced, `scope pg:b is not granted: the person's scope ceiling must list it`)
		line := enforceLine(t, run.records)
		assert.Equal(t, "all_or_nothing", line["rule"])
		assert.Equal(t, "refresh_token", line["grant_type"])

		grants.set(user, &zeroid.PersonGrant{Scopes: []string{"pg:a", "pg:b"}}, nil)
		again := refreshOutcome(t, clientID, families[2])
		require.Equal(t, http.StatusOK, again["status"], "once the role is restored the same refresh token works: %v", again)
		assert.Equal(t, "pg:a pg:b", again["scope"])
	})

	t.Run("an ID-JAG a person's ceiling narrows is refused whole", func(t *testing.T) {
		f := newPersonGrantFederation(t)
		grants := installPersonGrants(t, zeroid.PersonGrantModeEnforce, f.srv)
		user := uid("sre-c-jag")
		grants.set(user, &zeroid.PersonGrant{Scopes: []string{"pg:a"}}, nil)
		run := runModes(t, f.srv, func(t *testing.T) map[string]any {
			return idJAGOutcome(t, f, user, "pg:a pg:b")
		})
		require.Equal(t, http.StatusOK, run.today["status"], "%v", run.today)
		assert.Equal(t, "pg:a", run.today["scope"], "precondition: today the person's ceiling narrows the ID-JAG's scope")
		requireInvalidScope(t, run.enforced, `scope pg:b is not granted: the person's scope ceiling must list it`)
		line := enforceLine(t, run.records)
		assert.Equal(t, "all_or_nothing", line["rule"])
		assert.Equal(t, "id_jag", line["grant_type"])
	})

	t.Run("a CIBA push mint a person's ceiling narrows is refused, as access_denied", func(t *testing.T) {
		grants := installPersonGrants(t, zeroid.PersonGrantModeEnforce, testZeroIDServer)
		push := newPushHarness(t, []string{"pg:a", "pg:b"})
		user := uid("sre-c-push")
		grants.set(user, &zeroid.PersonGrant{Scopes: []string{"pg:a"}}, nil)
		run := runModes(t, testZeroIDServer, func(t *testing.T) map[string]any {
			return push.approve(t, user, "pg:a pg:b")
		})
		assert.Equal(t, "pg:a", run.today["scope"], "precondition: today the narrowed token is delivered; %v", run.today)
		assert.Equal(t, map[string]any{
			"error":             "access_denied",
			"error_description": `scope pg:b is not granted: the person's scope ceiling must list it`,
		}, run.enforced, "CIBA Core §12 defines no invalid_scope, so a push client is sent access_denied")
		line := enforceLine(t, run.records)
		assert.Equal(t, "all_or_nothing", line["rule"])
		assert.Equal(t, zeroidGrantTypeCIBA, line["grant_type"])
		assert.Equal(t, "refused", line["would"])
	})
}

// idJAGOutcome redeems a fresh ID-JAG for user naming scope at f.
func idJAGOutcome(t *testing.T, f *personGrantFederation, user, scope string) map[string]any {
	t.Helper()
	now := time.Now()
	idjag := f.upstream.SignTokenWithTyp(t, idJAGTyp, map[string]any{
		"iss": f.iss, "aud": f.aud, "sub": user,
		"client_id": f.jagClient.ClientID, "jti": uid("sre-jti"),
		"resource": "https://mcp.person-grant.test",
		"scope":    scope,
		"iat":      now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	})
	return federationOutcome(t, f.url, map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:jwt-bearer",
		"assertion":     idjag,
		"account_id":    f.cfg.AccountID,
		"project_id":    f.cfg.ProjectID,
		"client_id":     f.jagClient.ClientID,
		"client_secret": f.jagClient.ClientSecret,
	})
}

// pushHarness is a CIBA push-mode client whose notifications are captured.
type pushHarness struct {
	clientID, endpoint string
	capt               *capturingRoundTripper
}

// newPushHarness registers a push-mode client through the admin API, whose
// registered scopes are a listing, with scopes, and captures what is posted
// to its notification endpoint, dispatching synchronously.
func newPushHarness(t *testing.T, scopes []string) *pushHarness {
	t.Helper()
	p := &pushHarness{clientID: uid("sre-push"), capt: newCapturingRoundTripper()}
	p.endpoint = "https://push.example.test/" + p.clientID
	testZeroIDServer.SetBackchannelPingTransport(p.capt)
	testZeroIDServer.SetBackchannelPingDispatchSync(true)
	t.Cleanup(func() {
		testZeroIDServer.SetBackchannelPingDispatchSync(false)
		testZeroIDServer.SetBackchannelPingTransport(nil)
	})
	resp := post(t, adminPath("/oauth/clients"), map[string]any{
		"client_id":                       p.clientID,
		"name":                            p.clientID,
		"grant_types":                     []string{"client_credentials"},
		"redirect_uris":                   []string{testRedirectURI},
		"client_notification_endpoint":    p.endpoint,
		"backchannel_token_delivery_mode": "push",
		"scopes":                          scopes,
	}, nil)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	_ = resp.Body.Close()
	return p
}

// approve starts a push-mode request for user naming scope, approves it, and
// returns the one notification its client is sent, less what differs on every
// request: the auth_req_id, and the token's per-mint claims.
func (p *pushHarness) approve(t *testing.T, user, scope string) map[string]any {
	t.Helper()
	before := len(p.capt.requests())
	resp := post(t, "/oauth2/bc-authorize", map[string]any{
		"client_id": p.clientID, "account_id": testAccountID, "project_id": testProjectID,
		"login_hint": user, "scope": scope, "client_notification_token": "push-bearer",
	}, cibaInitiatorHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	id := decode(t, resp)["auth_req_id"].(string)
	approveInTenant(t, id, user, adminHeaders())

	var delivered []map[string]any
	for _, cb := range p.capt.requests()[before:] {
		if cb.URL != p.endpoint {
			continue
		}
		var payload map[string]any
		require.NoError(t, json.Unmarshal([]byte(cb.Body), &payload))
		delivered = append(delivered, payload)
	}
	require.Len(t, delivered, 1, "exactly one notification is sent")
	out := delivered[0]
	assert.Equal(t, id, out["auth_req_id"])
	delete(out, "auth_req_id")
	if token, ok := out["access_token"].(string); ok {
		claims := decodeJWTPayload(t, token)
		for _, c := range append([]string{"authorization_details"}, perMintClaims...) {
			delete(claims, c)
		}
		out["access_token"] = claims
	}
	return out
}

// TestScopeRulesEnforce_OneCode (rule D): every scope refusal at the token
// endpoint answers invalid_scope, naming the first offending scope and the
// ceiling that must list it. A refusal that is not about scopes keeps its code,
// and a push client keeps CIBA Core §12's codes.
func TestScopeRulesEnforce_OneCode(t *testing.T) {
	brokerExchange := func(tn hrdTenant, applicationID, scope string) func(t *testing.T) *http.Response {
		user := uid("sre-d-user")
		subject := personToken(t, tn.account, tn.project, user)
		return func(t *testing.T) *http.Response {
			return post(t, "/oauth2/token", map[string]any{
				"grant_type":     "urn:ietf:params:oauth:grant-type:token-exchange",
				"subject_token":  subject,
				"account_id":     tn.account,
				"project_id":     tn.project,
				"user_id":        user,
				"application_id": applicationID,
				"scope":          scope,
			}, map[string]string{testTrustedServiceHeader: "trusted-service"})
		}
	}

	t.Run("policy_violation answers invalid_scope", func(t *testing.T) {
		tn := newTenant(t, "")
		identityID := registerIdentityWithPolicy(t, uid("sre-d-pv"), tn.policy(t, []string{"sr:read"}), "", nil, tn.headers)
		run := offShadowEnforce(t, brokerExchange(tn, identityID, "sr:read sr:write"))
		require.Equal(t, http.StatusBadRequest, run.today["status"])
		assert.Equal(t, "policy_violation", run.today["error"], "precondition")
		requireInvalidScope(t, run.enforced, `scope sr:write is not granted: the identity's credential policy's allowed_scopes must list it`)
		line := enforceLine(t, run.records)
		assert.Equal(t, "one_code", line["rule"])
		assert.Equal(t, "policy_violation", line["today_code"])
		assert.Equal(t, "invalid_scope", line["would_code"])
	})

	t.Run("insufficient_scope answers invalid_scope", func(t *testing.T) {
		tn := newTenant(t, "")
		identityID := registerIdentityWithPolicy(t, uid("sre-d-is"), "", "", []string{"sr:read"}, tn.headers)
		run := offShadowEnforce(t, brokerExchange(tn, identityID, "sr:read sr:write"))
		require.Equal(t, http.StatusBadRequest, run.today["status"])
		assert.Equal(t, "insufficient_scope", run.today["error"], "precondition")
		requireInvalidScope(t, run.enforced, `scope sr:write is not granted: the identity's allowed_scopes must list it`)
		assert.Equal(t, "insufficient_scope", enforceLine(t, run.records)["today_code"])
	})

	t.Run("a person ceiling's invalid_grant answers invalid_scope", func(t *testing.T) {
		clientID := authCodeClient(t, []string{"pg:a", "pg:b"})
		grants := installPersonGrants(t, zeroid.PersonGrantModeEnforce, testZeroIDServer)
		user := uid("sre-d-person")
		grants.set(user, &zeroid.PersonGrant{Scopes: []string{"pg:c"}}, nil)
		run := offShadowEnforce(t, redeemCode(clientID, user, []string{"pg:a", "pg:b"}))
		require.Equal(t, http.StatusBadRequest, run.today["status"])
		assert.Equal(t, "invalid_grant", run.today["error"], "precondition")
		requireInvalidScope(t, run.enforced, `scope pg:a is not granted: the person's scope ceiling must list it`)
		line := enforceLine(t, run.records)
		assert.Equal(t, "one_code", line["rule"])
		assert.Equal(t, "invalid_grant", line["today_code"])
	})

	t.Run("an invalid_scope refusal keeps its code and names the scope", func(t *testing.T) {
		f := newPersonGrantFederation(t)
		grants := installPersonGrants(t, zeroid.PersonGrantModeEnforce, f.srv)
		user := uid("sre-d-jag")
		grants.set(user, &zeroid.PersonGrant{Scopes: []string{"pg:c"}}, nil)
		run := runModes(t, f.srv, func(t *testing.T) map[string]any {
			return idJAGOutcome(t, f, user, "pg:a pg:b")
		})
		require.Equal(t, http.StatusBadRequest, run.today["status"])
		assert.Equal(t, "invalid_scope", run.today["error"])
		assert.Equal(t, "none of the requested scopes is granted to this user", run.today["error_description"])
		requireInvalidScope(t, run.enforced, `scope pg:a is not granted: the person's scope ceiling must list it`)
		assert.Empty(t, run.records.lines(t), "the code is unchanged, so no rule records a change")
	})

	t.Run("a refusal not about scopes keeps its code", func(t *testing.T) {
		tn := newTenant(t, "")
		policyID := tn.policyWith(t, nil, map[string]any{"max_ttl_seconds": 300, "allowed_grant_types": []string{"token_exchange"}})
		identityID := registerIdentityWithPolicy(t, uid("sre-d-ttl"), policyID, "", nil, tn.headers)
		run := offShadowEnforce(t, brokerExchange(tn, identityID, "sr:read"))
		require.Equal(t, http.StatusBadRequest, run.today["status"])
		assert.Equal(t, "policy_violation", run.today["error"], "precondition: the lifetime axis refuses")
		assert.Equal(t, run.today, run.enforced)
		assert.Empty(t, run.records.lines(t))

		client := registerOAuthClient(t, uid("sre-d-auth"), []string{"sr:read"})
		run = offShadowEnforce(t, clientCredentialsRequest(tn, oauthClientResp{ClientID: client.ClientID, ClientSecret: "wrong"}, "sr:admin"))
		assert.Equal(t, "invalid_client", run.enforced["error"])
		assert.Equal(t, run.today, run.enforced)
	})

	t.Run("a push client keeps access_denied for a person-ceiling refusal", func(t *testing.T) {
		grants := installPersonGrants(t, zeroid.PersonGrantModeEnforce, testZeroIDServer)
		push := newPushHarness(t, []string{"pg:a"})
		user := uid("sre-d-push")
		grants.set(user, &zeroid.PersonGrant{Scopes: []string{"pg:c"}}, nil)
		require.NoError(t, testZeroIDServer.SetScopeRulesMode(zeroid.ScopeRulesModeOff))
		t.Cleanup(func() { require.NoError(t, testZeroIDServer.SetScopeRulesMode(zeroid.ScopeRulesModeOff)) })

		today := push.approve(t, user, "pg:a")
		assert.Equal(t, map[string]any{
			"error":             "access_denied",
			"error_description": "none of the requested scopes is granted to this user",
		}, today, "precondition")

		require.NoError(t, testZeroIDServer.SetScopeRulesMode(zeroid.ScopeRulesModeShadow))
		shadowRecords := captureScopeRules(t)
		assert.Equal(t, today, push.approve(t, user, "pg:a"))
		assert.Equal(t, "one_code", scopeRuleLine(t, shadowRecords)["rule"], "shadow counts rule D for a push client")

		require.NoError(t, testZeroIDServer.SetScopeRulesMode(zeroid.ScopeRulesModeEnforce))
		records := captureScopeRules(t)
		assert.Equal(t, today, push.approve(t, user, "pg:a"), "CIBA Core §12 defines no invalid_scope: the push answer is unchanged")
		assert.Empty(t, records.lines(t), "enforce makes no change here, so records none")
	})
}

// TestScopeRulesEnforce_FederatedClientCredentials: client_credentials
// authenticated by a trusted workload issuer's assertion, with no registered
// client, under rules A and C. The agent's credential policy lists
// tools:read.
func TestScopeRulesEnforce_FederatedClientCredentials(t *testing.T) {
	w := newWorkloadFed(t)
	request := func(scope string) func(t *testing.T) map[string]any {
		return func(t *testing.T) map[string]any {
			return federationOutcome(t, w.f.http.URL, map[string]any{
				"grant_type":            "client_credentials",
				"scope":                 scope,
				"client_assertion":      w.assertion(t, nil),
				"client_assertion_type": clientAssertionType,
			})
		}
	}

	t.Run("rule A: an omitted request is issued none, not the policy's list", func(t *testing.T) {
		run := runModes(t, w.f.srv, request(""))
		require.Equal(t, http.StatusOK, run.today["status"], "%v", run.today)
		assert.Equal(t, "tools:read", run.today["scope"], "precondition: today an omitted scope gets the policy's list")
		requireNoScopes(t, run.enforced)
		line := enforceLine(t, run.records)
		assert.Equal(t, "omitted_request", line["rule"])
		assert.Equal(t, "client_credentials", line["grant_type"])
		assert.Equal(t, w.agent, line["identity_id"])
	})

	t.Run("rule C: a request the policy narrows is refused whole", func(t *testing.T) {
		run := runModes(t, w.f.srv, request("tools:read tools:write"))
		require.Equal(t, http.StatusOK, run.today["status"], "%v", run.today)
		assert.Equal(t, "tools:read", run.today["scope"], "precondition: today the policy narrows the request")
		requireInvalidScope(t, run.enforced, `scope tools:write is not granted: the identity's credential policy's allowed_scopes must list it`)
		assert.Equal(t, "all_or_nothing", enforceLine(t, run.records)["rule"])
	})
}

// TestScopeRulesEnforce_NoChange: a request every stricter rule answers the
// same way is issued exactly as with the mode off, and records nothing.
func TestScopeRulesEnforce_NoChange(t *testing.T) {
	tn := newTenant(t, "")
	extID := uid("sre-none")
	tn.register(t, extID, tn.policy(t, nil), "", nil)
	client := registerOAuthClient(t, extID, []string{"sr:read", "sr:write"})
	run := offShadowEnforce(t, clientCredentialsRequest(tn, client, "sr:read"))
	require.Equal(t, http.StatusOK, run.today["status"])
	assert.Equal(t, run.today, run.enforced, "named, listed by the admin-registered client, not narrowed")
	assert.Empty(t, run.records.lines(t))
	assert.Empty(t, run.records.counts(t))
}

// TestScopeRulesEnforce_ModeAtRuntime: Server.SetScopeRulesMode switches to
// enforce and back without a restart, and refuses an unknown mode.
func TestScopeRulesEnforce_ModeAtRuntime(t *testing.T) {
	tn := newTenant(t, "")
	reg := registerAgentInTenant(t, uid("sre-rt"), tn.headers)
	request := apiKeyRequest(reg.APIKey, "sr:manage")
	status := func() int {
		resp := request(t)
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	setScopeRules(t, zeroid.ScopeRulesModeEnforce)
	assert.Equal(t, http.StatusBadRequest, status())
	assert.Error(t, testZeroIDServer.SetScopeRulesMode("Enforce"))
	assert.Equal(t, http.StatusBadRequest, status(), "a refused mode leaves enforce on")
	require.NoError(t, testZeroIDServer.SetScopeRulesMode(zeroid.ScopeRulesModeShadow))
	assert.Equal(t, http.StatusOK, status(), "shadow only counts")
	require.NoError(t, testZeroIDServer.SetScopeRulesMode(zeroid.ScopeRulesModeOff))
	assert.Equal(t, http.StatusOK, status())
}

// The descriptions name scopes without quotes: RFC 6749 §5.2 keeps '"' and
// '\' out of error_description.
func TestScopeRulesEnforce_DescriptionCharset(t *testing.T) {
	tn := newTenant(t, "")
	reg := registerAgentInTenant(t, uid("sre-cs"), tn.headers)
	setScopeRules(t, zeroid.ScopeRulesModeEnforce)
	outcome := tokenOutcome(t, apiKeyRequest(reg.APIKey, "sr:manage")(t))
	desc, _ := outcome["error_description"].(string)
	require.NotEmpty(t, desc)
	for _, r := range desc {
		assert.True(t, r == 0x20 || r == 0x21 || (r >= 0x23 && r <= 0x5b) || (r >= 0x5d && r <= 0x7e),
			"error_description character %q is outside RFC 6749 §5.2's set: %s", r, desc)
	}
	assert.False(t, strings.ContainsAny(desc, `"\`))
}

// TestScopeRulesEnforce_ReservedScopes: reserved scopes stay under their own
// rules in enforce exactly as in shadow. Rule A keeps a key's reserved scope,
// rules B and C never judge one, and a refusal by the reserved-scope rules
// keeps its own answer.
func TestScopeRulesEnforce_ReservedScopes(t *testing.T) {
	status, _, key := createProductKey(t, "test-user", []string{"data:read", testReservedScope}, true)
	require.Equal(t, http.StatusCreated, status)

	t.Run("an omitted request keeps the key's scopes, reserved one included", func(t *testing.T) {
		run := offShadowEnforce(t, apiKeyRequest(key, ""))
		require.Equal(t, http.StatusOK, run.today["status"])
		assert.Equal(t, "data:read "+testReservedScope, run.today["scope"])
		assert.Equal(t, run.today, run.enforced)
		assert.Empty(t, run.records.lines(t))
	})

	t.Run("a request naming the reserved scope is issued it", func(t *testing.T) {
		run := offShadowEnforce(t, apiKeyRequest(key, testReservedScope))
		require.Equal(t, http.StatusOK, run.today["status"])
		assert.Equal(t, run.today, run.enforced)
		assert.Empty(t, run.records.lines(t))
	})

	t.Run("a key that does not list it keeps the reserved-scope rules' answer", func(t *testing.T) {
		status, _, unlisted := createProductKey(t, "test-user", nil, false)
		require.Equal(t, http.StatusCreated, status)
		run := offShadowEnforce(t, apiKeyRequest(unlisted, testReservedScope))
		require.Equal(t, http.StatusBadRequest, run.today["status"])
		assert.Equal(t, run.today, run.enforced)
		assert.Empty(t, run.records.lines(t))
	})

	t.Run("an exchange refused for naming the reserved scope keeps its code", func(t *testing.T) {
		code, body := exchangeKey(t, key, "")
		require.Equal(t, http.StatusOK, code, "%v", body)
		root := body["access_token"].(string)
		tn := hrdTenant{account: testAccountID, project: testProjectID, headers: adminHeaders()}
		actorScopes := []string{"data:read", testReservedScope}
		policyID := tn.policyWith(t, actorScopes, map[string]any{"max_ttl_seconds": 30})
		k := generateKey(t)
		wimse := tn.register(t, uid("sre-rs-actor"), policyID, ecPublicKeyPEM(t, k), actorScopes)
		run := offShadowEnforce(t, func(t *testing.T) *http.Response {
			return post(t, "/oauth2/token", map[string]any{
				"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
				"subject_token": root,
				"actor_token":   buildAssertion(t, k, wimse),
				"scope":         testReservedScope,
			}, nil)
		})
		require.Equal(t, http.StatusBadRequest, run.today["status"])
		assert.Equal(t, "insufficient_scope", run.today["error"])
		assert.Equal(t, run.today, run.enforced, "the reserved-scope rules refused it, not a ceiling")
		assert.Empty(t, run.records.lines(t))
	})
}

// TestScopeRulesEnforce_InternalServiceGrants: the on-behalf exchange and the
// asserted-tenant grant are exempt in enforce exactly as in shadow: their
// answers are unchanged and nothing is recorded.
func TestScopeRulesEnforce_InternalServiceGrants(t *testing.T) {
	gw := gateway(t)
	jb := jobs(t)
	tn := newTenant(t, "")
	subject := brokerSession(t, testAccountID, testProjectID, uid("sre-obo"), nil)["access_token"].(string)

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
			run := offShadowEnforce(t, func(t *testing.T) *http.Response {
				return post(t, "/oauth2/token", tc.client.auth(t, tc.body()), nil)
			})
			require.Equal(t, http.StatusOK, run.today["status"])
			assert.NotContains(t, run.enforced["access_token.claims"], "scopes")
			assert.Equal(t, http.StatusOK, run.enforced["status"])
			assert.Empty(t, run.records.lines(t))

			run = offShadowEnforce(t, func(t *testing.T) *http.Response {
				body := tc.body()
				body["scope"] = "sr:read"
				return post(t, "/oauth2/token", tc.client.auth(t, body), nil)
			})
			require.Equal(t, http.StatusBadRequest, run.today["status"])
			assert.Equal(t, run.today, run.enforced)
			assert.Empty(t, run.records.lines(t))
		})
	}
}
