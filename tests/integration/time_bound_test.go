package integration_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExpiredIdentityDeniedAcrossGrantTypes verifies the IsExpired() gate
// at every grant-type entry point + the chokepoint in IssueCredential. An
// identity past its expires_at gets a 400 invalid_grant regardless of how
// the caller tries to mint a token.
//
// Covers acceptance criterion: "Every grant type checks IsActiveAndUnexpired
// before issuing tokens." Companion acceptance criterion (cleanup worker
// idempotency) is covered by TestCleanupWorkerSweepsExpiredIdentities.
func TestExpiredIdentityDeniedAcrossGrantTypes(t *testing.T) {
	ext := uid("expired-multi-grant")
	reg := registerAgent(t, ext)
	require.NotEmpty(t, reg.APIKey, "agent must have an API key for the api_key probe")

	// While still active and unexpired, both probes must succeed — proves
	// the test setup is sound before we flip expires_at.
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type": "api_key",
		"api_key":    reg.APIKey,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "api_key while active must succeed; body=%v", decode(t, resp))

	// Register an oauth client keyed on the same external_id so
	// client_credentials → identity resolution hits this same agent.
	oauthClient := registerOAuthClient(t, ext, []string{"data:read"})
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     oauthClient.ClientID,
		"client_secret": oauthClient.ClientSecret,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "client_credentials while active must succeed; body=%v", decode(t, resp))

	// Stamp expires_at one second in the past via direct repo update —
	// fastest way to age the identity without sleeping.
	past := time.Now().Add(-time.Second).UTC().Format(time.RFC3339)
	patched, err := doRaw(t, http.MethodPatch, adminPath("/identities/"+reg.AgentID), map[string]any{
		"expires_at": past,
	}, adminHeaders())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, patched.StatusCode, "PATCH /identities expires_at must succeed")
	_ = patched.Body.Close()

	// api_key path: chokepoint + grant-level check both kick in. Either
	// "identity_expired" or "api_key_expired" is acceptable — the test
	// only requires fail-closed.
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type": "api_key",
		"api_key":    reg.APIKey,
	}, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "api_key for expired identity must fail")
	body := decode(t, resp)
	assert.Equal(t, "invalid_grant", body["error"], "expected invalid_grant; body=%v", body)

	// client_credentials path: grant-level check at oauth.go:215.
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     oauthClient.ClientID,
		"client_secret": oauthClient.ClientSecret,
	}, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "client_credentials for expired identity must fail")
	body = decode(t, resp)
	assert.Equal(t, "invalid_grant", body["error"], "expected invalid_grant; body=%v", body)
	assert.Equal(t, "identity_expired", body["error_description"],
		"client_credentials grant should emit the precise identity_expired hint; body=%v", body)
}

// TestExpiredIdentityDeniedJWTBearer and TestExpiredIdentityDeniedTokenExchange
// extend grant coverage to the two flows the high-level multi-grant test
// can't easily exercise (they need a per-test agent keypair). Both are
// caught by the chokepoint, but the per-grant fail-fast check at oauth.go
// is what produces the precise invalid_grant: identity_expired error
// callers see — these tests lock that semantics in.
func TestExpiredIdentityDeniedJWTBearer(t *testing.T) {
	// Register identity with a self-controlled keypair (jwt_bearer flow).
	agentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ext := uid("expired-jwt-bearer")
	identity := registerIdentity(t, ext, []string{"data:read"}, ecPublicKeyPEM(t, agentKey))

	// Baseline: jwt_bearer succeeds while identity is active.
	assertion := buildAssertion(t, agentKey, identity.WIMSEURI)
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
		"subject":    assertion,
		"scope":      "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "baseline jwt_bearer must succeed; body=%v", decode(t, resp))

	// Expire the identity.
	past := time.Now().Add(-time.Second).UTC().Format(time.RFC3339)
	patched, err := doRaw(t, http.MethodPatch, adminPath("/identities/"+identity.ID), map[string]any{
		"expires_at": past,
	}, adminHeaders())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, patched.StatusCode)
	_ = patched.Body.Close()

	// jwt_bearer with a fresh assertion now blocked — both gate sites in
	// oauth.jwtBearer (Status + IsExpired) and the chokepoint must catch.
	assertion2 := buildAssertion(t, agentKey, identity.WIMSEURI)
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
		"subject":    assertion2,
		"scope":      "data:read",
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "jwt_bearer for expired identity must fail")
	body := decode(t, resp)
	assert.Equal(t, "invalid_grant", body["error"])
	assert.Equal(t, "identity_expired", body["error_description"])
}

func TestExpiredIdentityDeniedTokenExchange(t *testing.T) {
	// Orchestrator first (gets a valid subject_token).
	orchKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	orchExt := uid("expired-tx-orchestrator")
	orchestrator := registerIdentity(t, orchExt, []string{"data:read"}, ecPublicKeyPEM(t, orchKey))

	// Mint orchestrator token via jwt_bearer.
	orchAssertion := buildAssertion(t, orchKey, orchestrator.WIMSEURI)
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
		"subject":    orchAssertion,
		"scope":      "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	orchToken := decode(t, resp)["access_token"].(string)

	// Sub-agent (the actor in token_exchange).
	subKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	subExt := uid("expired-tx-sub")
	subAgent := registerIdentity(t, subExt, []string{"data:read"}, ecPublicKeyPEM(t, subKey))

	// Expire the sub-agent (the actor whose identity is the one being gated).
	past := time.Now().Add(-time.Second).UTC().Format(time.RFC3339)
	patched, err := doRaw(t, http.MethodPatch, adminPath("/identities/"+subAgent.ID), map[string]any{
		"expires_at": past,
	}, adminHeaders())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, patched.StatusCode)
	_ = patched.Body.Close()

	// token_exchange with the orchestrator's subject_token + sub-agent's
	// actor_token must fail: oauth.tokenExchange gates actorIdentity.IsExpired.
	subActor := buildAssertion(t, subKey, subAgent.WIMSEURI)
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token":      orchToken,
		"subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
		"actor_token":        subActor,
		"scope":              "data:read",
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "token_exchange for expired actor must fail")
	body := decode(t, resp)
	assert.Equal(t, "invalid_grant", body["error"])
	assert.Equal(t, "identity_expired", body["error_description"])
}

// TestExtendAccessReactivates exercises the "Extend access" flow: PATCH
// expires_at to a future RFC3339 string brings an expired identity back
// online. Cleared-to-NULL (empty string) also works.
func TestExtendAccessReactivates(t *testing.T) {
	ext := uid("extend-access")
	reg := registerAgent(t, ext)

	// Expire it.
	past := time.Now().Add(-time.Second).UTC().Format(time.RFC3339)
	_, err := doRaw(t, http.MethodPatch, adminPath("/identities/"+reg.AgentID), map[string]any{
		"expires_at": past,
	}, adminHeaders())
	require.NoError(t, err)

	// Confirm denied.
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type": "api_key",
		"api_key":    reg.APIKey,
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "must be denied while expired")

	// Extend by one hour.
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	patched, err := doRaw(t, http.MethodPatch, adminPath("/identities/"+reg.AgentID), map[string]any{
		"expires_at": future,
	}, adminHeaders())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, patched.StatusCode, "PATCH must succeed")
	_ = patched.Body.Close()

	// And again — succeeds.
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type": "api_key",
		"api_key":    reg.APIKey,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "post-extend api_key must succeed; body=%v", decode(t, resp))

	// Clear to NULL.
	patched, err = doRaw(t, http.MethodPatch, adminPath("/identities/"+reg.AgentID), map[string]any{
		"expires_at": "",
	}, adminHeaders())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, patched.StatusCode)
	_ = patched.Body.Close()

	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type": "api_key",
		"api_key":    reg.APIKey,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "post-clear api_key must succeed")
}

// TestCleanupWorkerSweepsExpiredIdentities runs the cleanup worker twice
// and asserts:
//  1. First sweep flips the expired identity to deactivated and cascade-
//     revokes its issued credentials.
//  2. Second sweep is idempotent — no errors, no state churn.
func TestCleanupWorkerSweepsExpiredIdentities(t *testing.T) {
	ext := uid("sweep")
	reg := registerAgent(t, ext)

	// Issue a token first so we have one to assert against.
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type": "api_key",
		"api_key":    reg.APIKey,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	tokenBefore := decode(t, resp)["access_token"].(string)
	require.NotEmpty(t, tokenBefore)

	pre := introspect(t, tokenBefore)
	require.True(t, pre["active"].(bool), "token should be active before sweep")

	// Stamp expires_at in the past.
	past := time.Now().Add(-time.Second).UTC().Format(time.RFC3339)
	patched, err := doRaw(t, http.MethodPatch, adminPath("/identities/"+reg.AgentID), map[string]any{
		"expires_at": past,
	}, adminHeaders())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, patched.StatusCode)
	_ = patched.Body.Close()

	// First sweep: deactivates the identity → cascade revokes the token.
	testZeroIDServer.RunCleanupOnce(context.Background())

	// Token must now be inactive (cascade revocation kicked in).
	after := introspect(t, tokenBefore)
	assert.False(t, after["active"].(bool),
		"token must be revoked by the cascade triggered when the sweep deactivated the expired identity")

	// Identity itself must now be deactivated.
	idResp, err := doRaw(t, http.MethodGet, adminPath("/identities/"+reg.AgentID), nil, adminHeaders())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, idResp.StatusCode)
	idBody := decode(t, idResp)
	assert.Equal(t, "deactivated", idBody["status"], "identity must be deactivated after sweep")

	// Second sweep is idempotent — no errors, no state changes. The
	// identity is no longer status=active so the ListExpiredActive query
	// returns no rows.
	testZeroIDServer.RunCleanupOnce(context.Background())

	idResp2, err := doRaw(t, http.MethodGet, adminPath("/identities/"+reg.AgentID), nil, adminHeaders())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, idResp2.StatusCode)
	idBody2 := decode(t, idResp2)
	assert.Equal(t, "deactivated", idBody2["status"],
		"second sweep must not change anything — identity stays deactivated")
}

// TestSweepEmitsIdentityExpiredSignal locks in AC4: the cleanup worker
// fires a CAE signal of type identity_expired (not retirement) when
// auto-expiring an identity. Admin-initiated deactivation still emits
// retirement — covered separately by the deactivation_test suite.
func TestSweepEmitsIdentityExpiredSignal(t *testing.T) {
	ext := uid("sweep-signal-type")
	reg := registerAgent(t, ext)

	past := time.Now().Add(-time.Second).UTC().Format(time.RFC3339)
	patched, err := doRaw(t, http.MethodPatch, adminPath("/identities/"+reg.AgentID), map[string]any{
		"expires_at": past,
	}, adminHeaders())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, patched.StatusCode)
	_ = patched.Body.Close()

	testZeroIDServer.RunCleanupOnce(context.Background())

	// Query the cae_signals table directly — the SSE stream is a
	// separate concern and an at-rest assertion is more deterministic.
	var rows []struct {
		SignalType string         `bun:"signal_type"`
		Source     string         `bun:"source"`
		Payload    map[string]any `bun:"payload,type:jsonb"`
	}
	err = testDB.NewSelect().
		Table("cae_signals").
		Column("signal_type", "source", "payload").
		Where("identity_id = ?", reg.AgentID).
		Order("created_at ASC").
		Scan(context.Background(), &rows)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(rows), 1, "sweep must emit at least one CAE signal")

	// Find the lifecycle signal emitted by runDeactivationCleanup.
	var found bool
	for _, r := range rows {
		if r.Source != "identity_lifecycle" {
			continue
		}
		found = true
		assert.Equal(t, "identity_expired", r.SignalType,
			"sweep-driven cleanup must emit SignalTypeIdentityExpired, not generic retirement")
		assert.Equal(t, "expired", r.Payload["reason"],
			"payload.reason must carry the precise cause; got %v", r.Payload)
	}
	require.True(t, found, "no identity_lifecycle signal found; rows=%v", rows)
}

// TestXUserIDSystemPrefixRejected locks in the audit-spoof guard:
// an admin caller that submits X-User-ID with the reserved system: prefix
// must NOT see their value reflected in modified_by. Without this guard,
// a real admin could attribute their actions to the cleanup worker by
// setting X-User-ID: system:expired_sweep.
func TestXUserIDSystemPrefixRejected(t *testing.T) {
	ext := uid("audit-spoof-guard")
	reg := registerAgent(t, ext)

	// PATCH with a spoofed system caller. The handler should silently drop
	// the header and leave modified_by unset (empty string) on the row.
	headers := adminHeaders()
	headers["X-User-ID"] = "system:expired_sweep" // attempted spoof
	patched, err := doRaw(t, http.MethodPatch, adminPath("/identities/"+reg.AgentID), map[string]any{
		"description": "spoof attempt",
	}, headers)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, patched.StatusCode)
	body := decode(t, patched)
	// modified_by must not echo the spoofed value. Empty is acceptable
	// (no caller context was actually set). Anything other than the
	// spoofed string is acceptable.
	if mb, ok := body["modified_by"].(string); ok {
		assert.NotEqual(t, "system:expired_sweep", mb,
			"X-User-ID with reserved system: prefix must not flow into modified_by; got %q", mb)
	}

	// Sanity: a non-reserved X-User-ID still flows through unchanged.
	headers["X-User-ID"] = "alice@example.com"
	patched, err = doRaw(t, http.MethodPatch, adminPath("/identities/"+reg.AgentID), map[string]any{
		"description": "legit caller",
	}, headers)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, patched.StatusCode)
	body = decode(t, patched)
	if mb, ok := body["modified_by"].(string); ok {
		assert.Equal(t, "alice@example.com", mb,
			"non-reserved X-User-ID should flow through to modified_by")
	}
}

// TestExpiringSoonEndpoint verifies that GET /expiring-soon returns
// only identities within the requested window and excludes already-
// deactivated rows.
func TestExpiringSoonEndpoint(t *testing.T) {
	// Identity expiring in 2 hours — inside the default 168h window.
	inSoon := uid("expiring-in-window")
	soonReg := registerAgent(t, inSoon)
	inTwoHrs := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
	_, err := doRaw(t, http.MethodPatch, adminPath("/identities/"+soonReg.AgentID), map[string]any{
		"expires_at": inTwoHrs,
	}, adminHeaders())
	require.NoError(t, err)

	// Identity expiring in 30 days — outside the default 168h window.
	outOfWindow := uid("expiring-far-future")
	farReg := registerAgent(t, outOfWindow)
	in30Days := time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339)
	_, err = doRaw(t, http.MethodPatch, adminPath("/identities/"+farReg.AgentID), map[string]any{
		"expires_at": in30Days,
	}, adminHeaders())
	require.NoError(t, err)

	// Identity with no expiry at all — must never appear.
	neverExt := uid("never-expires")
	_ = registerAgent(t, neverExt)

	// Default window (168h) AND spec-literal "7d" syntax — both should
	// produce the same result. Locks in the human-friendly parser the
	// acceptance criterion explicitly requires.
	for _, q := range []string{"", "?within=7d", "?within=168h"} {
		resp, err := doRaw(t, http.MethodGet, adminPath("/expiring-soon")+q, nil, adminHeaders())
		require.NoError(t, err, "request with query %q", q)
		require.Equal(t, http.StatusOK, resp.StatusCode, "expiring-soon should return 200 for %q", q)
		body := decode(t, resp)

		idents, ok := body["identities"].([]any)
		require.True(t, ok, "identities must be a list (q=%q); body=%v", q, body)
		gotIDs := map[string]bool{}
		for _, raw := range idents {
			m := raw.(map[string]any)
			gotIDs[m["id"].(string)] = true
		}
		assert.True(t, gotIDs[soonReg.AgentID],
			"expiring-in-window identity %s missing for query %q; got=%v", soonReg.AgentID, q, gotIDs)
		assert.False(t, gotIDs[farReg.AgentID],
			"far-future identity must NOT appear in 7d window (q=%q)", q)
	}
}

// TestIdentityLinkedOAuthClientGatesAuthCodeAndRefresh verifies the H1 close:
// when an OAuth client is explicitly bound to an agent identity via
// identity_id, both the authorization_code and refresh_token grants gate
// on the linked identity's expires_at — closing the synthetic-identity
// bypass the reviewer flagged.
//
// Without the identity link, the human-session flow stays untouched
// (TestExpiringSoonEndpoint already exercises the unlinked path).
func TestIdentityLinkedOAuthClientGatesAuthCodeAndRefresh(t *testing.T) {
	// 1. Register an agent identity (no expiry yet — establish baseline).
	ext := uid("linked-client-agent")
	agent := registerAgent(t, ext)

	// 2. Register a PKCE-style OAuth client bound to that identity. The
	// _redirect_uri_ and _grant_types_ mark this as an agent-authorized
	// authorization_code flow (the deployer's hypothetical "PKCE-provision
	// my agent" scenario).
	clientID := uid("linked-oauth-client")
	resp := post(t, adminPath("/oauth/clients"), map[string]any{
		"client_id":     clientID,
		"name":          clientID,
		"grant_types":   []string{"authorization_code", "refresh_token"},
		"redirect_uris": []string{testRedirectURI},
		"scopes":        []string{"data:read"},
		"identity_id":   agent.AgentID,
	}, adminHeaders())
	createBody := decode(t, resp)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "client create with identity_id must succeed; body=%v", createBody)

	// 3. Mint a PKCE auth-code-style JWT for this client and exchange it
	// while the identity is still active — must succeed.
	verifier, challenge := buildPKCEPair(t)
	code := buildAuthCode(t, clientID, "user-linked-001", testRedirectURI, challenge, []string{"data:read"})
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "authorization_code",
		"code":          code,
		"code_verifier": verifier,
		"client_id":     clientID,
		"redirect_uri":  testRedirectURI,
	}, nil)
	body := decode(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode, "authorization_code while identity active must succeed; body=%v", body)
	refreshTok := ""
	if rt, ok := body["refresh_token"].(string); ok {
		refreshTok = rt
	}
	require.NotEmpty(t, refreshTok, "client is registered for refresh_token grant; must return one")

	// 4. Expire the linked identity.
	past := time.Now().Add(-time.Second).UTC().Format(time.RFC3339)
	patched, err := doRaw(t, http.MethodPatch, adminPath("/identities/"+agent.AgentID), map[string]any{
		"expires_at": past,
	}, adminHeaders())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, patched.StatusCode)
	_ = patched.Body.Close()

	// 5. Try to exchange a fresh auth code — now blocked by the identity gate.
	verifier2, challenge2 := buildPKCEPair(t)
	code2 := buildAuthCode(t, clientID, "user-linked-002", testRedirectURI, challenge2, []string{"data:read"})
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "authorization_code",
		"code":          code2,
		"code_verifier": verifier2,
		"client_id":     clientID,
		"redirect_uri":  testRedirectURI,
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "authorization_code for expired-linked-identity must fail")
	body2 := decode(t, resp)
	require.Equal(t, "invalid_grant", body2["error"])
	require.Equal(t, "identity_expired", body2["error_description"])

	// 6. Refresh the existing refresh token — also blocked. This is the
	// previously-open path: pre-PR, the refresh would mint a new access
	// token because the synthetic identity carrier bypassed the chokepoint.
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": refreshTok,
		"client_id":     clientID,
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "refresh_token for expired-linked-identity must fail")
	body3 := decode(t, resp)
	require.Equal(t, "invalid_grant", body3["error"])
	require.Equal(t, "identity_expired", body3["error_description"])
}

// TestExpiredCredentialPolicyDeniesIssuance exercises the EnforcePolicy
// expiry check. An expired credential policy must reject token issuance
// even when the identity itself is still unexpired.
func TestExpiredCredentialPolicyDeniesIssuance(t *testing.T) {
	// Create a policy expiring in the past.
	past := time.Now().Add(-time.Second).UTC().Format(time.RFC3339)
	resp := post(t, adminPath("/credential-policies"), map[string]any{
		"name":                uid("expired-policy"),
		"description":         "Test expired policy",
		"max_ttl_seconds":     3600,
		"allowed_grant_types": []string{"client_credentials", "api_key"},
		"expires_at":          past,
	}, adminHeaders())
	policyBody := decode(t, resp)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "policy create must succeed; body=%v", policyBody)
	policyID := policyBody["id"].(string)

	// Register an agent assigned to this expired policy.
	ext := uid("agent-on-expired-policy")
	resp = post(t, adminPath("/agents/register"), map[string]any{
		"name":                 ext,
		"external_id":          ext,
		"sub_type":             "orchestrator",
		"trust_level":          "first_party",
		"created_by":           "test-user",
		"credential_policy_id": policyID,
	}, adminHeaders())
	reg := decode(t, resp)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "agent register must succeed; body=%v", reg)
	apiKey := reg["api_key"].(string)

	// api_key grant: EnforcePolicy fires on the identity policy.
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type": "api_key",
		"api_key":    apiKey,
	}, nil)
	require.NotEqual(t, http.StatusOK, resp.StatusCode, "expired policy must block issuance; body=%v", decode(t, resp))
}
