package integration_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestClientCredentialsFlow exercises the full RFC 6749 §4.4 client_credentials flow:
// register identity + OAuth client → get token → introspect active → revoke → introspect inactive.
func TestClientCredentialsFlow(t *testing.T) {
	agentID := uid("billing-agent")
	scopes := []string{"billing:read", "billing:write"}

	// Platform: register identity and OAuth2 client.
	registerIdentity(t, agentID, scopes)
	client := registerOAuthClient(t, agentID, scopes)

	// Agent: exchange client credentials for a JWT.
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
		"scope":         "billing:read",
	}, nil) // no admin headers — this is a public endpoint
	require.Equal(t, http.StatusOK, resp.StatusCode)

	token := decode(t, resp)
	accessToken := token["access_token"].(string)
	assert.Equal(t, "Bearer", token["token_type"])
	assert.NotEmpty(t, accessToken)
	assert.EqualValues(t, 3600, token["expires_in"])

	// Introspect: token should be active.
	result := introspect(t, accessToken)
	assert.True(t, result["active"].(bool), "token should be active after issuance")
	assert.Equal(t, testIssuer, result["iss"])
	assert.Contains(t, result["scope"], "billing:read")
	assert.Equal(t, testAccountID, result["account_id"])
	assert.Equal(t, testProjectID, result["project_id"])

	// Agent: revoke the token (RFC 7009 — must return 200 regardless).
	revokeResp := post(t, "/oauth2/token/revoke", map[string]string{"token": accessToken}, nil)
	require.Equal(t, http.StatusOK, revokeResp.StatusCode)
	revokeResp.Body.Close()

	// Introspect again: token must now be inactive.
	result = introspect(t, accessToken)
	assert.False(t, result["active"].(bool), "token should be inactive after revocation")
}

// TestClientCredentialsScopeIntersection verifies that the issued token's scope
// is the intersection of the requested scope and the client's registered scopes.
func TestClientCredentialsScopeIntersection(t *testing.T) {
	agentID := uid("scope-agent")
	registerIdentity(t, agentID, []string{"data:read", "data:write"})
	client := registerOAuthClient(t, agentID, []string{"data:read", "data:write"})

	// Request only data:read even though client has data:read + data:write.
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	token := decode(t, resp)
	assert.Equal(t, "data:read", token["scope"], "scope should be capped at requested value")
}

// TestClientCredentialsWrongSecret verifies that an invalid secret is rejected.
func TestClientCredentialsWrongSecret(t *testing.T) {
	agentID := uid("secret-agent")
	registerIdentity(t, agentID, []string{"billing:read"})
	registerOAuthClient(t, agentID, []string{"billing:read"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     agentID,
		"client_secret": "wrong-secret",
	}, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()
}

// TestJWTBearerFlow exercises the full RFC 7523 jwt_bearer flow:
// register identity with public key → agent signs assertion → exchange → introspect active.
func TestJWTBearerFlow(t *testing.T) {
	// Generate the agent's own key pair (simulates agent-controlled key).
	agentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	agentID := uid("data-agent")
	identity := registerIdentity(t, agentID, []string{"data:read", "data:write"}, ecPublicKeyPEM(t, agentKey))

	// Agent: build a self-signed JWT assertion with its private key.
	assertion := buildAssertion(t, agentKey, identity.WIMSEURI)

	// Agent: exchange assertion for a ZeroID-issued JWT.
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
		"subject":    assertion,
		"scope":      "data:read",
	}, nil) // public endpoint — no admin headers
	require.Equal(t, http.StatusOK, resp.StatusCode)

	token := decode(t, resp)
	accessToken := token["access_token"].(string)
	assert.Equal(t, "Bearer", token["token_type"])
	assert.NotEmpty(t, accessToken)

	// Introspect: token should be active with correct sub.
	result := introspect(t, accessToken)
	assert.True(t, result["active"].(bool))
	assert.Equal(t, identity.WIMSEURI, result["sub"])
	assert.Equal(t, testIssuer, result["iss"])
	assert.Contains(t, result["scope"], "data:read")
}

// TestJWTBearerWrongKey verifies that an assertion signed with an unknown key is rejected.
func TestJWTBearerWrongKey(t *testing.T) {
	// Register identity with one key.
	registeredKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	agentID := uid("wrong-key-agent")
	identity := registerIdentity(t, agentID, []string{"data:read"}, ecPublicKeyPEM(t, registeredKey))

	// Sign assertion with a different (unregistered) key.
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	assertion := buildAssertion(t, wrongKey, identity.WIMSEURI)

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
		"subject":    assertion,
		"scope":      "data:read",
	}, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()
}

// TestTokenExchangeFlow exercises the full RFC 8693 token_exchange / agent delegation flow:
// - orchestrator gets a client_credentials token (subject_token)
// - sub-agent builds a signed assertion (actor_token)
// - exchange produces a delegated token with act.sub = orchestrator WIMSE URI
func TestTokenExchangeFlow(t *testing.T) {
	// Set up orchestrator (billing agent) — uses client_credentials.
	orchID := uid("orchestrator")
	registerIdentity(t, orchID, []string{"billing:read", "data:read"})
	orchClient := registerOAuthClient(t, orchID, []string{"billing:read", "data:read"})

	// Orchestrator gets its own active token.
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     orchClient.ClientID,
		"client_secret": orchClient.ClientSecret,
		"scope":         "billing:read data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	orchToken := decode(t, resp)["access_token"].(string)

	// Set up sub-agent (data agent) — uses jwt_bearer key pair.
	subKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	subID := uid("sub-agent")
	subIdentity := registerIdentity(t, subID, []string{"data:read"}, ecPublicKeyPEM(t, subKey))

	// Sub-agent builds its actor assertion.
	actorAssertion := buildAssertion(t, subKey, subIdentity.WIMSEURI)

	// Exchange: orchestrator delegates data:read to the sub-agent.
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": orchToken,
		"actor_token":   actorAssertion,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	token := decode(t, resp)
	delegatedToken := token["access_token"].(string)
	assert.NotEmpty(t, delegatedToken)
	assert.Equal(t, "data:read", token["scope"])

	// Introspect: verify delegation chain.
	result := introspect(t, delegatedToken)
	assert.True(t, result["active"].(bool))
	assert.Equal(t, subIdentity.WIMSEURI, result["sub"], "sub should be the sub-agent")

	act, ok := result["act"].(map[string]any)
	require.True(t, ok, "act claim must be present for token_exchange")

	// Derive orchestrator WIMSE URI from introspecting its token.
	orchIntrospect := introspect(t, orchToken)
	orchWIMSEURI := orchIntrospect["sub"].(string)

	assert.Equal(t, orchWIMSEURI, act["sub"], "act.sub should be the orchestrator WIMSE URI")
}

// TestTokenExchangeScopeEnforcement verifies that a sub-agent cannot request scopes
// beyond what the orchestrator currently holds.
func TestTokenExchangeScopeEnforcement(t *testing.T) {
	orchID := uid("scope-orch")
	registerIdentity(t, orchID, []string{"data:read"}) // orchestrator has only data:read
	orchClient := registerOAuthClient(t, orchID, []string{"data:read"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     orchClient.ClientID,
		"client_secret": orchClient.ClientSecret,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	orchToken := decode(t, resp)["access_token"].(string)

	subKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	subID := uid("scope-sub")
	subIdentity := registerIdentity(t, subID, []string{"data:read", "data:write"}, ecPublicKeyPEM(t, subKey))
	actorAssertion := buildAssertion(t, subKey, subIdentity.WIMSEURI)

	// Request data:write, which the orchestrator doesn't have — must be refused or downscoped.
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": orchToken,
		"actor_token":   actorAssertion,
		"scope":         "data:write", // orchestrator doesn't hold this scope
	}, nil)
	// The service returns an empty granted scope or an error — either way data:write must not appear.
	if resp.StatusCode == http.StatusOK {
		token := decode(t, resp)
		scope, _ := token["scope"].(string)
		assert.NotContains(t, scope, "data:write", "data:write must not be granted when orchestrator lacks it")
	} else {
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		resp.Body.Close()
	}
}

// TestRevokedSubjectTokenCannotDelegate verifies that a revoked orchestrator token
// cannot be used to produce new delegated tokens.
func TestRevokedSubjectTokenCannotDelegate(t *testing.T) {
	orchID := uid("revoked-orch")
	registerIdentity(t, orchID, []string{"data:read"})
	orchClient := registerOAuthClient(t, orchID, []string{"data:read"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     orchClient.ClientID,
		"client_secret": orchClient.ClientSecret,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	orchToken := decode(t, resp)["access_token"].(string)

	// Revoke the orchestrator token.
	revokeResp := post(t, "/oauth2/token/revoke", map[string]string{"token": orchToken}, nil)
	require.Equal(t, http.StatusOK, revokeResp.StatusCode)
	revokeResp.Body.Close()

	// Attempt token_exchange with the now-revoked token.
	subKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	subID := uid("sub-after-revoke")
	subIdentity := registerIdentity(t, subID, []string{"data:read"}, ecPublicKeyPEM(t, subKey))
	actorAssertion := buildAssertion(t, subKey, subIdentity.WIMSEURI)

	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": orchToken,
		"actor_token":   actorAssertion,
		"scope":         "data:read",
	}, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "revoked subject_token must be rejected")
	resp.Body.Close()
}

// TestRevokeMissingTokenReturns200 verifies RFC 7009 §2.2: revoke always returns 200
// even when the token does not exist.
func TestRevokeMissingTokenReturns200(t *testing.T) {
	resp := post(t, "/oauth2/token/revoke", map[string]string{"token": "not-a-real-token"}, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}

// TestIntrospectUnknownToken verifies that introspecting an unknown token returns active:false.
func TestIntrospectUnknownToken(t *testing.T) {
	result := introspect(t, "unknown.token.value")
	assert.False(t, result["active"].(bool))
}

// ── API Key + RS256 token exchange tests ─────────────────────────────────────

// TestAPIKeyGrant exercises the api_key grant flow:
// register agent (gets zid_sk_* key) → exchange for RS256 JWT → introspect → revoke.
func TestAPIKeyGrant(t *testing.T) {
	agent := registerAgent(t, uid("apikey-agent"))

	// Exchange API key for RS256 JWT.
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type": "api_key",
		"api_key":    agent.APIKey,
		"scope":      "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	token := decode(t, resp)
	accessToken := token["access_token"].(string)
	assert.Equal(t, "Bearer", token["token_type"])
	assert.NotEmpty(t, accessToken)

	// Introspect: token should be active.
	result := introspect(t, accessToken)
	assert.True(t, result["active"].(bool))
	assert.Contains(t, result["sub"].(string), "spiffe://", "sub should be a WIMSE URI")
	assert.Contains(t, result["scope"], "data:read")

	// Revoke and confirm inactive.
	revokeResp := post(t, "/oauth2/token/revoke", map[string]string{"token": accessToken}, nil)
	require.Equal(t, http.StatusOK, revokeResp.StatusCode)
	revokeResp.Body.Close()

	result = introspect(t, accessToken)
	assert.False(t, result["active"].(bool))
}

// TestTokenExchangeWithRS256SubjectToken verifies that an RS256 token (from api_key grant)
// can be used as subject_token in RFC 8693 token exchange for agent delegation.
// This tests the parseTokenAnyAlg / tokenAlgorithm fix that reads the JWT alg header
// to select the correct verification key instead of hardcoding ES256.
func TestTokenExchangeWithRS256SubjectToken(t *testing.T) {
	// Orchestrator: register and get RS256 token via api_key.
	orch := registerAgent(t, uid("rs256-orch"))
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type": "api_key",
		"api_key":    orch.APIKey,
		"scope":      "data:read data:write",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	orchToken := decode(t, resp)["access_token"].(string)

	// Sub-agent: register with jwt_bearer key pair.
	subKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	subID := uid("rs256-sub")
	subIdentity := registerIdentity(t, subID, []string{"data:read"}, ecPublicKeyPEM(t, subKey))

	// Sub-agent builds actor assertion.
	actorAssertion := buildAssertion(t, subKey, subIdentity.WIMSEURI)

	// Token exchange: RS256 subject_token + ES256 actor_token → delegated ES256 token.
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": orchToken,
		"actor_token":   actorAssertion,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	token := decode(t, resp)
	delegatedToken := token["access_token"].(string)
	assert.NotEmpty(t, delegatedToken)
	assert.Equal(t, "data:read", token["scope"])

	// Introspect: verify delegation chain.
	result := introspect(t, delegatedToken)
	assert.True(t, result["active"].(bool))
	assert.Equal(t, subIdentity.WIMSEURI, result["sub"], "sub should be the sub-agent WIMSE URI")

	act, ok := result["act"].(map[string]any)
	require.True(t, ok, "act claim must be present")
	assert.Contains(t, act["sub"], "spiffe://", "act.sub should be the orchestrator WIMSE URI")

	depth, ok := result["delegation_depth"]
	require.True(t, ok, "delegation_depth must be present")
	assert.EqualValues(t, 1, depth)
}

// TestTokenExchangeES256SubjectTokenStillWorks verifies that the standard ES256 delegation
// flow (client_credentials → token_exchange) continues to work after the alg-detection change.
func TestTokenExchangeES256SubjectTokenStillWorks(t *testing.T) {
	// Orchestrator: client_credentials (ES256).
	orchID := uid("es256-orch")
	registerIdentity(t, orchID, []string{"data:read"})
	orchClient := registerOAuthClient(t, orchID, []string{"data:read"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     orchClient.ClientID,
		"client_secret": orchClient.ClientSecret,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	orchToken := decode(t, resp)["access_token"].(string)

	// Sub-agent with jwt_bearer key pair.
	subKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	subID := uid("es256-sub")
	subIdentity := registerIdentity(t, subID, []string{"data:read"}, ecPublicKeyPEM(t, subKey))
	actorAssertion := buildAssertion(t, subKey, subIdentity.WIMSEURI)

	// Token exchange with ES256 subject_token.
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": orchToken,
		"actor_token":   actorAssertion,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	token := decode(t, resp)
	assert.NotEmpty(t, token["access_token"])
	assert.Equal(t, "data:read", token["scope"])
}

// TestMultiHopDelegation verifies that token_exchange can be chained:
// orchestrator (depth 0) → sub-agent 1 (depth 1) → sub-agent 2 (depth 2).
// delegation_depth must increment at each hop and act.sub must reflect the
// immediate delegator (not the original orchestrator).
func TestMultiHopDelegation(t *testing.T) {
	// ── Orchestrator: client_credentials (depth 0) ─────────────────────────
	orchID := uid("mh-orch")
	registerIdentity(t, orchID, []string{"data:read"})
	orchClient := registerOAuthClient(t, orchID, []string{"data:read"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     orchClient.ClientID,
		"client_secret": orchClient.ClientSecret,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	orchToken := decode(t, resp)["access_token"].(string)
	orchWIMSE := introspect(t, orchToken)["sub"].(string)

	// ── Sub-agent 1: token_exchange from orchestrator (depth 1) ────────────
	sub1Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	sub1ID := uid("mh-sub1")
	sub1Identity := registerIdentity(t, sub1ID, []string{"data:read"}, ecPublicKeyPEM(t, sub1Key))

	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": orchToken,
		"actor_token":   buildAssertion(t, sub1Key, sub1Identity.WIMSEURI),
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	depth1Token := decode(t, resp)["access_token"].(string)

	d1 := introspect(t, depth1Token)
	assert.True(t, d1["active"].(bool))
	assert.Equal(t, sub1Identity.WIMSEURI, d1["sub"], "depth-1 sub should be sub-agent 1")
	assert.EqualValues(t, 1, d1["delegation_depth"], "depth-1 token should have delegation_depth=1")
	act1 := d1["act"].(map[string]any)
	assert.Equal(t, orchWIMSE, act1["sub"], "depth-1 act.sub should be orchestrator")

	// ── Sub-agent 2: token_exchange from sub-agent 1 (depth 2) ─────────────
	sub2Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	sub2ID := uid("mh-sub2")
	sub2Identity := registerIdentity(t, sub2ID, []string{"data:read"}, ecPublicKeyPEM(t, sub2Key))

	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": depth1Token,
		"actor_token":   buildAssertion(t, sub2Key, sub2Identity.WIMSEURI),
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	depth2Token := decode(t, resp)["access_token"].(string)

	d2 := introspect(t, depth2Token)
	assert.True(t, d2["active"].(bool))
	assert.Equal(t, sub2Identity.WIMSEURI, d2["sub"], "depth-2 sub should be sub-agent 2")
	assert.EqualValues(t, 2, d2["delegation_depth"], "depth-2 token should have delegation_depth=2")
	act2 := d2["act"].(map[string]any)
	assert.Equal(t, sub1Identity.WIMSEURI, act2["sub"], "depth-2 act.sub should be sub-agent 1 (immediate delegator)")
}

// TestRevokeTokenCascadesToChildren verifies that revoking a parent token via
// POST /oauth2/token/revoke also invalidates all downstream credentials issued
// via RFC 8693 token_exchange against that parent.
//
// Chain under test:
//
//	orchestrator (depth=0) → sub-agent (depth=1) → grandchild (depth=2)
//
// Revoking the orchestrator token must cause all three to become inactive.
func TestRevokeTokenCascadesToChildren(t *testing.T) {
	// ── Orchestrator: client_credentials (depth=0) ──────────────────────────
	orchID := uid("rev-casc-orch")
	registerIdentity(t, orchID, []string{"data:read"})
	orchClient := registerOAuthClient(t, orchID, []string{"data:read"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     orchClient.ClientID,
		"client_secret": orchClient.ClientSecret,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	orchToken := decode(t, resp)["access_token"].(string)

	// ── Sub-agent: token_exchange from orchestrator (depth=1) ───────────────
	sub1Key := generateKey(t)
	sub1Identity := registerIdentity(t, uid("rev-casc-sub1"), []string{"data:read"}, ecPublicKeyPEM(t, sub1Key))

	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": orchToken,
		"actor_token":   buildAssertion(t, sub1Key, sub1Identity.WIMSEURI),
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	depth1Token := decode(t, resp)["access_token"].(string)

	// ── Grandchild: token_exchange from sub-agent (depth=2) ─────────────────
	sub2Key := generateKey(t)
	sub2Identity := registerIdentity(t, uid("rev-casc-sub2"), []string{"data:read"}, ecPublicKeyPEM(t, sub2Key))

	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": depth1Token,
		"actor_token":   buildAssertion(t, sub2Key, sub2Identity.WIMSEURI),
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	depth2Token := decode(t, resp)["access_token"].(string)

	// ── All three tokens must be active before revocation ───────────────────
	require.True(t, introspect(t, orchToken)["active"].(bool), "orchestrator token must be active before revocation")
	require.True(t, introspect(t, depth1Token)["active"].(bool), "depth-1 token must be active before revocation")
	require.True(t, introspect(t, depth2Token)["active"].(bool), "depth-2 token must be active before revocation")

	// ── Revoke only the orchestrator token ───────────────────────────────────
	revokeResp := post(t, "/oauth2/token/revoke", map[string]string{"token": orchToken}, nil)
	require.Equal(t, http.StatusOK, revokeResp.StatusCode)
	revokeResp.Body.Close()

	// ── All three must now be inactive ───────────────────────────────────────
	assert.False(t, introspect(t, orchToken)["active"].(bool),
		"orchestrator token must be inactive after revocation")
	assert.False(t, introspect(t, depth1Token)["active"].(bool),
		"depth-1 token must be inactive: parent was revoked")
	assert.False(t, introspect(t, depth2Token)["active"].(bool),
		"depth-2 token must be inactive: grandparent was revoked")
}

// TestRevokeMidChainDoesNotRevokeParent verifies that revoking a mid-chain token
// cascades downward to descendants but does NOT revoke the parent above it.
//
// Chain: orchestrator (depth=0) → sub-agent (depth=1) → grandchild (depth=2)
// Action: revoke depth-1
// Expected: depth-0 stays active, depth-1 and depth-2 become inactive.
func TestRevokeMidChainDoesNotRevokeParent(t *testing.T) {
	// ── Orchestrator (depth=0) ───────────────────────────────────────────────
	orchID := uid("mid-orch")
	registerIdentity(t, orchID, []string{"data:read"})
	orchClient := registerOAuthClient(t, orchID, []string{"data:read"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     orchClient.ClientID,
		"client_secret": orchClient.ClientSecret,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	orchToken := decode(t, resp)["access_token"].(string)

	// ── Sub-agent (depth=1) ──────────────────────────────────────────────────
	sub1Key := generateKey(t)
	sub1Identity := registerIdentity(t, uid("mid-sub1"), []string{"data:read"}, ecPublicKeyPEM(t, sub1Key))

	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": orchToken,
		"actor_token":   buildAssertion(t, sub1Key, sub1Identity.WIMSEURI),
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	depth1Token := decode(t, resp)["access_token"].(string)

	// ── Grandchild (depth=2) ─────────────────────────────────────────────────
	sub2Key := generateKey(t)
	sub2Identity := registerIdentity(t, uid("mid-sub2"), []string{"data:read"}, ecPublicKeyPEM(t, sub2Key))

	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": depth1Token,
		"actor_token":   buildAssertion(t, sub2Key, sub2Identity.WIMSEURI),
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	depth2Token := decode(t, resp)["access_token"].(string)

	require.True(t, introspect(t, orchToken)["active"].(bool))
	require.True(t, introspect(t, depth1Token)["active"].(bool))
	require.True(t, introspect(t, depth2Token)["active"].(bool))

	// ── Revoke depth-1 only ──────────────────────────────────────────────────
	revokeResp := post(t, "/oauth2/token/revoke", map[string]string{"token": depth1Token}, nil)
	require.Equal(t, http.StatusOK, revokeResp.StatusCode)
	revokeResp.Body.Close()

	// ── Parent (depth=0) must remain active ──────────────────────────────────
	assert.True(t, introspect(t, orchToken)["active"].(bool),
		"orchestrator token must remain active: revocation does not propagate upward")

	// ── depth-1 and depth-2 must be inactive ─────────────────────────────────
	assert.False(t, introspect(t, depth1Token)["active"].(bool),
		"depth-1 token must be inactive: it was directly revoked")
	assert.False(t, introspect(t, depth2Token)["active"].(bool),
		"depth-2 token must be inactive: its parent was revoked")
}

// TestRevokeCascadesFanOut verifies that revoking an orchestrator token invalidates
// all parallel children that were independently issued via token_exchange against it.
//
// Chain: orchestrator → [sub-agent A, sub-agent B, sub-agent C]
func TestRevokeCascadesFanOut(t *testing.T) {
	// ── Orchestrator ─────────────────────────────────────────────────────────
	orchID := uid("fan-orch")
	registerIdentity(t, orchID, []string{"data:read"})
	orchClient := registerOAuthClient(t, orchID, []string{"data:read"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     orchClient.ClientID,
		"client_secret": orchClient.ClientSecret,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	orchToken := decode(t, resp)["access_token"].(string)

	// ── Three independent sub-agents each get a delegated token ──────────────
	childTokens := make([]string, 3)
	for i := range childTokens {
		key := generateKey(t)
		identity := registerIdentity(t, uid("fan-sub"), []string{"data:read"}, ecPublicKeyPEM(t, key))
		resp = post(t, "/oauth2/token", map[string]any{
			"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
			"subject_token": orchToken,
			"actor_token":   buildAssertion(t, key, identity.WIMSEURI),
			"scope":         "data:read",
		}, nil)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		childTokens[i] = decode(t, resp)["access_token"].(string)
		require.True(t, introspect(t, childTokens[i])["active"].(bool))
	}

	// ── Revoke orchestrator ───────────────────────────────────────────────────
	revokeResp := post(t, "/oauth2/token/revoke", map[string]string{"token": orchToken}, nil)
	require.Equal(t, http.StatusOK, revokeResp.StatusCode)
	revokeResp.Body.Close()

	// ── All children must be inactive ────────────────────────────────────────
	assert.False(t, introspect(t, orchToken)["active"].(bool), "orchestrator must be inactive")
	for i, tok := range childTokens {
		assert.False(t, introspect(t, tok)["active"].(bool),
			"child token %d must be inactive after orchestrator revocation", i)
	}
}

// TestRevokeDoesNotAffectSiblingChains verifies that revoking one delegation chain
// has no effect on a completely independent chain issued by a different orchestrator.
//
// Chain A: orch-A → sub-A   (revoked)
// Chain B: orch-B → sub-B   (must remain active)
func TestRevokeDoesNotAffectSiblingChains(t *testing.T) {
	issueChain := func(prefix string) (orchToken, childToken string) {
		orchID := uid(prefix + "-orch")
		registerIdentity(t, orchID, []string{"data:read"})
		orchClient := registerOAuthClient(t, orchID, []string{"data:read"})

		resp := post(t, "/oauth2/token", map[string]any{
			"grant_type":    "client_credentials",
			"account_id":    testAccountID,
			"project_id":    testProjectID,
			"client_id":     orchClient.ClientID,
			"client_secret": orchClient.ClientSecret,
			"scope":         "data:read",
		}, nil)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		orchToken = decode(t, resp)["access_token"].(string)

		key := generateKey(t)
		identity := registerIdentity(t, uid(prefix+"-sub"), []string{"data:read"}, ecPublicKeyPEM(t, key))
		resp = post(t, "/oauth2/token", map[string]any{
			"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
			"subject_token": orchToken,
			"actor_token":   buildAssertion(t, key, identity.WIMSEURI),
			"scope":         "data:read",
		}, nil)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		childToken = decode(t, resp)["access_token"].(string)
		return
	}

	orchA, subA := issueChain("sib-a")
	orchB, subB := issueChain("sib-b")

	require.True(t, introspect(t, orchA)["active"].(bool))
	require.True(t, introspect(t, subA)["active"].(bool))
	require.True(t, introspect(t, orchB)["active"].(bool))
	require.True(t, introspect(t, subB)["active"].(bool))

	// Revoke chain A only.
	revokeResp := post(t, "/oauth2/token/revoke", map[string]string{"token": orchA}, nil)
	require.Equal(t, http.StatusOK, revokeResp.StatusCode)
	revokeResp.Body.Close()

	// Chain A is gone.
	assert.False(t, introspect(t, orchA)["active"].(bool), "orch-A must be inactive")
	assert.False(t, introspect(t, subA)["active"].(bool), "sub-A must be inactive: parent revoked")

	// Chain B is completely unaffected.
	assert.True(t, introspect(t, orchB)["active"].(bool), "orch-B must remain active: different chain")
	assert.True(t, introspect(t, subB)["active"].(bool), "sub-B must remain active: different chain")
}

// TestRevokeDeepChain verifies cascade revocation works across four delegation hops.
//
// Chain: depth-0 → depth-1 → depth-2 → depth-3
// Revoking depth-0 must invalidate all four tokens.
func TestRevokeDeepChain(t *testing.T) {
	// ── depth-0: client_credentials ──────────────────────────────────────────
	orchID := uid("deep-orch")
	registerIdentity(t, orchID, []string{"data:read"})
	orchClient := registerOAuthClient(t, orchID, []string{"data:read"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     orchClient.ClientID,
		"client_secret": orchClient.ClientSecret,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	tokens := []string{decode(t, resp)["access_token"].(string)}

	// ── depth-1 through depth-3: each exchanges the previous token ───────────
	for i := 1; i <= 3; i++ {
		key := generateKey(t)
		identity := registerIdentity(t, uid("deep-sub"), []string{"data:read"}, ecPublicKeyPEM(t, key))
		resp = post(t, "/oauth2/token", map[string]any{
			"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
			"subject_token": tokens[i-1],
			"actor_token":   buildAssertion(t, key, identity.WIMSEURI),
			"scope":         "data:read",
		}, nil)
		require.Equal(t, http.StatusOK, resp.StatusCode, "token exchange at depth %d failed", i)
		tokens = append(tokens, decode(t, resp)["access_token"].(string))
	}

	for i, tok := range tokens {
		require.True(t, introspect(t, tok)["active"].(bool), "depth-%d token must be active before revocation", i)
	}

	// ── Revoke the root ───────────────────────────────────────────────────────
	revokeResp := post(t, "/oauth2/token/revoke", map[string]string{"token": tokens[0]}, nil)
	require.Equal(t, http.StatusOK, revokeResp.StatusCode)
	revokeResp.Body.Close()

	// ── All four must be inactive ─────────────────────────────────────────────
	for i, tok := range tokens {
		assert.False(t, introspect(t, tok)["active"].(bool),
			"depth-%d token must be inactive after root revocation", i)
	}
}

// TestRevokeIsIdempotent verifies that revoking an already-revoked token returns
// 200 with no error, and the token remains inactive (RFC 7009 §2.2).
func TestRevokeIsIdempotent(t *testing.T) {
	agentID := uid("idem-agent")
	registerIdentity(t, agentID, []string{"data:read"})
	client := registerOAuthClient(t, agentID, []string{"data:read"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	token := decode(t, resp)["access_token"].(string)

	// First revocation.
	r1 := post(t, "/oauth2/token/revoke", map[string]string{"token": token}, nil)
	assert.Equal(t, http.StatusOK, r1.StatusCode)
	r1.Body.Close()

	assert.False(t, introspect(t, token)["active"].(bool), "token must be inactive after first revocation")

	// Second revocation of the same token — must still return 200.
	r2 := post(t, "/oauth2/token/revoke", map[string]string{"token": token}, nil)
	assert.Equal(t, http.StatusOK, r2.StatusCode, "second revocation must return 200 per RFC 7009")
	r2.Body.Close()

	assert.False(t, introspect(t, token)["active"].(bool), "token must remain inactive after second revocation")
}
