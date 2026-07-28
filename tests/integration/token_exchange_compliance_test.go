// RFC 8693 (OAuth 2.0 Token Exchange) compliance suite — negative-space.
//
// See COMPLIANCE.md for the conventions this file follows.
//
// Happy-path coverage (orchestrator → sub-agent delegation, scope
// attenuation, act claim chain) lives in oauth_test.go. This file pins
// the §2.1 request-shape MUSTs and §2.2 response-shape MUSTs that aren't
// otherwise exercised — what the server MUST reject and what shape the
// successful response MUST carry.

package integration_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// txFixture sets up an orchestrator with an active token and a sub-agent
// with a registered keypair for actor_token signing.
type txFixture struct {
	OrchestratorToken    string
	SubAgentKey          *ecdsa.PrivateKey
	SubAgentWIMSEURI     string
	OrchestratorWIMSEURI string
}

func setupTokenExchangeFixture(t *testing.T) txFixture {
	t.Helper()
	orchID := uid("compliance-tx-orch")
	registerIdentity(t, orchID, []string{"data:read"})
	orchClient := registerOAuthClient(t, orchID, []string{"data:read"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     orchClient.ClientID,
		"client_secret": orchClient.ClientSecret,
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	orchToken, _ := decode(t, resp)["access_token"].(string)
	orchIntro := introspect(t, orchToken)
	orchWIMSE, _ := orchIntro["sub"].(string)

	subKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	subID := uid("compliance-tx-sub")
	subIdentity := registerIdentity(t, subID, []string{"data:read"}, ecPublicKeyPEM(t, subKey))

	return txFixture{
		OrchestratorToken:    orchToken,
		SubAgentKey:          subKey,
		SubAgentWIMSEURI:     subIdentity.WIMSEURI,
		OrchestratorWIMSEURI: orchWIMSE,
	}
}

// ── RFC 8693 §2.1 — Request shape ──────────────────────────────────────────

func TestRFC8693_S2_1_SubjectTokenRequired(t *testing.T) {
	// RFC 8693 §2.1: "subject_token REQUIRED. A security token that
	//   represents the identity of the party on behalf of whom the request
	//   is being made."
	f := setupTokenExchangeFixture(t)
	actorAssertion := buildAssertion(t, f.SubAgentKey, f.SubAgentWIMSEURI)
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":  "urn:ietf:params:oauth:grant-type:token-exchange",
		"actor_token": actorAssertion,
		// subject_token deliberately omitted
		"scope": "data:read",
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body := decode(t, resp)
	assert.Equal(t, "invalid_request", body["error"],
		"missing subject_token MUST be invalid_request (not invalid_grant)")
}

func TestRFC8693_S2_1_GrantTypeMustBeTokenExchangeURN(t *testing.T) {
	// RFC 8693 §2.1: "grant_type REQUIRED. The value
	//   urn:ietf:params:oauth:grant-type:token-exchange indicates that a
	//   token exchange is being performed."
	// Any other value is a different grant; "token-exchange" without the
	// urn:ietf:... prefix MUST NOT be silently accepted.
	f := setupTokenExchangeFixture(t)
	actorAssertion := buildAssertion(t, f.SubAgentKey, f.SubAgentWIMSEURI)
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "token-exchange", // missing urn:ietf:... prefix
		"subject_token": f.OrchestratorToken,
		"actor_token":   actorAssertion,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body := decode(t, resp)
	assert.Equal(t, "unsupported_grant_type", body["error"],
		"only the exact urn:ietf:params:oauth:grant-type:token-exchange identifier triggers RFC 8693 dispatch")
}

func TestRFC8693_S2_1_InvalidSubjectTokenRejected(t *testing.T) {
	// RFC 8693 §2.1 (implicit): the subject_token MUST be a token the AS
	// recognises. A junk value MUST be rejected — not silently issue a
	// new token off attacker-controlled input.
	f := setupTokenExchangeFixture(t)
	actorAssertion := buildAssertion(t, f.SubAgentKey, f.SubAgentWIMSEURI)
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": "not-a-real-token",
		"actor_token":   actorAssertion,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body := decode(t, resp)
	assert.Equal(t, "invalid_grant", body["error"])
}

// ── RFC 8693 §2.2 — Response shape ─────────────────────────────────────────

func TestRFC8693_S2_2_ResponseContainsAccessTokenAndTokenType(t *testing.T) {
	// RFC 8693 §2.2.1: "access_token REQUIRED. The security token issued
	//   by the authorization server. ... token_type REQUIRED. ... ZeroID
	//   issues Bearer tokens for non-DPoP exchanges."
	f := setupTokenExchangeFixture(t)
	actorAssertion := buildAssertion(t, f.SubAgentKey, f.SubAgentWIMSEURI)
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": f.OrchestratorToken,
		"actor_token":   actorAssertion,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	assert.NotEmpty(t, body["access_token"], "access_token REQUIRED in response")
	assert.Equal(t, "Bearer", body["token_type"],
		"non-DPoP token_exchange MUST issue Bearer per RFC 8693 §2.2.1")
}

// ── RFC 8693 §4 — Issued-token claims ──────────────────────────────────────

func TestRFC8693_S4_2_ActClaimChainsDelegation(t *testing.T) {
	// RFC 8693 §4.2: "act ... A JSON object that contains claims about a
	//   distinct chained delegating principal." The actor (orchestrator)
	//   MUST appear in the act claim of the issued delegated token.
	f := setupTokenExchangeFixture(t)
	actorAssertion := buildAssertion(t, f.SubAgentKey, f.SubAgentWIMSEURI)
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": f.OrchestratorToken,
		"actor_token":   actorAssertion,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	delegated, _ := decode(t, resp)["access_token"].(string)

	intro := introspect(t, delegated)
	require.Equal(t, true, intro["active"])
	assert.Equal(t, f.SubAgentWIMSEURI, intro["sub"],
		"delegated token's sub MUST be the actor (sub-agent)")

	act, ok := intro["act"].(map[string]any)
	require.True(t, ok, "delegated token MUST carry act claim")
	assert.Equal(t, f.OrchestratorWIMSEURI, act["sub"],
		"act.sub MUST equal the delegating principal's identifier (orchestrator's WIMSE URI)")
}

// ── RFC 8693 — Revoked subject_token rejected ──────────────────────────────

func TestRFC8693_RevokedSubjectTokenRejected(t *testing.T) {
	// RFC 8693 inherits RFC 6749 §5.2: "invalid_grant ... The provided
	//   authorization grant ... is invalid, expired, revoked". A revoked
	//   subject_token MUST NOT mint a successor delegated token.
	f := setupTokenExchangeFixture(t)
	actorAssertion := buildAssertion(t, f.SubAgentKey, f.SubAgentWIMSEURI)

	// Revoke the orchestrator's token first.
	rev := post(t, "/oauth2/token/revoke", map[string]any{
		"token": f.OrchestratorToken,
	}, nil)
	require.Equal(t, http.StatusOK, rev.StatusCode)
	_ = rev.Body.Close()

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": f.OrchestratorToken,
		"actor_token":   actorAssertion,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"token_exchange with a revoked subject_token MUST be rejected")
	body := decode(t, resp)
	assert.Equal(t, "invalid_grant", body["error"])
}

// ── RFC 8693 — Actor signed by wrong key rejected ──────────────────────────

func TestRFC8693_ActorTokenSignedByWrongKeyRejected(t *testing.T) {
	// RFC 8693 §1.2 inherits RFC 7521/7523: the actor's assertion is a
	// JWT-bearer-style signed object. An actor_token signed by a key NOT
	// registered for the sub-agent identity MUST be rejected at signature
	// verification.
	f := setupTokenExchangeFixture(t)
	attackerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	// Sign an actor assertion for the sub-agent's WIMSE URI using a key
	// the sub-agent doesn't actually own.
	now := time.Now()
	b := jwt.NewBuilder().
		Issuer(f.SubAgentWIMSEURI).
		Subject(f.SubAgentWIMSEURI).
		Audience([]string{testIssuer}).
		IssuedAt(now).
		Expiration(now.Add(5 * time.Minute)).
		JwtID(uuid.New().String())
	tok, err := b.Build()
	require.NoError(t, err)
	bad, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), attackerKey))
	require.NoError(t, err)

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": f.OrchestratorToken,
		"actor_token":   string(bad),
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body := decode(t, resp)
	assert.Equal(t, "invalid_grant", body["error"],
		"actor_token signed by an unregistered key MUST be rejected")
}
