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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"database/sql"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"sync"
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
	// RFC 8693 §4.1: "act ... provides a means within a JWT to express that
	//   delegation has occurred and identify the acting party to whom
	//   authority has been delegated." The subject_token's principal (the
	//   orchestrator) stays the token's sub; the acting party (the sub-agent)
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
	assert.Equal(t, f.OrchestratorWIMSEURI, intro["sub"],
		"delegated token's sub MUST be the subject_token's principal (orchestrator)")

	act, ok := intro["act"].(map[string]any)
	require.True(t, ok, "delegated token MUST carry act claim")
	assert.Equal(t, f.SubAgentWIMSEURI, act["sub"],
		"act.sub MUST equal the acting party's identifier (sub-agent's WIMSE URI)")
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

// ── RFC 8693 — Subject revoked while the exchange runs ─────────────────────

func TestRFC8693_SubjectRevokedBeforeExchangeStoresTokenRejected(t *testing.T) {
	// RFC 8693 inherits RFC 6749 §5.2: "invalid_grant ... The provided
	//   authorization grant ... is invalid, expired, revoked". A subject_token
	//   revoked after the exchange checked it, but before the exchange stored
	//   its token, MUST NOT mint a successor delegated token.
	//
	// The test parks the exchange after its checks by holding
	// issued_credentials in EXCLUSIVE mode, which lets the exchange read
	// credential rows but not lock or write one. While it waits, the test
	// revokes the subject's tree in the lock's own transaction and commits.
	tn := newTenant(t, "")
	scopes := []string{"data:read"}
	policyID := tn.policy(t, scopes)
	root, _ := tn.workloadRoot(t, policyID, scopes)
	actor := rlNewActor(t, tn, policyID, scopes)
	ctx := context.Background()

	var rootID string
	require.NoError(t, testDB.NewRaw(`SELECT id FROM issued_credentials WHERE jti = ?`, rlJTI(t, root)).Scan(ctx, &rootID))

	tx, err := testDB.BeginTx(ctx, &sql.TxOptions{})
	require.NoError(t, err)
	defer tx.Rollback() //nolint:errcheck
	_, err = tx.ExecContext(ctx, `LOCK TABLE issued_credentials IN EXCLUSIVE MODE`)
	require.NoError(t, err)

	type result struct {
		status int
		body   map[string]any
	}
	done := make(chan result, 1)
	go func() {
		status, body := rlExchange(t, actor, scopes, root)
		done <- result{status, body}
	}()
	waiting := rlWaitForLockWait(t, "issued_credentials", []string{"relation"}, done)
	t.Logf("exchange parked on: %.200s", waiting)

	_, err = tx.ExecContext(ctx, `SELECT jti FROM revoke_credential_cascade(?, ?, ?, NOW(), 'test')`,
		rootID, tn.account, tn.project)
	require.NoError(t, err)
	require.NoError(t, tx.Commit())

	r := <-done
	assert.Empty(t, rlLiveBelowRevoked(t, tn), "no live token is left below the revoked subject_token")
	require.Equal(t, http.StatusBadRequest, r.status,
		"an exchange whose subject_token was revoked before its token was stored MUST be rejected: %v", r.body)
	assert.Equal(t, "invalid_grant", r.body["error"])
}

func TestRFC8693_SubjectRevokedConcurrentlyNeverLeavesLiveToken(t *testing.T) {
	// RFC 8693 inherits RFC 6749 §5.2: "invalid_grant ... The provided
	//   authorization grant ... is invalid, expired, revoked". An exchange
	//   racing an RFC 7009 revocation of its subject_token MUST end with the
	//   exchange rejected or its token revoked with the subject, never with
	//   a live token below a revoked one.
	//
	// No help from the test: the exchange and the revocation run at once,
	// the revocation after a random delay of up to 12 ms, ZEROID_RACE_TRIALS
	// times (default 150). The stored row decides a hit, not introspection,
	// which refuses a token below a revoked one even when the row is live.
	trials := 150
	if v := os.Getenv("ZEROID_RACE_TRIALS"); v != "" {
		n, err := strconv.Atoi(v)
		require.NoError(t, err, "ZEROID_RACE_TRIALS")
		trials = n
	}
	tn := newTenant(t, "")
	scopes := []string{"data:read"}
	policyID := tn.policy(t, scopes)
	actor := rlNewActor(t, tn, policyID, scopes)

	var hits, exchanged, rejected, serverErrors int
	for i := range trials {
		root, _ := tn.workloadRoot(t, policyID, scopes)
		n, err := rand.Int(rand.Reader, big.NewInt(12000))
		require.NoError(t, err)
		delay := time.Duration(n.Int64()) * time.Microsecond

		var wg sync.WaitGroup
		var status int
		var body map[string]any
		wg.Add(2)
		go func() { defer wg.Done(); status, body = rlExchange(t, actor, scopes, root) }()
		go func() { defer wg.Done(); time.Sleep(delay); rlRevoke(t, root) }()
		wg.Wait()

		switch {
		case status == http.StatusOK:
			exchanged++
			if !rlRowRevoked(t, rlJTI(t, body["access_token"].(string))) {
				hits++
				t.Logf("trial %d: live token below the revoked subject_token (revoke delayed %s)", i, delay)
			}
		case status >= http.StatusInternalServerError:
			serverErrors++
			t.Logf("trial %d: exchange returned %d: %v", i, status, body)
		default:
			rejected++
		}
	}
	t.Logf("%d trials: %d exchanged (%d left live below a revoked subject_token), %d rejected, %d server errors",
		trials, exchanged, hits, rejected, serverErrors)
	assert.Zero(t, hits, "no exchange leaves a live token below its revoked subject_token")
	assert.Zero(t, serverErrors, "an exchange racing a revocation is rejected, not failed")
	assert.Empty(t, rlLiveBelowRevoked(t, tn))
}

func TestRFC8693_SubjectDelegatedFromRevokedTokenRejected(t *testing.T) {
	// RFC 8693 inherits RFC 6749 §5.2: "invalid_grant ... The provided
	//   authorization grant ... is invalid, expired, revoked". A subject_token
	//   delegated from a revoked token is revoked with it, so it MUST NOT mint
	//   a successor, even where the store still holds its own row unrevoked.
	f := rlRevokedParentFixture(t)
	status, body := rlExchange(t, rlNewActor(t, f.tn, f.policyID, f.scopes), f.scopes, f.child)
	require.Equal(t, http.StatusBadRequest, status,
		"token_exchange from a token below a revoked one MUST be rejected: %v", body)
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
