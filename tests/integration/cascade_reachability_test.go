// Regression suite for the cascade-revocation reachability fixes.
//
// The bug cluster: (1) token_exchange issued delegated children with no
// expiry bound from the parent, so children routinely outlived their
// parents; (2) the cascade-revocation SQL (migrations 007/029) required
// every node in the recursive walk to be live, so an expired or revoked
// INTERMEDIATE stopped traversal and its still-live descendants were never
// revoked; (3) the cleanup worker hard-deleted expired credential rows
// immediately, severing the parent_jti edges the walk depends on.
//
// Fixes under test:
//   - tokenExchange passes CredentialExpiresAt = subject credential expiry
//     (child exp clamped to parent).
//   - Migration 031 moves the liveness filters from the traversal legs to
//     the final UPDATE, so the walk passes through dead intermediates.
//
// This file also pins two adjacent single-fix regressions from the same
// review: WIMSE proof-token single-use under concurrency (atomic claim in
// MarkUsed) and attestation-expiry enforcement in GetHighestVerifiedLevel.

package integration_test

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/domain"
)

// tokenClaims extracts jti and exp from a token without verifying the
// signature — fine for tests; the server signed it moments ago.
func tokenClaims(t *testing.T, tokenStr string) (jti string, exp time.Time) {
	t.Helper()
	parsed, err := jwt.ParseInsecure([]byte(tokenStr))
	require.NoError(t, err)
	jti, _ = parsed.JwtID()
	exp, _ = parsed.Expiration()
	return jti, exp
}

// setCredentialExpiryInDB rewrites the issued_credentials row's expires_at
// directly, simulating a credential whose DB lifetime has been shortened
// (or has lapsed) after issuance.
func setCredentialExpiryInDB(t *testing.T, jti string, expiresAt time.Time) {
	t.Helper()
	res, err := testDB.NewUpdate().
		TableExpr("issued_credentials").
		Set("expires_at = ?", expiresAt.UTC()).
		Where("jti = ?", jti).
		Exec(context.Background())
	require.NoError(t, err, "setCredentialExpiryInDB: direct UPDATE failed")
	n, err := res.RowsAffected()
	require.NoError(t, err)
	require.EqualValues(t, 1, n, "setCredentialExpiryInDB: expected exactly one row for jti %s", jti)
}

// mintOrchestratorToken registers an identity + confidential client and
// returns a client_credentials access token for it, plus the identity.
func mintOrchestratorToken(t *testing.T, prefix string) (string, identityResp) {
	t.Helper()
	ext := uid(prefix)
	identity := registerIdentity(t, ext, []string{"data:read"})
	client := registerOAuthClient(t, ext, []string{"data:read"})
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	token, _ := decode(t, resp)["access_token"].(string)
	require.NotEmpty(t, token)
	return token, identity
}

// exchangeForSubAgent runs an RFC 8693 token exchange from subjectToken to a
// freshly registered sub-agent and returns the delegated token.
func exchangeForSubAgent(t *testing.T, subjectToken, prefix string) string {
	t.Helper()
	subKey := generateKey(t)
	subIdentity := registerIdentity(t, uid(prefix), []string{"data:read"}, ecPublicKeyPEM(t, subKey))
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": subjectToken,
		"actor_token":   buildAssertion(t, subKey, subIdentity.WIMSEURI),
		"scope":         "data:read",
	}, nil)
	body := decode(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode, "token exchange failed: %v", body)
	token, _ := body["access_token"].(string)
	require.NotEmpty(t, token)
	return token
}

// TestTokenExchangeChildClampedToParentExpiry pins the invariant that a
// delegated credential never outlives the subject credential it was
// exchanged from. Without the clamp, an exchange late in the parent's
// lifetime mints a child with the full default TTL — and once the parent
// expires, the revocation cascade loses its only path to the child.
func TestTokenExchangeChildClampedToParentExpiry(t *testing.T) {
	orchToken, _ := mintOrchestratorToken(t, "clamp-orch")
	orchJTI, _ := tokenClaims(t, orchToken)

	// Shorten the parent's remaining lifetime to 45s. The parent JWT's own
	// exp claim is untouched (still far in the future), so the subject_token
	// still validates — only the credential row's authority window shrinks.
	parentExpiry := time.Now().Add(45 * time.Second)
	setCredentialExpiryInDB(t, orchJTI, parentExpiry)

	childToken := exchangeForSubAgent(t, orchToken, "clamp-sub")
	_, childExp := tokenClaims(t, childToken)

	assert.LessOrEqual(t, childExp.Unix(), parentExpiry.Unix()+2,
		"delegated child exp (%s) must not outlive parent credential expiry (%s); slack 2s",
		childExp.UTC(), parentExpiry.UTC())
}

// TestCascadeRevocationWalksThroughExpiredIntermediate pins the migration
// 031 traversal fix on the credential-anchored cascade (RFC 7009 revoke):
// revoking the root must reach a live grandchild even when the credential
// between them has already expired.
func TestCascadeRevocationWalksThroughExpiredIntermediate(t *testing.T) {
	orchToken, _ := mintOrchestratorToken(t, "walk-orch")
	depth1Token := exchangeForSubAgent(t, orchToken, "walk-sub1")
	depth2Token := exchangeForSubAgent(t, depth1Token, "walk-sub2")

	require.True(t, introspect(t, orchToken)["active"].(bool))
	require.True(t, introspect(t, depth1Token)["active"].(bool))
	require.True(t, introspect(t, depth2Token)["active"].(bool))

	// Kill the intermediate by expiry (not revocation): its row stays in the
	// DB but is no longer live. Pre-031, the recursive walk refused to pass
	// through it and the grandchild survived the root's revocation.
	depth1JTI, _ := tokenClaims(t, depth1Token)
	setCredentialExpiryInDB(t, depth1JTI, time.Now().Add(-time.Minute))

	resp := post(t, "/oauth2/token/revoke", map[string]any{"token": orchToken}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	assert.False(t, introspect(t, orchToken)["active"].(bool),
		"root token must be inactive after revoke")
	assert.False(t, introspect(t, depth2Token)["active"].(bool),
		"grandchild must be revoked even though the intermediate credential expired before the cascade ran")
}

// TestCascadeRevocationFromIdentityWithExpiredAnchor pins the migration 031
// anchor fix on the identity-anchored cascade (CAE signals / deactivation):
// a critical signal against an identity whose own credential has already
// expired must still revoke that credential's live delegated children.
func TestCascadeRevocationFromIdentityWithExpiredAnchor(t *testing.T) {
	orchToken, orchIdentity := mintOrchestratorToken(t, "anchor-orch")
	depth1Token := exchangeForSubAgent(t, orchToken, "anchor-sub1")
	require.True(t, introspect(t, depth1Token)["active"].(bool))

	// Expire the anchor credential. Pre-031, the anchor leg's liveness
	// filter matched zero rows, the walk never started, and the child kept
	// working despite a CRITICAL signal against its delegator.
	orchJTI, _ := tokenClaims(t, orchToken)
	setCredentialExpiryInDB(t, orchJTI, time.Now().Add(-time.Minute))

	signalResp := post(t, adminPath("/signals/ingest"), map[string]any{
		"identity_id": orchIdentity.ID,
		"signal_type": "anomalous_behavior",
		"severity":    "critical",
		"source":      "integration-test",
		"payload":     map[string]any{"reason": "expired-anchor cascade regression"},
	}, adminHeaders())
	require.Equal(t, http.StatusCreated, signalResp.StatusCode)
	_ = signalResp.Body.Close()

	// Signal-triggered revocation is asynchronous; poll instead of a fixed
	// sleep so the test converges fast locally and tolerates CI load. The
	// loop stays in the test goroutine because introspect uses require
	// (FailNow must not be called from a polling goroutine, which rules
	// out assert.Eventually here).
	deadline := time.Now().Add(2 * time.Second)
	for introspect(t, depth1Token)["active"].(bool) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	assert.False(t, introspect(t, depth1Token)["active"].(bool),
		"delegated child must be revoked even though the anchor credential expired before the signal fired")
}

// TestProofTokenSingleUseUnderConcurrency pins the atomic-claim fix in
// ProofRepository.MarkUsed: N concurrent verifications of the same WPT must
// yield exactly one success. The previous read-then-mark sequence let every
// concurrent caller observe is_used = FALSE and all succeed.
func TestProofTokenSingleUseUnderConcurrency(t *testing.T) {
	agentKey := generateKey(t)
	ext := uid("proof-race")
	identity := registerIdentity(t, ext, []string{"data:read"}, ecPublicKeyPEM(t, agentKey))

	tokResp := post(t, "/oauth2/token", map[string]any{
		"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
		"subject":    buildAssertion(t, agentKey, identity.WIMSEURI),
		"scope":      "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, tokResp.StatusCode)
	accessTok, _ := decode(t, tokResp)["access_token"].(string)

	const audience = "https://target.example.com"
	proofResp := post(t, adminPath("/proof/generate"), map[string]any{
		"identity_id": identity.ID,
		"audience":    audience,
		"nonce":       "race-nonce-" + ext,
	}, map[string]string{"Authorization": "Bearer " + accessTok})
	proofBody := decode(t, proofResp)
	require.Equal(t, http.StatusOK, proofResp.StatusCode, "proof generation failed: %v", proofBody)
	proofToken, _ := proofBody["proof_token"].(string)
	require.NotEmpty(t, proofToken)

	// Pre-build one request per goroutine (requests are single-use), then
	// fire them all at once. Assertions stay in the test goroutine —
	// require.* must not run inside the workers.
	const workers = 12
	requests := make([]*http.Request, workers)
	for i := range requests {
		requests[i] = newRequest(t, http.MethodPost, adminPath("/proof/verify"), map[string]any{
			"proof_token": proofToken,
			"audience":    audience,
		}, adminHeaders())
	}

	statuses := make([]int, workers)
	errs := make([]error, workers)
	var start, done sync.WaitGroup
	start.Add(1)
	done.Add(workers)
	for i := range requests {
		go func(i int) {
			defer done.Done()
			start.Wait() // line up all workers before releasing
			resp, err := http.DefaultClient.Do(requests[i])
			if err != nil {
				errs[i] = err
				return
			}
			statuses[i] = resp.StatusCode
			_ = resp.Body.Close()
		}(i)
	}
	start.Done()
	done.Wait()

	successes := 0
	for i := range statuses {
		require.NoError(t, errs[i])
		switch statuses[i] {
		case http.StatusOK:
			successes++
		case http.StatusUnauthorized:
			// expected for every loser
		default:
			t.Fatalf("unexpected status %d from concurrent proof verification", statuses[i])
		}
	}
	assert.Equal(t, 1, successes,
		"exactly one of %d concurrent verifications of the same proof token may succeed", workers)
}

// TestExpiredAttestationNoLongerSatisfiesPolicy pins the wall-clock
// expires_at predicate in GetHighestVerifiedLevel: an attestation past its
// expiry must stop satisfying a policy's required_attestation gate, even
// though no sweep has flipped is_expired.
//
// The verified attestation record is inserted directly via testDB rather
// than through /attestation/submit + /verify: this test pins the READ path
// (the policy gate's level query), and going through the verifier would
// couple it to whatever AttestationPolicy earlier tests left on the shared
// tenant. The inserted row is exactly what a successful verification
// writes: is_verified = TRUE, is_expired = FALSE, expires_at set.
func TestExpiredAttestationNoLongerSatisfiesPolicy(t *testing.T) {
	ext := uid("attest-expiry")
	policyID := createRichCredentialPolicy(t, map[string]any{
		"name":                 uid("attest-expiry-policy"),
		"allowed_grant_types":  []string{"client_credentials"},
		"required_attestation": "software",
		"max_ttl_seconds":      3600,
	}, adminHeaders())
	identityID := registerIdentityWithPolicy(t, ext, policyID, "", []string{"data:read"}, adminHeaders())
	client := registerOAuthClient(t, ext, []string{"data:read"})

	mint := func() *http.Response {
		return post(t, "/oauth2/token", map[string]any{
			"grant_type":    "client_credentials",
			"client_id":     client.ClientID,
			"client_secret": client.ClientSecret,
			"account_id":    testAccountID,
			"project_id":    testProjectID,
			"scope":         "data:read",
		}, nil)
	}

	// No attestation yet → policy gate must refuse.
	resp := mint()
	require.NotEqual(t, http.StatusOK, resp.StatusCode,
		"policy requires software attestation; issuance without one must fail")
	_ = resp.Body.Close()

	// Insert a verified software attestation with a future expiry — the
	// exact row state a successful verification leaves behind.
	now := time.Now().UTC()
	futureExpiry := now.Add(time.Hour)
	record := &domain.AttestationRecord{
		ID:         uuid.New().String(),
		IdentityID: identityID,
		AccountID:  testAccountID,
		ProjectID:  testProjectID,
		Level:      domain.AttestationLevelSoftware,
		ProofType:  domain.ProofTypeOIDCToken,
		ProofValue: "test-proof",
		ProofHash:  "test-proof-hash",
		VerifiedAt: &now,
		IsVerified: true,
		ExpiresAt:  &futureExpiry,
		CreatedAt:  now,
	}
	_, err := testDB.NewInsert().Model(record).Exec(context.Background())
	require.NoError(t, err, "failed to insert verified attestation record")

	// Read back through the same predicates the policy gate uses, so a
	// failure here localizes to the insert rather than the gate.
	var insertedLevel string
	err = testDB.NewSelect().
		TableExpr("attestation_records").
		ColumnExpr("level").
		Where("identity_id = ?", identityID).
		Where("is_verified = TRUE").
		Scan(context.Background(), &insertedLevel)
	require.NoError(t, err, "inserted attestation record not found")
	require.Equal(t, "software", insertedLevel)

	// With a fresh verified attestation the gate opens.
	resp = mint()
	mintBody := decode(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"verified attestation must satisfy the policy gate: %v", mintBody)

	// Lapse the attestation by wall clock only — is_expired stays FALSE,
	// exactly the state the old query treated as still-valid forever.
	res, err := testDB.NewUpdate().
		TableExpr("attestation_records").
		Set("expires_at = ?", time.Now().Add(-time.Hour).UTC()).
		Where("identity_id = ?", identityID).
		Exec(context.Background())
	require.NoError(t, err)
	n, err := res.RowsAffected()
	require.NoError(t, err)
	require.GreaterOrEqual(t, n, int64(1), "expected to lapse at least one attestation record")

	resp = mint()
	assert.NotEqual(t, http.StatusOK, resp.StatusCode,
		"an attestation past expires_at must no longer satisfy required_attestation")
	_ = resp.Body.Close()
}
