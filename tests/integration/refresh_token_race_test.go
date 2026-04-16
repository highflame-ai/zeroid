package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// TestRefreshTokenConcurrentRotation closes the RFC 6749 §6 rotation race:
// two concurrent POSTs with the same refresh token must not both issue a
// successor. Exactly one request wins and receives a new token; the rest are
// rejected with invalid_grant.
//
// Before the fix, the read-check-revoke sequence ran under READ COMMITTED
// (despite the comment claiming "serializable"), so both rotations passed the
// active check before either committed the revocation — both then minted new
// tokens, bypassing reuse detection entirely.
func TestRefreshTokenConcurrentRotation(t *testing.T) {
	const concurrency = 10

	// Acquire a single refresh token via the authorization_code flow.
	verifier, challenge := buildPKCEPair(t)
	code := buildAuthCode(t, testMCPClientID, "user-race-001", testRedirectURI, challenge, []string{"data:read"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "authorization_code",
		"client_id":     testMCPClientID,
		"code":          code,
		"code_verifier": verifier,
		"redirect_uri":  testRedirectURI,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	refreshToken := decode(t, resp)["refresh_token"].(string)
	require.NotEmpty(t, refreshToken)

	var (
		successes int32
		failures  int32
		wg        sync.WaitGroup
	)
	start := make(chan struct{})

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			status := rotateRaw(t, refreshToken)
			if status == http.StatusOK {
				atomic.AddInt32(&successes, 1)
			} else {
				atomic.AddInt32(&failures, 1)
			}
		}()
	}

	close(start) // release all goroutines at once
	wg.Wait()

	// Security-critical invariant: exactly one successor minted.
	assert.Equal(t, int32(1), atomic.LoadInt32(&successes),
		"exactly one concurrent rotation should succeed")
	assert.Equal(t, int32(concurrency-1), atomic.LoadInt32(&failures),
		"all other concurrent rotations should be rejected")
}

// TestRefreshTokenReuseRevokesFamily verifies family revocation cascades when
// reuse is detected: replaying an already-rotated refresh token must invalidate
// not only the replayed token but every successor in the family (rt2 and
// beyond). Complements TestRefreshTokenRotation, which only checks that the
// replayed token itself is rejected.
func TestRefreshTokenReuseRevokesFamily(t *testing.T) {
	verifier, challenge := buildPKCEPair(t)
	code := buildAuthCode(t, testMCPClientID, "user-reuse-001", testRedirectURI, challenge, []string{"data:read"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "authorization_code",
		"client_id":     testMCPClientID,
		"code":          code,
		"code_verifier": verifier,
		"redirect_uri":  testRedirectURI,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	rt1 := decode(t, resp)["refresh_token"].(string)

	// First rotation: succeeds, yields rt2.
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": rt1,
		"client_id":     testMCPClientID,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	rt2 := decode(t, resp)["refresh_token"].(string)
	require.NotEmpty(t, rt2)

	// Replay rt1 — already revoked → reuse detected → family revoked.
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": rt1,
		"client_id":     testMCPClientID,
	}, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_grant", decode(t, resp)["error"])

	// rt2 must also be dead now — the family was revoked as a unit.
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": rt2,
		"client_id":     testMCPClientID,
	}, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"rt2 must be revoked once reuse was detected on its sibling rt1")
}

// TestRefreshTokenRotationRollbackOnInsertFailure verifies that when the
// successor insert fails during rotation, the Postgres transaction rolls back
// the claim UPDATE and leaves the original token active. This is the specific
// property that protects a client from a transient DB error turning into a
// forced family revocation on retry.
//
// Primarily this pins the contract that repo methods honor the bun.IDB they
// are given — if someone accidentally reverts ClaimByTokenHash or Create to
// use r.db directly, the transaction would no longer cover them and this test
// would fail.
func TestRefreshTokenRotationRollbackOnInsertFailure(t *testing.T) {
	ctx := context.Background()
	repo := postgres.NewRefreshTokenRepository(testDB)

	// Seed two unrelated refresh tokens with known hashes.
	victimHash := "rollback-victim-hash-" + uid("")
	colliderHash := "rollback-collider-hash-" + uid("")

	victim := &domain.RefreshToken{
		TokenHash: victimHash,
		ClientID:  testMCPClientID,
		AccountID: testAccountID,
		ProjectID: testProjectID,
		UserID:    "user-rollback-victim",
		Scopes:    "data:read",
		FamilyID:  "00000000-0000-0000-0000-00000000aaaa",
		State:     domain.RefreshTokenStateActive,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	require.NoError(t, repo.Create(ctx, testDB, victim))

	collider := &domain.RefreshToken{
		TokenHash: colliderHash,
		ClientID:  testMCPClientID,
		AccountID: testAccountID,
		ProjectID: testProjectID,
		UserID:    "user-rollback-collider",
		Scopes:    "data:read",
		FamilyID:  "00000000-0000-0000-0000-00000000bbbb",
		State:     domain.RefreshTokenStateActive,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	require.NoError(t, repo.Create(ctx, testDB, collider))

	// Drive the same claim + insert flow the service uses, but craft the
	// successor to collide with `collider` on token_hash (UNIQUE violation).
	txErr := testDB.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		claimed, err := repo.ClaimByTokenHash(ctx, tx, victimHash)
		if err != nil {
			return err
		}
		require.Equal(t, victimHash, claimed.TokenHash)

		successor := &domain.RefreshToken{
			TokenHash: colliderHash, // forces UNIQUE violation on insert
			ClientID:  claimed.ClientID,
			AccountID: claimed.AccountID,
			ProjectID: claimed.ProjectID,
			UserID:    claimed.UserID,
			Scopes:    claimed.Scopes,
			FamilyID:  claimed.FamilyID,
			State:     domain.RefreshTokenStateActive,
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}
		return repo.Create(ctx, tx, successor)
	})
	require.Error(t, txErr, "successor insert must fail with a UNIQUE violation")

	// The claim UPDATE should have been rolled back — victim must be active.
	got, err := repo.GetByTokenHash(ctx, victimHash)
	require.NoError(t, err, "victim must still be retrievable as an active, non-expired token")
	assert.Equal(t, domain.RefreshTokenStateActive, got.State,
		"claim must have rolled back; victim should not be revoked")

	// A subsequent legitimate claim must now succeed — i.e., the rollback fully
	// restored the row, not just its state column.
	reclaimed, err := repo.ClaimByTokenHash(ctx, testDB, victimHash)
	require.NoError(t, err, "second claim after rollback must succeed")
	assert.Equal(t, domain.RefreshTokenStateRevoked, reclaimed.State,
		"claimed row reflects the revoked state returned by UPDATE RETURNING")
}

// rotateRaw issues a refresh_token grant request directly without going through
// the require-heavy post helper, so it is safe to call from goroutines. Returns
// the HTTP status code, or 0 if the request could not be made (surfaced via
// t.Errorf so a real transport failure doesn't masquerade as a silent miss).
func rotateRaw(t *testing.T, refreshToken string) int {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
		"client_id":     testMCPClientID,
	})
	if err != nil {
		t.Errorf("marshal refresh request: %v", err)
		return 0
	}
	req, err := http.NewRequest(http.MethodPost, testServer.URL+"/oauth2/token", bytes.NewReader(body))
	if err != nil {
		t.Errorf("build refresh request: %v", err)
		return 0
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Errorf("execute refresh request: %v", err)
		return 0
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}
