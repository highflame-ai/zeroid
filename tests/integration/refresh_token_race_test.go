package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
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
// concurrent POSTs with the same refresh token must not both issue a successor.
// Exactly one request wins; the rest are rejected. Additionally, the winner's
// new refresh token MUST survive the race — late-arriving sibling requests
// that see the original as "revoked" must not trip family revocation against
// the fresh successor (handled via the reuse grace window).
//
// Before the fix, the read-check-revoke sequence ran under READ COMMITTED
// (despite a comment claiming "serializable"), so both rotations passed the
// active check before either committed the revocation — both then minted new
// tokens, bypassing reuse detection entirely.
func TestRefreshTokenConcurrentRotation(t *testing.T) {
	const concurrency = 10

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
		successes    int32
		failures     int32
		winnerTokMu  sync.Mutex
		winnerTok    string
		wg           sync.WaitGroup
	)
	start := make(chan struct{})

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			status, body := rotateRaw(t, refreshToken)
			if status == http.StatusOK {
				atomic.AddInt32(&successes, 1)
				// Capture the winner's successor token for the post-race assertion.
				var parsed map[string]any
				if err := json.Unmarshal(body, &parsed); err == nil {
					if rt, ok := parsed["refresh_token"].(string); ok {
						winnerTokMu.Lock()
						winnerTok = rt
						winnerTokMu.Unlock()
					}
				}
			} else {
				atomic.AddInt32(&failures, 1)
			}
		}()
	}

	close(start)
	wg.Wait()

	// Primary invariant: exactly one successor minted.
	assert.Equal(t, int32(1), atomic.LoadInt32(&successes),
		"exactly one concurrent rotation should succeed")
	assert.Equal(t, int32(concurrency-1), atomic.LoadInt32(&failures),
		"all other concurrent rotations should be rejected")

	// Secondary invariant (grace window): the winner's new refresh token must
	// survive — losing siblings that saw the original as revoked must not have
	// tripped family revocation against it.
	require.NotEmpty(t, winnerTok, "should have captured the winner's refresh_token")
	status, _ := rotateRaw(t, winnerTok)
	assert.Equal(t, http.StatusOK, status,
		"winner's successor token must remain usable after the race (grace window protects it)")
}

// TestRefreshTokenReuseWithinGraceWindowProtectsFamily verifies that a replay
// arriving within the grace window returns a benign "already rotated" error
// without nuking the family. Simulates a legitimate concurrent-retry scenario
// (multi-tab, network retry) where the second request loses but the session —
// represented by the freshly issued successor — must survive.
func TestRefreshTokenReuseWithinGraceWindowProtectsFamily(t *testing.T) {
	verifier, challenge := buildPKCEPair(t)
	code := buildAuthCode(t, testMCPClientID, "user-grace-within", testRedirectURI, challenge, []string{"data:read"})

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

	// Replay rt1 immediately — within grace window.
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": rt1,
		"client_id":     testMCPClientID,
	}, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_grant", decode(t, resp)["error"])

	// rt2 MUST still be alive — grace window suppresses family revocation.
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": rt2,
		"client_id":     testMCPClientID,
	}, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"rt2 must remain usable: replay within grace window is treated as concurrent retry, not reuse")
}

// TestRefreshTokenReuseOutsideGraceWindowRevokesFamily verifies that a replay
// arriving after the grace window fires the full RFC 6749 §10.4 reuse-detection
// response: the entire family is revoked.
//
// Rather than sleeping for the grace window duration, the test backdates the
// revoked_at column directly via testDB to simulate a delayed replay.
func TestRefreshTokenReuseOutsideGraceWindowRevokesFamily(t *testing.T) {
	ctx := context.Background()

	verifier, challenge := buildPKCEPair(t)
	code := buildAuthCode(t, testMCPClientID, "user-grace-outside", testRedirectURI, challenge, []string{"data:read"})

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

	// Backdate rt1's revoked_at past the grace window so the next replay hits
	// the reuse-detection path.
	backdate := time.Now().Add(-2 * domain.RefreshTokenReuseGraceWindow)
	_, err := testDB.NewUpdate().
		Model((*domain.RefreshToken)(nil)).
		Set("revoked_at = ?", backdate).
		Where("user_id = ?", "user-grace-outside").
		Where("state = ?", domain.RefreshTokenStateRevoked).
		Exec(ctx)
	require.NoError(t, err)

	// Replay rt1 — now outside grace window → family revocation fires.
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": rt1,
		"client_id":     testMCPClientID,
	}, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_grant", decode(t, resp)["error"])

	// rt2 must now be dead — the family was revoked as a unit.
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": rt2,
		"client_id":     testMCPClientID,
	}, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"rt2 must be revoked once reuse was detected on its sibling rt1 outside the grace window")
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

	got, err := repo.GetByTokenHash(ctx, victimHash)
	require.NoError(t, err, "victim must still be retrievable as an active, non-expired token")
	assert.Equal(t, domain.RefreshTokenStateActive, got.State,
		"claim must have rolled back; victim should not be revoked")

	reclaimed, err := repo.ClaimByTokenHash(ctx, testDB, victimHash)
	require.NoError(t, err, "second claim after rollback must succeed")
	assert.Equal(t, domain.RefreshTokenStateRevoked, reclaimed.State,
		"claimed row reflects the revoked state returned by UPDATE RETURNING")
}

// rotateRaw issues a refresh_token grant request directly without going through
// the require-heavy post helper, so it is safe to call from goroutines. Returns
// the HTTP status code and response body, or (0, nil) if the request could not
// be made (surfaced via t.Errorf so a real transport failure does not
// masquerade as a silent miss).
func rotateRaw(t *testing.T, refreshToken string) (int, []byte) {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
		"client_id":     testMCPClientID,
	})
	if err != nil {
		t.Errorf("marshal refresh request: %v", err)
		return 0, nil
	}
	req, err := http.NewRequest(http.MethodPost, testServer.URL+"/oauth2/token", bytes.NewReader(body))
	if err != nil {
		t.Errorf("build refresh request: %v", err)
		return 0, nil
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Errorf("execute refresh request: %v", err)
		return 0, nil
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("read refresh response: %v", err)
		return resp.StatusCode, nil
	}
	return resp.StatusCode, respBody
}
