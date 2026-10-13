package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/service"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// exchangeMCPCode runs an authorization_code exchange for the MCP test client
// (which holds the refresh_token grant) and returns the access and refresh
// tokens.
func exchangeMCPCode(t *testing.T, userID string) (accessToken, refreshToken string) {
	t.Helper()
	verifier, challenge := buildPKCEPair(t)
	code := buildAuthCode(t, testMCPClientID, userID, testRedirectURI, challenge, []string{"data:read"})
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "authorization_code",
		"client_id":     testMCPClientID,
		"code":          code,
		"code_verifier": verifier,
		"redirect_uri":  testRedirectURI,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	accessToken, _ = body["access_token"].(string)
	refreshToken, _ = body["refresh_token"].(string)
	require.NotEmpty(t, accessToken)
	require.NotEmpty(t, refreshToken)
	return accessToken, refreshToken
}

// refreshMCP presents a refresh token for the MCP test client and returns the
// status and decoded body.
func refreshMCP(t *testing.T, refreshToken string) (int, map[string]any) {
	t.Helper()
	status, raw := rotateRaw(t, refreshToken)
	var body map[string]any
	require.NoError(t, json.Unmarshal(raw, &body), "refresh response must be JSON: %s", raw)
	return status, body
}

// TestRefreshTokenConcurrentRotation pins the rotation race (RFC 6749 §6) and
// its RFC 9700 §4.14.2 consequence. Concurrent POSTs with the same refresh
// token: exactly one wins the claim and gets a successor; the rest present a
// token that has by then been rotated, which is the reuse signal, so the
// family is revoked — the winner's successor and every access token issued
// from the family included.
//
// Before the claim was made atomic, both rotations could pass the active check
// before either committed, both minted successors, and reuse detection never
// fired at all.
func TestRefreshTokenConcurrentRotation(t *testing.T) {
	// Two is the case the guarantee is hardest for: with a single loser there
	// is exactly one revocation sweep, and the winner's access token may be
	// minted after it. Ten exercises the claim under heavier contention. The
	// two-way race is repeated because the interleaving is timing-dependent.
	for i := range 10 {
		t.Run(fmt.Sprintf("two-way/%d", i), func(t *testing.T) { assertConcurrentRotation(t, 2) })
	}
	t.Run("ten-way", func(t *testing.T) { assertConcurrentRotation(t, 10) })
}

func assertConcurrentRotation(t *testing.T, concurrency int) {
	originalAT, refreshToken := exchangeMCPCode(t, uid("user-race"))

	var (
		successes   int32
		failures    int32
		winnerMu    sync.Mutex
		winnerRT    string
		winnerAT    string
		loserErrors []string
		wg          sync.WaitGroup
	)
	start := make(chan struct{})

	for range concurrency {
		wg.Go(func() {
			<-start
			status, body := rotateRaw(t, refreshToken)
			var parsed map[string]any
			_ = json.Unmarshal(body, &parsed)
			winnerMu.Lock()
			defer winnerMu.Unlock()
			if status == http.StatusOK {
				atomic.AddInt32(&successes, 1)
				winnerRT, _ = parsed["refresh_token"].(string)
				winnerAT, _ = parsed["access_token"].(string)
			} else {
				atomic.AddInt32(&failures, 1)
				e, _ := parsed["error"].(string)
				loserErrors = append(loserErrors, e)
			}
		})
	}

	close(start)
	wg.Wait()

	// Exactly one successor minted.
	require.Equal(t, int32(1), atomic.LoadInt32(&successes),
		"exactly one concurrent rotation should succeed")
	assert.Equal(t, int32(concurrency-1), atomic.LoadInt32(&failures),
		"all other concurrent rotations should be rejected")
	for _, e := range loserErrors {
		assert.Equal(t, "invalid_grant", e, "a losing rotation is answered invalid_grant")
	}

	// The losers presented a rotated token, so the family is revoked: the
	// winner's successor no longer rotates...
	require.NotEmpty(t, winnerRT, "should have captured the winner's refresh_token")
	status, body := refreshMCP(t, winnerRT)
	assert.Equal(t, http.StatusBadRequest, status,
		"the winner's successor must be revoked with its family once a rotated token was presented")
	assert.Equal(t, "invalid_grant", body["error"])

	// ...and no access token issued from the family is still active: neither
	// the authorization_code exchange's nor the one the winner just received
	// (which may have been minted after the losers' revocation sweep ran).
	assert.False(t, introspect(t, originalAT)["active"].(bool),
		"the authorization_code access token must be revoked with the family")
	require.NotEmpty(t, winnerAT)
	assert.False(t, introspect(t, winnerAT)["active"].(bool),
		"the winner's access token must be revoked with the family")
}

// TestRefreshTokenConcurrentRotation_WinnerMintsAfterRevocation forces the
// interleaving the timing-dependent race above rarely produces: the loser
// revokes the family — refresh tokens, then the family's access tokens —
// BEFORE the winner has inserted its access token. The loser's sweep cannot
// see a row that does not exist yet, so only the winner's own re-check after
// minting stops that access token surviving the family.
//
// The ordering is forced by holding a SHARE lock on issued_credentials: reads
// (the loser's sweep) proceed, inserts (the winner's access token) wait. Safe
// because no integration test runs in parallel.
func TestRefreshTokenConcurrentRotation_WinnerMintsAfterRevocation(t *testing.T) {
	ctx := context.Background()
	exchangeAT, refreshToken := exchangeMCPCode(t, uid("user-race-late-mint"))

	// Retire the exchange's own access token first, so the loser's sweep finds
	// nothing to update and is not itself held by the lock below.
	resp := post(t, "/oauth2/token/revoke", map[string]any{"token": exchangeAT}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()
	require.False(t, introspect(t, exchangeAT)["active"].(bool))

	tx, err := testDB.BeginTx(ctx, nil)
	require.NoError(t, err)
	released := false
	release := func() {
		if !released {
			released = true
			require.NoError(t, tx.Rollback())
		}
	}
	t.Cleanup(release)
	_, err = tx.ExecContext(ctx, "LOCK TABLE issued_credentials IN SHARE MODE")
	require.NoError(t, err)

	type result struct {
		status int
		body   map[string]any
	}
	results := make(chan result, 2)
	for range 2 {
		go func() {
			status, raw := rotateRaw(t, refreshToken)
			var body map[string]any
			_ = json.Unmarshal(raw, &body)
			results <- result{status, body}
		}()
	}

	// The loser never touches issued_credentials for writing on this path, so
	// it answers while the winner is still blocked on its insert.
	var loser result
	select {
	case loser = <-results:
	case <-time.After(10 * time.Second):
		t.Fatal("neither rotation returned while the winner's insert was held")
	}
	require.Equal(t, http.StatusBadRequest, loser.status, "the first answer must be the loser's")
	assert.Equal(t, "invalid_grant", loser.body["error"])

	release()
	var winner result
	select {
	case winner = <-results:
	case <-time.After(10 * time.Second):
		t.Fatal("the winner did not complete after the lock was released")
	}
	require.Equal(t, http.StatusOK, winner.status, "exactly one rotation succeeds")

	winnerAT, _ := winner.body["access_token"].(string)
	winnerRT, _ := winner.body["refresh_token"].(string)
	require.NotEmpty(t, winnerAT)
	assert.False(t, introspect(t, winnerAT)["active"].(bool),
		"an access token minted after its family was revoked must not survive")
	status, _ := refreshMCP(t, winnerRT)
	assert.Equal(t, http.StatusBadRequest, status, "the winner's successor is revoked with the family")
}

// TestRefreshTokenReuseRevokesFamilyImmediately pins RFC 9700 §4.14.2 for the
// sequential case. A client rotates rt1 → rt2, then rt1 is presented again,
// straight away. The replay is refused, and the newest token in the family
// (rt2) must be refused too, along with every access token minted from the
// family. There is no window after a rotation in which a replay is waved
// through as a retry: the server cannot tell which party holds rt2.
func TestRefreshTokenReuseRevokesFamilyImmediately(t *testing.T) {
	at1, rt1 := exchangeMCPCode(t, uid("user-reuse-immediate"))

	status, body := refreshMCP(t, rt1)
	require.Equal(t, http.StatusOK, status)
	rt2, _ := body["refresh_token"].(string)
	at2, _ := body["access_token"].(string)
	require.NotEmpty(t, rt2)
	require.NotEmpty(t, at2)
	require.True(t, introspect(t, at2)["active"].(bool), "precondition: the refreshed access token is active")

	// The response to the replay is byte-for-byte the response to a token the
	// server has never seen: it must not tell the presenter that reuse was
	// detected.
	unknownStatus, unknownBody := refreshMCP(t, "zid_rt_"+uid("never-issued"))

	status, body = refreshMCP(t, rt1)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", body["error"])
	assert.Equal(t, unknownStatus, status, "a replay is answered like any unusable refresh token")
	assert.Equal(t, unknownBody, body, "a replay is answered like any unusable refresh token")

	status, body = refreshMCP(t, rt2)
	assert.Equal(t, http.StatusBadRequest, status,
		"rt2 must be revoked once its rotated-out predecessor was presented again")
	assert.Equal(t, "invalid_grant", body["error"])

	assert.False(t, introspect(t, at1)["active"].(bool),
		"the access token from the authorization_code exchange must be revoked with the family")
	assert.False(t, introspect(t, at2)["active"].(bool),
		"the access token minted by the refresh must be revoked with the family")
}

// TestRefreshTokenReuseLeavesOtherFamiliesAlone bounds the revocation: reuse
// in one family revokes that family only — another session of the same user
// and client keeps working.
func TestRefreshTokenReuseLeavesOtherFamiliesAlone(t *testing.T) {
	user := uid("user-reuse-isolation")
	_, victimRT := exchangeMCPCode(t, user)
	otherAT, otherRT := exchangeMCPCode(t, user)

	status, _ := refreshMCP(t, victimRT)
	require.Equal(t, http.StatusOK, status)
	status, _ = refreshMCP(t, victimRT) // reuse → victim family revoked
	require.Equal(t, http.StatusBadRequest, status)

	assert.True(t, introspect(t, otherAT)["active"].(bool),
		"an access token from another family must survive")
	status, _ = refreshMCP(t, otherRT)
	assert.Equal(t, http.StatusOK, status, "another family of the same user must still rotate")
}

// TestRefreshTokenRetryAfterServerFailureRotates drives RestoreRotation end
// to end through the refresh grant. The server consumes the presented token,
// then fails to mint the access token (forced here by a trigger that rejects
// the insert for this one user). The client never received a successor, so it
// retries with the token it holds — and that retry must rotate normally rather
// than be treated as reuse and revoke the family.
func TestRefreshTokenRetryAfterServerFailureRotates(t *testing.T) {
	ctx := context.Background()
	user := uid("user-restore-e2e")
	at1, rt1 := exchangeMCPCode(t, user)

	fn := "zeroid_test_fail_refresh_" + strings.ReplaceAll(uid(""), "-", "_")
	_, err := testDB.ExecContext(ctx, fmt.Sprintf(`
CREATE FUNCTION %[1]s() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
	IF NEW.grant_type = 'refresh_token' AND NEW.principal_sub = '%[2]s' THEN
		RAISE EXCEPTION 'forced failure for %[2]s';
	END IF;
	RETURN NEW;
END $$;
CREATE TRIGGER %[1]s BEFORE INSERT ON issued_credentials
	FOR EACH ROW EXECUTE FUNCTION %[1]s();`, fn, user))
	require.NoError(t, err)
	dropped := false
	drop := func() {
		if !dropped {
			dropped = true
			_, err := testDB.ExecContext(ctx, fmt.Sprintf(
				"DROP TRIGGER IF EXISTS %[1]s ON issued_credentials; DROP FUNCTION IF EXISTS %[1]s();", fn))
			require.NoError(t, err)
		}
	}
	t.Cleanup(drop)

	status, _ := refreshMCP(t, rt1)
	require.GreaterOrEqual(t, status, 500, "precondition: access-token issuance failed after the rotation")

	drop()

	status, body := refreshMCP(t, rt1)
	require.Equal(t, http.StatusOK, status,
		"the retry with the presented token must rotate, not be treated as reuse: %v", body)
	rt2, _ := body["refresh_token"].(string)
	require.NotEmpty(t, rt2)

	assert.True(t, introspect(t, at1)["active"].(bool), "the family was not revoked")
	status, _ = refreshMCP(t, rt2)
	assert.Equal(t, http.StatusOK, status, "the family keeps rotating")
}

// TestRefreshTokenRestoreRotation pins the one retry that must NOT be treated
// as reuse: the server consumed the presented token and stored a successor,
// then failed before answering. RestoreRotation puts the presented token back
// so the client's retry with it rotates normally — and refuses to resurrect
// anything once the family has been revoked.
func TestRefreshTokenRestoreRotation(t *testing.T) {
	ctx := context.Background()
	svc := service.NewRefreshTokenService(postgres.NewRefreshTokenRepository(testDB), testDB)

	issue := func(t *testing.T) string {
		t.Helper()
		res, err := svc.IssueRefreshToken(ctx, &service.RefreshTokenParams{
			ClientID:  testMCPClientID,
			AccountID: testAccountID,
			ProjectID: testProjectID,
			UserID:    uid("user-restore"),
			Scopes:    "data:read",
		})
		require.NoError(t, err)
		return res.RawToken
	}

	t.Run("an unused successor is undone and the presented token rotates again", func(t *testing.T) {
		raw := issue(t)
		claimed, successor, err := svc.RotateRefreshToken(ctx, raw, 0, "")
		require.NoError(t, err)

		restored, err := svc.RestoreRotation(ctx, claimed, successor)
		require.NoError(t, err)
		assert.True(t, restored)

		active, err := svc.IsRefreshTokenActive(ctx, raw)
		require.NoError(t, err)
		assert.True(t, active, "the presented token is active again")
		active, err = svc.IsRefreshTokenActive(ctx, successor.RawToken)
		require.NoError(t, err)
		assert.False(t, active, "the undone successor is gone")

		_, next, err := svc.RotateRefreshToken(ctx, raw, 0, "")
		require.NoError(t, err, "the retry rotates instead of tripping reuse detection")
		active, err = svc.IsRefreshTokenActive(ctx, next.RawToken)
		require.NoError(t, err)
		assert.True(t, active, "the family survives the retry")
	})

	t.Run("nothing is restored once reuse revoked the family", func(t *testing.T) {
		raw := issue(t)
		claimed, successor, err := svc.RotateRefreshToken(ctx, raw, 0, "")
		require.NoError(t, err)

		_, _, err = svc.RotateRefreshToken(ctx, raw, 0, "")
		var reuse *service.RefreshTokenReuseError
		require.ErrorAs(t, err, &reuse, "presenting the rotated token is reuse")
		assert.Equal(t, claimed.FamilyID, reuse.FamilyID)

		restored, err := svc.RestoreRotation(ctx, claimed, successor)
		require.NoError(t, err)
		assert.False(t, restored, "a revoked family must not be brought back")

		for _, tok := range []string{raw, successor.RawToken} {
			active, err := svc.IsRefreshTokenActive(ctx, tok)
			require.NoError(t, err)
			assert.False(t, active)
		}
	})

	t.Run("a successor that was itself rotated is not undone", func(t *testing.T) {
		raw := issue(t)
		claimed, successor, err := svc.RotateRefreshToken(ctx, raw, 0, "")
		require.NoError(t, err)
		_, third, err := svc.RotateRefreshToken(ctx, successor.RawToken, 0, "")
		require.NoError(t, err)

		restored, err := svc.RestoreRotation(ctx, claimed, successor)
		require.NoError(t, err)
		assert.False(t, restored)

		active, err := svc.IsRefreshTokenActive(ctx, raw)
		require.NoError(t, err)
		assert.False(t, active, "the original stays consumed")
		active, err = svc.IsRefreshTokenActive(ctx, third.RawToken)
		require.NoError(t, err)
		assert.True(t, active, "the live token is untouched")
	})
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
