package integration_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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

// setRefreshReuseGrace sets the shared test server's refresh-token reuse
// grace window for one test and restores the default afterwards. Safe because
// no integration test runs in parallel.
func setRefreshReuseGrace(t *testing.T, d time.Duration) {
	t.Helper()
	testZeroIDServer.SetRefreshReuseGrace(d)
	t.Cleanup(func() { testZeroIDServer.SetRefreshReuseGrace(domain.RefreshTokenReuseGraceWindow) })
}

// backdateRotation moves a rotated-out refresh token's revocation time into
// the past, so presenting it again is judged against the reuse grace window as
// if that much time had passed since the rotation.
func backdateRotation(t *testing.T, rawRefreshToken string, by time.Duration) {
	t.Helper()
	h := sha256.Sum256([]byte(rawRefreshToken))
	res, err := testDB.ExecContext(context.Background(),
		"UPDATE refresh_tokens SET revoked_at = revoked_at - make_interval(secs => ?) WHERE token_hash = ? AND state = 'revoked'",
		by.Seconds(), hex.EncodeToString(h[:]))
	require.NoError(t, err)
	n, err := res.RowsAffected()
	require.NoError(t, err)
	require.Equal(t, int64(1), n, "backdateRotation: the token must be a rotated-out (revoked) row")
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
//
// This is the strict posture (token.refresh_reuse_grace_seconds = 0). With
// the default grace window, see TestRefreshTokenConcurrentRotationWithinGrace.
func TestRefreshTokenConcurrentRotation(t *testing.T) {
	setRefreshReuseGrace(t, 0)
	// Two is the case the guarantee is hardest for: with a single loser there
	// is exactly one revocation sweep, and the winner's access token may be
	// minted after it. Ten exercises the claim under heavier contention. The
	// two-way race is repeated because the interleaving is timing-dependent.
	for i := range 10 {
		t.Run(fmt.Sprintf("two-way/%d", i), func(t *testing.T) { assertConcurrentRotation(t, 2, true) })
	}
	t.Run("ten-way", func(t *testing.T) { assertConcurrentRotation(t, 10, true) })
}

// TestRefreshTokenConcurrentRotationWithinGrace is the same race under the
// default reuse grace window: the losers present a token rotated out moments
// ago in a family that is still live, which is a concurrent retry (several
// tabs or processes sharing one refresh token). They are refused, nothing is
// revoked, and the winner's session carries on.
func TestRefreshTokenConcurrentRotationWithinGrace(t *testing.T) {
	setRefreshReuseGrace(t, domain.RefreshTokenReuseGraceWindow)
	for i := range 5 {
		t.Run(fmt.Sprintf("two-way/%d", i), func(t *testing.T) { assertConcurrentRotation(t, 2, false) })
	}
	t.Run("ten-way", func(t *testing.T) { assertConcurrentRotation(t, 10, false) })
}

func assertConcurrentRotation(t *testing.T, concurrency int, strict bool) {
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

	require.NotEmpty(t, winnerRT, "should have captured the winner's refresh_token")
	require.NotEmpty(t, winnerAT)
	if !strict {
		// Within the grace window the losers were concurrent retries: the
		// family is intact, every access token stays active, and the winner's
		// successor rotates.
		assert.True(t, introspect(t, originalAT)["active"].(bool),
			"a concurrent retry within the grace window must not revoke the family")
		assert.True(t, introspect(t, winnerAT)["active"].(bool),
			"the winner's access token survives a concurrent retry")
		status, body := refreshMCP(t, winnerRT)
		assert.Equal(t, http.StatusOK, status, "the winner's successor still rotates: %v", body)
		return
	}

	// The losers presented a rotated token, so the family is revoked: the
	// winner's successor no longer rotates...
	status, body := refreshMCP(t, winnerRT)
	assert.Equal(t, http.StatusBadRequest, status,
		"the winner's successor must be revoked with its family once a rotated token was presented")
	assert.Equal(t, "invalid_grant", body["error"])

	// ...and no access token issued from the family is still active: neither
	// the authorization_code exchange's nor the one the winner just received
	// (which may have been minted after the losers' revocation sweep ran).
	assert.False(t, introspect(t, originalAT)["active"].(bool),
		"the authorization_code access token must be revoked with the family")
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
	// The loser revokes the family only outside the reuse grace window.
	setRefreshReuseGrace(t, 0)
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
// sequential case with the grace window disabled
// (token.refresh_reuse_grace_seconds = 0). A client rotates rt1 → rt2, then
// rt1 is presented again, straight away. The replay is refused, and the
// newest token in the family (rt2) must be refused too, along with every
// access token minted from the family.
func TestRefreshTokenReuseRevokesFamilyImmediately(t *testing.T) {
	setRefreshReuseGrace(t, 0)
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

// rotateOnce runs an authorization_code exchange and one refresh, returning
// the exchange's tokens (at1, rt1 — rt1 now rotated out) and the refresh's
// (at2, rt2).
func rotateOnce(t *testing.T, user string) (at1, rt1, at2, rt2 string) {
	t.Helper()
	at1, rt1 = exchangeMCPCode(t, uid(user))
	status, body := refreshMCP(t, rt1)
	require.Equal(t, http.StatusOK, status)
	at2, _ = body["access_token"].(string)
	rt2, _ = body["refresh_token"].(string)
	require.NotEmpty(t, at2)
	require.NotEmpty(t, rt2)
	return at1, rt1, at2, rt2
}

// TestRefreshTokenReuseWithinGrace pins the reuse grace window
// (token.refresh_reuse_grace_seconds, default 10s). Presenting a token that
// was rotated out moments ago, in a family that is still live, is a concurrent
// retry: refused with the same invalid_grant as any unusable refresh token,
// nothing issued, and nothing revoked.
func TestRefreshTokenReuseWithinGrace(t *testing.T) {
	setRefreshReuseGrace(t, domain.RefreshTokenReuseGraceWindow)
	at1, rt1, at2, rt2 := rotateOnce(t, "user-reuse-grace")

	unknownStatus, unknownBody := refreshMCP(t, "zid_rt_"+uid("never-issued"))
	status, body := refreshMCP(t, rt1)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", body["error"])
	assert.Equal(t, unknownStatus, status, "a retry is answered like any unusable refresh token")
	assert.Equal(t, unknownBody, body, "a retry is answered like any unusable refresh token")
	assert.NotContains(t, body, "access_token", "nothing is issued to the retry")

	assert.True(t, introspect(t, at1)["active"].(bool), "the family's access tokens are untouched")
	assert.True(t, introspect(t, at2)["active"].(bool), "the successor's access token is untouched")
	status, body = refreshMCP(t, rt2)
	assert.Equal(t, http.StatusOK, status, "the successor still rotates: %v", body)
}

// TestRefreshTokenReuseAfterGrace: the same presentation once the window has
// passed is reuse, and revokes the family and its access tokens. The window is
// the configured one, not a constant: a rotation 60s ago is still within a
// 300s window and already outside a 30s one.
func TestRefreshTokenReuseAfterGrace(t *testing.T) {
	t.Run("outside the default window", func(t *testing.T) {
		setRefreshReuseGrace(t, domain.RefreshTokenReuseGraceWindow)
		at1, rt1, at2, rt2 := rotateOnce(t, "user-reuse-after-grace")
		backdateRotation(t, rt1, time.Hour)

		status, body := refreshMCP(t, rt1)
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Equal(t, "invalid_grant", body["error"])
		assert.False(t, introspect(t, at1)["active"].(bool), "the exchange's access token is revoked with the family")
		assert.False(t, introspect(t, at2)["active"].(bool), "the refreshed access token is revoked with the family")
		status, _ = refreshMCP(t, rt2)
		assert.Equal(t, http.StatusBadRequest, status, "the newest refresh token is revoked with the family")
	})

	t.Run("60s ago is within a 300s window", func(t *testing.T) {
		setRefreshReuseGrace(t, 300*time.Second)
		_, rt1, at2, rt2 := rotateOnce(t, "user-reuse-long-grace")
		backdateRotation(t, rt1, 60*time.Second)

		status, _ := refreshMCP(t, rt1)
		assert.Equal(t, http.StatusBadRequest, status)
		assert.True(t, introspect(t, at2)["active"].(bool), "within the configured window nothing is revoked")
		status, _ = refreshMCP(t, rt2)
		assert.Equal(t, http.StatusOK, status)
	})

	t.Run("60s ago is outside a 30s window", func(t *testing.T) {
		setRefreshReuseGrace(t, 30*time.Second)
		_, rt1, at2, rt2 := rotateOnce(t, "user-reuse-short-grace")
		backdateRotation(t, rt1, 60*time.Second)

		status, _ := refreshMCP(t, rt1)
		assert.Equal(t, http.StatusBadRequest, status)
		assert.False(t, introspect(t, at2)["active"].(bool), "outside the configured window the family is revoked")
		status, _ = refreshMCP(t, rt2)
		assert.Equal(t, http.StatusBadRequest, status)
	})
}

// TestRefreshTokenReuseGraceOnlyCoversRotation: a token revoked by anything
// other than rotation gets no grace, however recently it was revoked. Here the
// family is revoked directly (as reuse detection, RFC 7009 revocation and
// authorization-code replay all do, through RevokeFamily) — which revokes its
// refresh tokens but not its access tokens. Presenting the just-revoked newest
// token must then be treated as reuse, which revokes the family's access
// tokens; a grace refusal would leave them active.
func TestRefreshTokenReuseGraceOnlyCoversRotation(t *testing.T) {
	ctx := context.Background()
	setRefreshReuseGrace(t, domain.RefreshTokenReuseGraceWindow)
	_, _, at2, rt2 := rotateOnce(t, "user-reuse-grace-family-revoked")

	repo := postgres.NewRefreshTokenRepository(testDB)
	h := sha256.Sum256([]byte(rt2))
	row, err := repo.GetByTokenHashIncludingRevoked(ctx, hex.EncodeToString(h[:]))
	require.NoError(t, err)
	n, err := service.NewRefreshTokenService(repo, testDB).RevokeFamily(ctx, row.FamilyID, "test")
	require.NoError(t, err)
	require.Positive(t, n)
	require.True(t, introspect(t, at2)["active"].(bool), "precondition: revoking the refresh tokens left the access token")

	status, body := refreshMCP(t, rt2)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", body["error"])
	assert.False(t, introspect(t, at2)["active"].(bool),
		"a token revoked with its family is reuse even seconds later: no grace, the family's access tokens are revoked")
}

// TestRefreshTokenReuseLeavesOtherFamiliesAlone bounds the revocation: reuse
// in one family revokes that family only — another session of the same user
// and client keeps working.
func TestRefreshTokenReuseLeavesOtherFamiliesAlone(t *testing.T) {
	setRefreshReuseGrace(t, 0)
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

	t.Run("a retry within the grace window leaves the rotation restorable", func(t *testing.T) {
		raw := issue(t)
		claimed, successor, err := svc.RotateRefreshToken(ctx, raw, 0, "")
		require.NoError(t, err)

		_, _, err = svc.RotateRefreshToken(ctx, raw, 0, "")
		require.ErrorIs(t, err, service.ErrRefreshTokenAlreadyRotated, "within the window it is a concurrent retry")

		restored, err := svc.RestoreRotation(ctx, claimed, successor)
		require.NoError(t, err)
		assert.True(t, restored, "the retry revoked nothing, so the unused successor can still be undone")
		active, err := svc.IsRefreshTokenActive(ctx, raw)
		require.NoError(t, err)
		assert.True(t, active)
	})

	t.Run("nothing is restored once reuse revoked the family", func(t *testing.T) {
		svc.SetReuseGrace(0)
		t.Cleanup(func() { svc.SetReuseGrace(domain.RefreshTokenReuseGraceWindow) })
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

// TestRefreshTokenRevokeFamilyRacingRestore pins that a family revocation
// cannot be undone by a RestoreRotation committing at the same moment.
//
// RestoreRotation deletes the unused successor and reactivates the presented
// token in one transaction. A family revocation's UPDATE ... WHERE
// state='active' takes its snapshot before that transaction commits, so it
// sees the presented token as revoked (not a target) and the successor as
// active; it then blocks on the successor's row lock, finds the row deleted
// once the restore commits, and returns having revoked nothing — while the
// presented token is active again. Reuse detection, auth-code replay and
// RFC 7009 revocation would all report a revoked family that still has a
// usable refresh token.
//
// The interleaving is forced: the restore runs inside a transaction this test
// holds open, the revocation is started and observed waiting on its lock, and
// only then is the restore committed.
func TestRefreshTokenRevokeFamilyRacingRestore(t *testing.T) {
	ctx := context.Background()
	repo := postgres.NewRefreshTokenRepository(testDB)
	svc := service.NewRefreshTokenService(repo, testDB)

	issued, err := svc.IssueRefreshToken(ctx, &service.RefreshTokenParams{
		ClientID:  testMCPClientID,
		AccountID: testAccountID,
		ProjectID: testProjectID,
		UserID:    uid("user-restore-race"),
		Scopes:    "data:read",
	})
	require.NoError(t, err)
	claimed, successor, err := svc.RotateRefreshToken(ctx, issued.RawToken, 0, "")
	require.NoError(t, err)

	tx, err := testDB.BeginTx(ctx, nil)
	require.NoError(t, err)
	committed := false
	t.Cleanup(func() {
		if !committed {
			_ = tx.Rollback()
		}
	})
	successorHash := sha256.Sum256([]byte(successor.RawToken))
	restored, err := repo.RestoreClaimed(ctx, tx, claimed.ID, claimed.FamilyID, hex.EncodeToString(successorHash[:]))
	require.NoError(t, err)
	require.True(t, restored, "the restore itself must apply")

	done := make(chan error, 1)
	go func() {
		_, err := svc.RevokeFamily(ctx, claimed.FamilyID, "refresh_token_reuse")
		done <- err
	}()

	// Wait until the revocation is blocked on the restore's row lock, so its
	// snapshot predates the restore's commit.
	require.Eventually(t, func() bool {
		var waiting int
		err := testDB.NewRaw(
			"SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND query LIKE ?",
			"%"+claimed.FamilyID+"%",
		).Scan(ctx, &waiting)
		return err == nil && waiting > 0
	}, 10*time.Second, 10*time.Millisecond, "the family revocation never waited on the restore")

	require.NoError(t, tx.Commit())
	committed = true

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("the family revocation did not finish after the restore committed")
	}

	active, err := svc.IsRefreshTokenActive(ctx, issued.RawToken)
	require.NoError(t, err)
	assert.False(t, active, "a token the restore reactivated must not survive the family revocation")
}
