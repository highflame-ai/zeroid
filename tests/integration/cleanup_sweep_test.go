package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/domain"
)

// insertRefreshTokenRow inserts a refresh_tokens row directly via testDB so the
// test can deterministically place rows on either side of the
// expires_at - grace-window cutoff without driving full rotation flows. Returns
// the row id (gen_random_uuid default).
func insertRefreshTokenRow(t *testing.T, tokenHash, state string, expiresAt time.Time, revokedAt *time.Time) string {
	t.Helper()
	row := &domain.RefreshToken{
		TokenHash: tokenHash,
		ClientID:  "cleanup-sweep-client",
		AccountID: testAccountID,
		ProjectID: testProjectID,
		UserID:    "cleanup-sweep-user",
		FamilyID:  uuidV4(t),
		State:     state,
		ExpiresAt: expiresAt,
		RevokedAt: revokedAt,
	}
	_, err := testDB.NewInsert().Model(row).Returning("id").Exec(context.Background())
	require.NoError(t, err, "insert refresh_tokens row")
	require.NotEmpty(t, row.ID)
	return row.ID
}

// uuidV4 returns a fresh UUID string. refresh_tokens.family_id is NOT NULL
// type uuid, so each synthetic row needs its own.
func uuidV4(t *testing.T) string {
	t.Helper()
	var id string
	err := testDB.NewSelect().ColumnExpr("gen_random_uuid()::text").Scan(context.Background(), &id)
	require.NoError(t, err)
	return id
}

func refreshTokenExists(t *testing.T, id string) bool {
	t.Helper()
	n, err := testDB.NewSelect().
		Model((*domain.RefreshToken)(nil)).
		Where("id = ?", id).
		Count(context.Background())
	require.NoError(t, err)
	return n > 0
}

// TestCleanupSweepsExpiredRefreshTokensPastGraceWindow proves the new refresh-
// token sweep in CleanupWorker.RunOnce:
//   - a row expired well past the reuse-detection grace window is deleted;
//   - a row that is revoked but whose expires_at sits inside the grace window
//     (now - grace < expires_at) is RETAINED so reuse detection can still
//     consult it;
//   - an active, unexpired row is never touched.
func TestCleanupSweepsExpiredRefreshTokensPastGraceWindow(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	// (1) Long-expired, revoked: expires_at far beyond the cutoff → DELETE.
	revokedAt := now.Add(-time.Hour)
	wayExpired := insertRefreshTokenRow(t,
		uid("rt-way-expired"),
		domain.RefreshTokenStateRevoked,
		now.Add(-time.Hour),
		&revokedAt,
	)

	// (2) Revoked, but expires_at sits INSIDE the grace window (cutoff = now -
	// grace; this row's expires_at is now - 1s > cutoff) → RETAIN. This is the
	// reuse-forensics guard: a row whose expiry is more recent than the grace
	// lag must survive the sweep. We use a fixed 1s offset (not grace/2) so the
	// margin between this expiry and the cutoff is ~grace-1s ≈ 9s — large
	// enough that a slow CI runner delaying between `now` here and the cleanup
	// worker's own time.Now() can't push the row past the cutoff and flake.
	recentRevokedAt := now.Add(-1 * time.Second)
	withinGrace := insertRefreshTokenRow(t,
		uid("rt-within-grace"),
		domain.RefreshTokenStateRevoked,
		now.Add(-1*time.Second),
		&recentRevokedAt,
	)

	// (3) Active, unexpired → never swept.
	active := insertRefreshTokenRow(t,
		uid("rt-active"),
		domain.RefreshTokenStateActive,
		now.Add(24*time.Hour),
		nil,
	)

	require.True(t, refreshTokenExists(t, wayExpired), "precondition: long-expired row inserted")
	require.True(t, refreshTokenExists(t, withinGrace), "precondition: within-grace row inserted")
	require.True(t, refreshTokenExists(t, active), "precondition: active row inserted")

	testZeroIDServer.RunCleanupOnce(ctx)

	assert.False(t, refreshTokenExists(t, wayExpired),
		"refresh token expired past the grace window must be swept")
	assert.True(t, refreshTokenExists(t, withinGrace),
		"revoked refresh token whose expiry is inside the grace window must be retained for reuse forensics")
	assert.True(t, refreshTokenExists(t, active),
		"active, unexpired refresh token must never be swept")
}

// TestRefreshTokensExpiryIndexMigrationApplied asserts migration 032 created the
// expiry index that backs the sweep. The server runs migrations on startup, so
// reaching this point with the index present proves 032 applied cleanly.
func TestRefreshTokensExpiryIndexMigrationApplied(t *testing.T) {
	var count int
	err := testDB.NewSelect().
		ColumnExpr("count(*)").
		TableExpr("pg_indexes").
		Where("indexname = ?", "idx_refresh_tokens_expires_at").
		Scan(context.Background(), &count)
	require.NoError(t, err)
	assert.Equal(t, 1, count,
		"migration 032 must create idx_refresh_tokens_expires_at on refresh_tokens")
}
