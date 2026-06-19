package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/domain"
)

// TestCleanupWorkerSweepsExpiredRefreshTokens locks in migration 033 + the
// cleanup sweep: a refresh_tokens row past expires_at is deleted, an
// unexpired one survives. Without the sweep the table grows one row per
// refresh forever (rotation inserts a successor and revokes its predecessor,
// RFC 6749 §6).
func TestCleanupWorkerSweepsExpiredRefreshTokens(t *testing.T) {
	ctx := context.Background()
	family := "33333333-3333-3333-3333-333333333333"

	expired := &domain.RefreshToken{
		TokenHash: uid("rt-expired"),
		ClientID:  "test-client",
		AccountID: "acct-rt-cleanup",
		UserID:    "user-rt-cleanup",
		FamilyID:  family,
		State:     domain.RefreshTokenStateActive,
		ExpiresAt: time.Now().Add(-time.Hour),
	}
	live := &domain.RefreshToken{
		TokenHash: uid("rt-live"),
		ClientID:  "test-client",
		AccountID: "acct-rt-cleanup",
		UserID:    "user-rt-cleanup",
		FamilyID:  family,
		State:     domain.RefreshTokenStateActive,
		ExpiresAt: time.Now().Add(time.Hour),
	}

	_, err := testDB.NewInsert().Model(expired).Exec(ctx)
	require.NoError(t, err)
	_, err = testDB.NewInsert().Model(live).Exec(ctx)
	require.NoError(t, err)

	testZeroIDServer.RunCleanupOnce(ctx)

	exists := func(hash string) bool {
		n, err := testDB.NewSelect().
			Model((*domain.RefreshToken)(nil)).
			Where("token_hash = ?", hash).
			Count(ctx)
		require.NoError(t, err)
		return n > 0
	}

	assert.False(t, exists(expired.TokenHash), "expired refresh token must be swept")
	assert.True(t, exists(live.TokenHash), "unexpired refresh token must survive the sweep")
}
