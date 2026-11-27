package integration_test

import (
	"context"
	"database/sql"
	"io/fs"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid"
)

// Migration 060 pins the single-token cascade walk to index nested loops and
// leaves the bulk (identity, owner) cascades to the planner. CREATE OR REPLACE
// FUNCTION silently drops function-level settings, so a later migration that
// redefines one of these functions must carry them forward.
func TestCascadeFunctionsPinIndexWalk(t *testing.T) {
	config := func(fn string) string {
		var c string
		require.NoError(t, testDB.NewRaw(
			"SELECT COALESCE(array_to_string(proconfig, ','), '') FROM pg_proc WHERE proname = ?", fn,
		).Scan(context.Background(), &c), fn)
		return c
	}

	pinned := config("revoke_credential_cascade")
	assert.Contains(t, pinned, "enable_hashjoin=off")
	assert.Contains(t, pinned, "enable_mergejoin=off")

	for _, bulk := range []string{"revoke_credentials_cascade", "revoke_credentials_by_owner"} {
		assert.NotContains(t, config(bulk), "enable_hashjoin", "%s revokes in bulk; a hash join is the better plan there", bulk)
	}
}

// TestCascadeAnchorLockMigration applies migration 073's down and up scripts
// inside a transaction that is rolled back, so the shared schema is left
// untouched. Both directions keep the index-walk pin; only up locks the
// anchor before the walk.
func TestCascadeAnchorLockMigration(t *testing.T) {
	ctx := context.Background()
	const name = "073_cascade_revocation_locks_anchor"
	up, err := fs.ReadFile(zeroid.MigrationFiles(), name+".up.sql")
	require.NoError(t, err)
	down, err := fs.ReadFile(zeroid.MigrationFiles(), name+".down.sql")
	require.NoError(t, err)

	tx, err := testDB.BeginTx(ctx, &sql.TxOptions{})
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	state := func() (config, body string) {
		require.NoError(t, tx.QueryRowContext(ctx,
			`SELECT COALESCE(array_to_string(proconfig, ','), ''), prosrc FROM pg_proc WHERE proname = 'revoke_credential_cascade'`,
		).Scan(&config, &body))
		return config, body
	}

	config, body := state()
	require.Contains(t, body, "FOR NO KEY UPDATE", "migration must be applied by the suite")
	_, err = tx.ExecContext(ctx, string(down))
	require.NoError(t, err)
	config, body = state()
	assert.NotContains(t, body, "FOR NO KEY UPDATE", "down drops the anchor lock")
	assert.Contains(t, config, "enable_hashjoin=off", "down keeps the index-walk pin")
	assert.Contains(t, config, "enable_mergejoin=off", "down keeps the index-walk pin")
	_, err = tx.ExecContext(ctx, string(up))
	require.NoError(t, err)
	config, body = state()
	assert.Contains(t, body, "FOR NO KEY UPDATE", "up locks the anchor")
	assert.Contains(t, config, "enable_hashjoin=off", "up keeps the index-walk pin")
	assert.Contains(t, config, "enable_mergejoin=off", "up keeps the index-walk pin")
}
