package integration_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
