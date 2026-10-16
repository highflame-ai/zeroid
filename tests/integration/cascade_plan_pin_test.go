package integration_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Migration 059 pins the cascade walks to index nested loops. CREATE OR
// REPLACE FUNCTION silently drops function-level settings, so a later
// migration that redefines one of these functions must carry them forward.
func TestCascadeFunctionsPinIndexWalk(t *testing.T) {
	for _, fn := range []string{
		"revoke_credential_cascade",
		"revoke_credentials_cascade",
		"revoke_credentials_by_owner",
	} {
		var config string
		require.NoError(t, testDB.NewRaw(
			"SELECT COALESCE(array_to_string(proconfig, ','), '') FROM pg_proc WHERE proname = ?", fn,
		).Scan(context.Background(), &config), fn)
		assert.Contains(t, config, "enable_hashjoin=off", fn)
		assert.Contains(t, config, "enable_mergejoin=off", fn)
	}
}
