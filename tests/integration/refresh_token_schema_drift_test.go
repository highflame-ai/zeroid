package integration_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRefreshRotation_ToleratesExtraColumn pins rotation against schema drift:
// a refresh_tokens column the model does not know about (left behind by an
// edited migration) must not break rotation or reuse detection. Both used to
// read back with RETURNING *, which bun refuses to scan into the model, so
// every refresh answered invalid_grant and the token stayed active.
func TestRefreshRotation_ToleratesExtraColumn(t *testing.T) {
	ctx := context.Background()
	_, err := testDB.ExecContext(ctx,
		"ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS drift_extra TEXT DEFAULT ''")
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = testDB.ExecContext(ctx, "ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS drift_extra")
	})

	_, rt := exchangeMCPCode(t, uid("user-drift"))

	// Rotation (ClaimByTokenHash).
	status, body := refreshMCP(t, rt)
	require.Equal(t, http.StatusOK, status, "rotation must succeed with an unknown column: %v", body)
	successor, _ := body["refresh_token"].(string)
	require.NotEmpty(t, successor)

	// Reuse detection (RevokeFamily): replay the rotated-out token outside
	// the grace window, so the family is revoked and the successor dies.
	setRefreshReuseGrace(t, 0)
	status, body = refreshMCP(t, rt)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", body["error"])

	status, body = refreshMCP(t, successor)
	assert.Equal(t, http.StatusBadRequest, status,
		"reuse detection must revoke the family even with an unknown column: %v", body)
}
