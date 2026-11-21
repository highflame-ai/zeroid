package integration_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/domain"
)

// TestServiceKeysFKCascade_HardDeleteIdentity_CascadesKey is regression
// coverage for zeroid#196: migration 006 declares
// service_keys.identity_id REFERENCES identities(id) ON DELETE CASCADE, but
// CREATE TABLE IF NOT EXISTS is a no-op on any deployment where the table
// pre-existed the cascade — leaving legacy DBs with a non-cascading FK (the
// root cause of highflame-authn#109 / zeroid#187). Migration
// 040_service_keys_fk_cascade explicitly re-applies the cascade on every
// startup so all deployments converge on the declared shape.
//
// This test proves the FK itself (not just the current lucky call-ordering
// inside PurgeIdentity, which today deletes the identity before any service
// key row exists) permits a hard delete of a service-key-bearing identity to
// cascade cleanly. That's the invariant PurgeIdentity's compensating
// rollback silently depends on, and that any future hard-delete caller
// (e.g. a GDPR-erasure path) will need too.
func TestServiceKeysFKCascade_HardDeleteIdentity_CascadesKey(t *testing.T) {
	ctx := context.Background()
	reg := registerAgent(t, uid("fk-cascade")) // auto-creates a bootstrap service key

	// Precondition: exactly one service key row references this identity.
	n, err := testDB.NewSelect().
		Model((*domain.APIKey)(nil)).
		Where("identity_id = ?", reg.AgentID).
		Count(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, n, "precondition: registerAgent must create exactly one service key")

	// Hard-delete the identity directly at the repo layer — the same
	// DELETE FROM identities ... that IdentityRepository.Delete (and
	// therefore PurgeIdentity) issues. Before the fix, this trips "violates
	// foreign key constraint service_keys_identity_id_fkey" on any DB where
	// the table predates the cascade.
	_, err = testDB.NewDelete().
		Model((*domain.Identity)(nil)).
		Where("id = ?", reg.AgentID).
		Exec(ctx)
	require.NoError(t, err, "hard delete of a service-key-bearing identity must cascade, not FK-violate")

	// The service key must have been cascade-deleted along with its parent.
	n, err = testDB.NewSelect().
		Model((*domain.APIKey)(nil)).
		Where("identity_id = ?", reg.AgentID).
		Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, n, "service_keys row must cascade-delete with its parent identity")
}
