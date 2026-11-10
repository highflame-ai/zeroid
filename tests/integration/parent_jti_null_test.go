package integration_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"

	"github.com/highflame-ai/zeroid/migrations"
)

// columnOf reads one nullable text column of an issued credential.
func columnOf(t *testing.T, column, jti string) (isNull bool, value string) {
	t.Helper()
	var p *string
	require.NoError(t, testDB.NewRaw(
		"SELECT ? FROM issued_credentials WHERE jti = ?", bun.Ident(column), jti,
	).Scan(context.Background(), &p))
	if p == nil {
		return true, ""
	}
	return false, *p
}

// A credential with no parent must store parent_jti as NULL. The cascade
// walk's partial index (parent_jti IS NOT NULL) and the planner's stats both
// assume it; with an empty string on every root row the stats show one value in ~100% of
// rows and revoke_credential_cascade degrades to a sequential scan per tree
// node (migration 062). delegated_by_wimse_uri has the same partial index and
// the same rule.
func TestRootCredentialStoresNullParentJTI(t *testing.T) {
	policyID := delegationPolicy(t, uid("pjti-policy"), []string{"data:read", "data:write"})
	_, rootJTI, rootToken := issueRootCredential(t, policyID, "pjti-root", []string{"data:read", "data:write"})
	_, childJTI, _ := exchangeToken(t, policyID, "pjti-child", []string{"data:read"}, []string{"data:read"}, rootToken)

	isNull, _ := columnOf(t, "parent_jti", rootJTI)
	assert.True(t, isNull, "root credential must store parent_jti as NULL, not ''")
	isNull, _ = columnOf(t, "delegated_by_wimse_uri", rootJTI)
	assert.True(t, isNull, "root credential must store delegated_by_wimse_uri as NULL, not ''")

	isNull, parent := columnOf(t, "parent_jti", childJTI)
	require.False(t, isNull, "exchanged credential must record its parent")
	assert.Equal(t, rootJTI, parent)
	isNull, delegatedBy := columnOf(t, "delegated_by_wimse_uri", childJTI)
	require.False(t, isNull, "exchanged credential must record who delegated")
	assert.NotEmpty(t, delegatedBy)
}

// Migration 062 turns the empty strings written by earlier binaries into NULL
// and leaves real values alone.
func TestMigration062BackfillsEmptyToNull(t *testing.T) {
	ctx := context.Background()
	policyID := delegationPolicy(t, uid("pjti-bf-policy"), []string{"data:read"})
	_, rootJTI, rootToken := issueRootCredential(t, policyID, "pjti-bf-root", []string{"data:read"})
	_, childJTI, _ := exchangeToken(t, policyID, "pjti-bf-child", []string{"data:read"}, []string{"data:read"}, rootToken)
	_, wantDelegatedBy := columnOf(t, "delegated_by_wimse_uri", childJTI)

	// Write the root the way earlier binaries did.
	_, err := testDB.NewRaw(
		"UPDATE issued_credentials SET parent_jti = '', delegated_by_wimse_uri = '' WHERE jti = ?", rootJTI,
	).Exec(ctx)
	require.NoError(t, err)

	backfill, err := migrations.FS.ReadFile("062_parent_jti_empty_to_null.up.sql")
	require.NoError(t, err)
	require.NoError(t, testDB.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		_, err := tx.ExecContext(ctx, string(backfill))
		return err
	}))

	for _, column := range []string{"parent_jti", "delegated_by_wimse_uri"} {
		isNull, _ := columnOf(t, column, rootJTI)
		assert.True(t, isNull, "backfill must turn %s '' into NULL", column)
	}
	_, parent := columnOf(t, "parent_jti", childJTI)
	assert.Equal(t, rootJTI, parent, "backfill must keep a real parent_jti")
	_, delegatedBy := columnOf(t, "delegated_by_wimse_uri", childJTI)
	assert.Equal(t, wantDelegatedBy, delegatedBy, "backfill must keep a real delegated_by_wimse_uri")
}
