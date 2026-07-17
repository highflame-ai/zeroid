package integration_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCredentialPolicySourceKeyMigrationApplied asserts migration 037 added the
// source/source_key columns and the two partial unique indexes.
func TestCredentialPolicySourceKeyMigrationApplied(t *testing.T) {
	ctx := context.Background()

	for _, idx := range []string{"uq_credential_policies_source_key", "uq_credential_policies_user_name"} {
		var n int
		err := testDB.NewSelect().
			ColumnExpr("count(*)").
			TableExpr("pg_indexes").
			Where("indexname = ?", idx).
			Scan(ctx, &n)
		require.NoError(t, err)
		assert.Equal(t, 1, n, "migration 037 must create partial unique index %s", idx)
	}

	for _, col := range []string{"source", "source_key"} {
		var n int
		err := testDB.NewSelect().
			ColumnExpr("count(*)").
			TableExpr("information_schema.columns").
			Where("table_name = 'credential_policies'").
			Where("column_name = ?", col).
			Scan(ctx, &n)
		require.NoError(t, err)
		assert.Equal(t, 1, n, "migration 037 must add credential_policies.%s", col)
	}
}

// TestCreateCredentialPolicy_SourceKeyDedup proves derived-policy dedup keys on
// (source, source_key), NOT the display name: creating with the same source_key
// but a different name returns the SAME policy (idempotent find-or-create), while
// a different source_key creates a distinct one.
func TestCreateCredentialPolicy_SourceKeyDedup(t *testing.T) {
	headers := adminHeaders()
	key := uid("posture")

	derived := func(name, sourceKey string) map[string]any {
		return map[string]any{
			"name":           name,
			"source":         "discovery",
			"source_key":     sourceKey,
			"allowed_scopes": []string{"openid", "email"},
		}
	}

	resp1 := post(t, adminPath("/credential-policies"), derived(uid("derived-A"), key), headers)
	require.Equal(t, http.StatusCreated, resp1.StatusCode)
	id1, ok := decode(t, resp1)["id"].(string)
	require.True(t, ok)
	require.NotEmpty(t, id1)

	// Same source_key, DIFFERENT name → dedup to the existing policy, no duplicate.
	resp2 := post(t, adminPath("/credential-policies"), derived(uid("derived-B"), key), headers)
	require.Equal(t, http.StatusCreated, resp2.StatusCode)
	id2, _ := decode(t, resp2)["id"].(string)
	assert.Equal(t, id1, id2,
		"same (source, source_key) must dedup to one policy regardless of the display name")

	// Different source_key → a distinct policy.
	resp3 := post(t, adminPath("/credential-policies"), derived(uid("derived-C"), uid("posture2")), headers)
	require.Equal(t, http.StatusCreated, resp3.StatusCode)
	id3, _ := decode(t, resp3)["id"].(string)
	assert.NotEqual(t, id1, id3, "a different source_key must create a distinct policy")
}

// TestCreateCredentialPolicy_UserNameStillUnique proves user-authored policies
// (no source) keep name-uniqueness — the partial index preserves the old contract.
func TestCreateCredentialPolicy_UserNameStillUnique(t *testing.T) {
	headers := adminHeaders()
	name := uid("user-policy")

	resp1 := post(t, adminPath("/credential-policies"), map[string]any{"name": name}, headers)
	require.Equal(t, http.StatusCreated, resp1.StatusCode)
	_ = decode(t, resp1)

	resp2 := post(t, adminPath("/credential-policies"), map[string]any{"name": name}, headers)
	assert.Equal(t, http.StatusConflict, resp2.StatusCode,
		"a duplicate user-policy name (source IS NULL) must still 409")
	_ = decode(t, resp2)
}
