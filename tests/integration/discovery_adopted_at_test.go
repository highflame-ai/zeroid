// adopted_at (migration 045): the registry lists adopted agents by when they
// were adopted, not by when a connector first discovered them.

package integration_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"

	"github.com/highflame-ai/zeroid/migrations"
)

func adoptIdentity(t *testing.T, id string) map[string]any {
	t.Helper()
	resp, err := doRaw(t, http.MethodPost, adminPath("/identities/"+id+"/adopt"), map[string]any{
		"owner_user_id": "user-adopter",
	}, adminHeaders())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	return decode(t, resp)
}

// TestAdoptedAt_SetOnAdoptKeptBySyncClearedOnRevert pins the column's lifecycle:
// stamped by adopt, untouched by a connector re-sync (which DOES bump
// updated_at — the reason updated_at can't be the sort key), cleared when the
// adoption is reverted.
func TestAdoptedAt_SetOnAdoptKeptBySyncClearedOnRevert(t *testing.T) {
	ext := uid("adopted-at")
	out := ingestDiscovered(t, map[string]any{"external_id": ext, "origin": "okta"})
	identity := out["identity"].(map[string]any)
	assert.Nil(t, identity["adopted_at"], "a discovered identity has not been adopted")
	id := identity["id"].(string)

	adopted := adoptIdentity(t, id)
	adoptedAt, ok := adopted["adopted_at"].(string)
	require.True(t, ok && adoptedAt != "", "adopt must stamp adopted_at")

	// Compared as instants: the adopt response echoes Go's nanosecond value,
	// the re-sync reads Postgres' microsecond UTC copy of the same moment.
	resynced := ingestDiscovered(t, map[string]any{"external_id": ext, "origin": "okta", "name": "renamed"})
	resyncedAt, ok := resynced["identity"].(map[string]any)["adopted_at"].(string)
	require.True(t, ok, "a connector re-sync must keep adopted_at")
	want, err := time.Parse(time.RFC3339Nano, adoptedAt)
	require.NoError(t, err)
	got, err := time.Parse(time.RFC3339Nano, resyncedAt)
	require.NoError(t, err)
	assert.WithinDuration(t, want, got, time.Microsecond, "a connector re-sync must not move adopted_at")

	resp, err := doRaw(t, http.MethodPost, adminPath("/identities/"+id+"/dismiss"), nil, adminHeaders())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Nil(t, decode(t, resp)["adopted_at"], "reverting an adoption clears adopted_at")
}

// TestAdoptedAt_ListOrdersByAdoptionNotDiscovery is the bug: discover A then B,
// adopt B then A. Newest adoption first means A before B, even though A was
// discovered first — under the old created_at order it came last.
func TestAdoptedAt_ListOrdersByAdoptionNotDiscovery(t *testing.T) {
	tag := uid("adopt-order")
	a := ingestDiscovered(t, map[string]any{"external_id": tag + "-a", "origin": "okta"})["identity"].(map[string]any)["id"].(string)
	b := ingestDiscovered(t, map[string]any{"external_id": tag + "-b", "origin": "okta"})["identity"].(map[string]any)["id"].(string)

	adoptIdentity(t, b)
	adoptIdentity(t, a)

	resp := get(t, adminPath("/identities?status=pending&search="+tag), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	rows := decode(t, resp)["identities"].([]any)
	require.Len(t, rows, 2)
	assert.Equal(t, a, rows[0].(map[string]any)["id"], "most recently adopted first")
	assert.Equal(t, b, rows[1].(map[string]any)["id"])
}

// TestAdoptedAt_BackfillMatchesRuntime replays migration 046 against real
// adopt / revert / dismiss histories and checks it reconstructs exactly what
// the runtime would have stamped. Case "reverted then dismissed" is the one a
// naive "latest adoption, status not discovered" backfill gets wrong.
func TestAdoptedAt_BackfillMatchesRuntime(t *testing.T) {
	ctx := context.Background()
	dismiss := func(id string) {
		resp, err := doRaw(t, http.MethodPost, adminPath("/identities/"+id+"/dismiss"), nil, adminHeaders())
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		_ = resp.Body.Close()
	}
	discovered := func(prefix string) string {
		return ingestDiscovered(t, map[string]any{"external_id": uid(prefix), "origin": "okta"})["identity"].(map[string]any)["id"].(string)
	}

	adopted := discovered("backfill-adopted")
	adoptIdentity(t, adopted)

	revertedThenDismissed := discovered("backfill-reverted")
	adoptIdentity(t, revertedThenDismissed)
	dismiss(revertedThenDismissed) // pending → discovered
	dismiss(revertedThenDismissed) // discovered → deactivated

	readopted := discovered("backfill-readopted")
	adoptIdentity(t, readopted)
	dismiss(readopted)
	adoptIdentity(t, readopted)

	native := registerIdentity(t, uid("backfill-native"), nil).ID

	ids := []string{adopted, revertedThenDismissed, readopted, native}
	runtime := map[string]*time.Time{}
	for _, id := range ids {
		var at *time.Time
		require.NoError(t, testDB.NewSelect().Table("identities").Column("adopted_at").Where("id = ?", id).Scan(ctx, &at))
		runtime[id] = at
	}
	require.NotNil(t, runtime[adopted])
	require.Nil(t, runtime[revertedThenDismissed])
	require.NotNil(t, runtime[readopted])
	require.Nil(t, runtime[native])

	// Forget the runtime stamps, then let the backfill rebuild them.
	_, err := testDB.NewUpdate().Table("identities").Set("adopted_at = NULL").Where("id IN (?)", bun.In(ids)).Exec(ctx)
	require.NoError(t, err)
	backfill, err := migrations.FS.ReadFile("046_identity_adopted_at_backfill.up.sql")
	require.NoError(t, err)
	require.NoError(t, testDB.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		_, err := tx.ExecContext(ctx, string(backfill))
		return err
	}))

	for _, id := range ids {
		var at *time.Time
		require.NoError(t, testDB.NewSelect().Table("identities").Column("adopted_at").Where("id = ?", id).Scan(ctx, &at))
		if runtime[id] == nil {
			assert.Nil(t, at, "backfill must leave %s unstamped, as the runtime did", id)
			continue
		}
		// The audit row is stamped at transaction time, the runtime value just
		// before the write: the same moment within a second, never a different
		// adoption (the re-adopted case is seconds apart only if it's wrong).
		require.NotNil(t, at, "backfill must stamp %s", id)
		assert.WithinDuration(t, *runtime[id], *at, time.Second)
	}
}
