package integration_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid"
)

// Identity audit feed (migration 066, #483): ordered paging, fail-closed
// audit triggers, and credential policy auditing.

// readFeed pages the whole feed from (txid, seq) with a small page size and
// returns the rows in order and the cursor at the end.
func readFeed(t *testing.T, txid string, seq int64) ([]zeroid.AuditFeedEntry, string, int64) {
	t.Helper()
	var all []zeroid.AuditFeedEntry
	for {
		page, err := testZeroIDServer.IdentityAuditFeed(context.Background(), txid, seq, 7)
		require.NoError(t, err)
		all = append(all, page.Entries...)
		txid, seq = page.NextTxID, page.NextSeq
		if len(page.Entries) < 7 {
			return all, txid, seq
		}
	}
}

func feedEnd(t *testing.T) (string, int64) {
	t.Helper()
	_, txid, seq := readFeed(t, "0", 0)
	return txid, seq
}

// policyAuditRows is the audit rows for one credential policy, in feed order.
func policyAuditRows(t *testing.T, policyID string) []zeroid.AuditFeedEntry {
	t.Helper()
	var rows []zeroid.AuditFeedEntry
	err := testDB.NewSelect().Model(&rows).
		Where("table_name = 'credential_policies'").
		Where("COALESCE(new_data, old_data) ->> 'id' = ?", policyID).
		OrderExpr("ial.txid, ial.seq").
		Scan(context.Background())
	require.NoError(t, err)
	return rows
}

func TestIdentityAuditFeed_EveryRowOnce(t *testing.T) {
	h := tenantHeaders(uid("acct-feed"), uid("proj-feed"))
	var ids []string
	for i := 0; i < 5; i++ {
		ids = append(ids, createCredentialPolicy(t, uid("feed-policy"), h))
	}

	rows, _, _ := readFeed(t, "0", 0)

	seen := map[string]int{}
	for i, r := range rows {
		seen[r.ID]++
		if i > 0 {
			prev := rows[i-1]
			assert.True(t, prev.TxID != r.TxID || prev.Seq < r.Seq, "feed out of order at %d", i)
		}
	}
	for id, n := range seen {
		assert.Equal(t, 1, n, "audit row %s returned %d times", id, n)
	}
	for _, id := range ids {
		audit := policyAuditRows(t, id)
		require.Len(t, audit, 1)
		assert.Equal(t, 1, seen[audit[0].ID], "policy %s's audit row missing from the feed", id)
	}
}

// A row from a transaction that is still open holds back every later row,
// so a reader that has moved past the later rows cannot skip it.
func TestIdentityAuditFeed_WaitsForLateCommit(t *testing.T) {
	ctx := context.Background()
	txid, seq := feedEnd(t)
	acct := uid("acct-late")

	tx, err := testDB.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()

	insert := `INSERT INTO identity_audit_logs (account_id, table_name, action) VALUES (?, 'test', ?)`
	_, err = tx.ExecContext(ctx, insert, acct, "EARLY")
	require.NoError(t, err)
	_, err = testDB.ExecContext(ctx, insert, acct, "LATE")
	require.NoError(t, err)

	rows, _, _ := readFeed(t, txid, seq)
	for _, r := range rows {
		assert.NotEqual(t, acct, r.AccountID, "a row passed the open transaction: %s", r.Action)
	}

	require.NoError(t, tx.Commit())

	rows, _, _ = readFeed(t, txid, seq)
	var mine []string
	for _, r := range rows {
		if r.AccountID == acct {
			mine = append(mine, r.Action)
		}
	}
	assert.Equal(t, []string{"EARLY", "LATE"}, mine)
}

func TestIdentityAuditFeed_RejectsBadCursor(t *testing.T) {
	_, err := testZeroIDServer.IdentityAuditFeed(context.Background(), "1; DROP TABLE x", 0, 10)
	require.ErrorIs(t, err, zeroid.ErrInvalidAuditCursor)
}

func TestCredentialPolicyAudit_NamesTheCaller(t *testing.T) {
	h := tenantHeaders(uid("acct-cpaudit"), uid("proj-cpaudit"))
	h["X-User-ID"] = "user-cp-audit"
	id := createCredentialPolicy(t, uid("audited"), h)

	resp := doRequest(t, http.MethodPatch, adminPath("/credential-policies/"+id), map[string]any{"max_ttl_seconds": 600}, h)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusNoContent, deleteCredentialPolicy(t, id, h))

	rows := policyAuditRows(t, id)
	require.Len(t, rows, 3)
	for i, action := range []string{"CREATE", "UPDATE", "DELETE"} {
		assert.Equal(t, action, rows[i].Action)
		assert.Equal(t, "user-cp-audit", rows[i].UserID)
	}
	assert.Contains(t, string(rows[1].OldData), `"max_ttl_seconds": 3600`)
	assert.Contains(t, string(rows[1].NewData), `"max_ttl_seconds": 600`)
}

// The default policy a tenant gets on first use is ZeroID's own work, even
// when a person's request creates it.
func TestCredentialPolicyAudit_DefaultPolicyNamesNoOne(t *testing.T) {
	acct, proj := uid("acct-cpdefault"), uid("proj-cpdefault")
	registerIdentityIn(t, tenantHeaders(acct, proj), uid("feed-identity"), nil)

	var rows []zeroid.AuditFeedEntry
	err := testDB.NewSelect().Model(&rows).
		Where("table_name = 'credential_policies' AND account_id = ? AND project_id = ?", acct, proj).
		Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "CREATE", rows[0].Action)
	assert.Empty(t, rows[0].UserID)
}

// A failed audit insert fails the change it records (the triggers no longer
// catch their own errors).
func TestAuditTriggers_FailClosed(t *testing.T) {
	ctx := context.Background()
	const failer = "force-audit-failure"
	_, err := testDB.ExecContext(ctx, `
		CREATE OR REPLACE FUNCTION test_fail_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.caller_user_id = '`+failer+`' THEN RAISE EXCEPTION 'audit insert failed'; END IF;
			RETURN NEW;
		END $$;
		DROP TRIGGER IF EXISTS test_fail_audit ON identity_audit_logs;
		CREATE TRIGGER test_fail_audit BEFORE INSERT ON identity_audit_logs
			FOR EACH ROW EXECUTE FUNCTION test_fail_audit();`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = testDB.ExecContext(ctx, `DROP TRIGGER IF EXISTS test_fail_audit ON identity_audit_logs; DROP FUNCTION IF EXISTS test_fail_audit();`)
	})

	acct, proj := uid("acct-failclosed"), uid("proj-failclosed")
	h := tenantHeaders(acct, proj)
	h["X-User-ID"] = failer

	name := uid("never-saved")
	resp := post(t, adminPath("/credential-policies"), map[string]any{"name": name, "max_ttl_seconds": 3600}, h)
	_ = resp.Body.Close()
	assert.GreaterOrEqual(t, resp.StatusCode, 500)

	var n int
	n, err = testDB.NewSelect().Table("credential_policies").Where("name = ?", name).Count(ctx)
	require.NoError(t, err)
	assert.Zero(t, n, "the policy was saved without its audit row")

	identity := func(caller string) int {
		hh := tenantHeaders(acct, proj)
		hh["X-User-ID"] = caller
		resp := post(t, adminPath("/identities"), map[string]any{
			"external_id": uid("identity"), "trust_level": "unverified", "owner_user_id": "user-test-owner",
		}, hh)
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	// The same request saves with any other caller, so only the audit
	// failure can stop it.
	require.Equal(t, http.StatusCreated, identity("someone-else"))
	n, err = testDB.NewSelect().Table("identities").Where("account_id = ?", acct).Count(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, n)

	assert.Equal(t, http.StatusInternalServerError, identity(failer))

	n, err = testDB.NewSelect().Table("identities").Where("account_id = ?", acct).Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n, "the identity was saved without its audit row")
}

// An update that changes only bookkeeping (updated_at, which connector sync
// bumps every pass, and modified_by) writes no audit row; a real change does.
func TestAuditTriggers_SkipBookkeepingUpdates(t *testing.T) {
	ctx := context.Background()
	acct, proj := uid("acct-bookkeeping"), uid("proj-bookkeeping")
	ident := registerIdentityIn(t, tenantHeaders(acct, proj), uid("bookkeeping"), nil)
	h := tenantHeaders(acct, proj)
	policyID := createCredentialPolicy(t, uid("bookkeeping-policy"), h)

	count := func(table, id string) int {
		n, err := testDB.NewSelect().Table("identity_audit_logs").
			Where("table_name = ?", table).
			Where("action = 'UPDATE'").
			Where("identity_id = ? OR COALESCE(new_data, old_data) ->> 'id' = ?", id, id).
			Count(ctx)
		require.NoError(t, err)
		return n
	}

	_, err := testDB.ExecContext(ctx, `UPDATE identities SET updated_at = now(), modified_by = 'system:sync' WHERE id = ?`, ident.ID)
	require.NoError(t, err)
	_, err = testDB.ExecContext(ctx, `UPDATE credential_policies SET updated_at = now() WHERE id = ?`, policyID)
	require.NoError(t, err)
	assert.Zero(t, count("identities", ident.ID), "a last-seen bump is not a change")
	assert.Zero(t, count("credential_policies", policyID))

	_, err = testDB.ExecContext(ctx, `UPDATE identities SET name = 'renamed', updated_at = now() WHERE id = ?`, ident.ID)
	require.NoError(t, err)
	_, err = testDB.ExecContext(ctx, `UPDATE credential_policies SET max_ttl_seconds = 60 WHERE id = ?`, policyID)
	require.NoError(t, err)
	assert.Equal(t, 1, count("identities", ident.ID))
	assert.Equal(t, 1, count("credential_policies", policyID))
}

// Deleting a credential policy clears it from the identities that used it
// (ON DELETE SET NULL). Those identity rows name whoever deleted the policy,
// not the identity's last editor.
func TestIdentityAudit_PolicyDeleteCascadeNamesTheDeleter(t *testing.T) {
	ctx := context.Background()
	acct, proj := uid("acct-cascade"), uid("proj-cascade")
	a := tenantHeaders(acct, proj)
	a["X-User-ID"] = "user-cascade-a"
	b := tenantHeaders(acct, proj)
	b["X-User-ID"] = "user-cascade-b"

	policyID := createCredentialPolicy(t, uid("cascade-policy"), a)
	resp := post(t, adminPath("/identities"), map[string]any{
		"external_id":          uid("cascade"),
		"trust_level":          "unverified",
		"owner_user_id":        "user-test-owner",
		"credential_policy_id": policyID,
	}, a)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	identityID := decode(t, resp)["id"].(string)

	require.Equal(t, http.StatusNoContent, deleteCredentialPolicy(t, policyID, b))

	var rows []zeroid.AuditFeedEntry
	err := testDB.NewSelect().Model(&rows).
		Where("table_name = 'identities' AND identity_id = ?", identityID).
		OrderExpr("ial.txid, ial.seq").
		Scan(ctx)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	assert.Equal(t, "CREATE", rows[0].Action)
	assert.Equal(t, "user-cascade-a", rows[0].UserID)
	assert.Equal(t, "UPDATE", rows[1].Action)
	assert.Equal(t, "user-cascade-b", rows[1].UserID)
	assert.Contains(t, string(rows[1].OldData), policyID)
	assert.Contains(t, string(rows[1].NewData), `"credential_policy_id": null`)
}
