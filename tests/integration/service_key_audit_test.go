package integration_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// keyAuditRow is one identity_audit_logs row written by the service_keys
// trigger (migration 047).
type keyAuditRow struct {
	Action       string `bun:"action"`
	CallerUserID string `bun:"caller_user_id"`
	OldData      string `bun:"old_data"`
	NewData      string `bun:"new_data"`
}

func keyAuditRows(t *testing.T, identityID string) []keyAuditRow {
	t.Helper()
	var rows []keyAuditRow
	err := testDB.NewSelect().
		Table("identity_audit_logs").
		Column("action", "caller_user_id").
		ColumnExpr("COALESCE(old_data::text, '') AS old_data").
		ColumnExpr("COALESCE(new_data::text, '') AS new_data").
		Where("identity_id = ?", identityID).
		Where("table_name = ?", "service_keys").
		Order("created_at ASC", "action ASC").
		Scan(context.Background(), &rows)
	require.NoError(t, err)
	return rows
}

func countAction(rows []keyAuditRow, action string) int {
	n := 0
	for _, r := range rows {
		if r.Action == action {
			n++
		}
	}
	return n
}

// listKeyIDs returns the key IDs the list endpoint returns for a query.
func listKeyIDs(t *testing.T, query string) []string {
	t.Helper()
	resp := get(t, adminPath("/api-keys?"+query), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var ids []string
	for _, k := range decode(t, resp)["keys"].([]any) {
		ids = append(ids, k.(map[string]any)["id"].(string))
	}
	return ids
}

func withCaller(caller string) map[string]string {
	h := adminHeaders()
	h["X-User-ID"] = caller
	return h
}

func TestKeyAudit_CreateAndSingleRevoke(t *testing.T) {
	reg := registerAgent(t, uid("key-audit-revoke"))

	keyIDs := listKeyIDs(t, "identity_id="+reg.AgentID)
	require.Len(t, keyIDs, 1, "registration creates exactly one key")

	resp := post(t, adminPath("/api-keys/"+keyIDs[0]+"/revoke"),
		map[string]any{"reason": "leaked"}, withCaller("sec-dana"))
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	rows := keyAuditRows(t, reg.AgentID)
	require.Equal(t, 1, countAction(rows, "CREATE_KEY"))
	require.Equal(t, 1, countAction(rows, "REVOKE_KEY"))
	for _, r := range rows {
		if r.Action == "REVOKE_KEY" {
			assert.Equal(t, "sec-dana", r.CallerUserID, "the revoke must name the person who revoked")
			assert.Contains(t, r.NewData, `"revoke_reason": "leaked"`)
			assert.Contains(t, r.NewData, keyIDs[0])
		}
		assert.NotContains(t, r.OldData+r.NewData, "key_hash", "the audit row must never carry the key hash")
	}
}

func TestKeyAudit_RotateNamesTheOperator(t *testing.T) {
	reg := registerAgent(t, uid("key-audit-rotate"))

	rotate(t, reg.AgentID, map[string]string{"X-User-ID": "sre-bob"})

	rows := keyAuditRows(t, reg.AgentID)
	require.Equal(t, 2, countAction(rows, "CREATE_KEY"), "bootstrap key + rotated key")
	require.Equal(t, 1, countAction(rows, "REVOKE_KEY"))
	var created []keyAuditRow
	for _, r := range rows {
		if r.Action == "CREATE_KEY" {
			created = append(created, r)
		}
	}
	assert.Equal(t, "sre-bob", created[len(created)-1].CallerUserID,
		"the rotated key's creation must name the operator, not the owner the key acts for")
	for _, r := range rows {
		if r.Action == "REVOKE_KEY" {
			assert.Equal(t, "sre-bob", r.CallerUserID,
				"the old key's revoke must name the rotation operator, not a system label")
			assert.Contains(t, r.NewData, `"revoke_reason": "key rotated"`)
		}
	}
}

func TestKeyAudit_DeactivateRevokesWithCaller(t *testing.T) {
	reg := registerAgent(t, uid("key-audit-deactivate"))

	resp, err := doRaw(t, http.MethodDelete, adminPath("/agents/registry/"+reg.AgentID), nil, withCaller("admin-erin"))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	rows := keyAuditRows(t, reg.AgentID)
	require.Equal(t, 1, countAction(rows, "REVOKE_KEY"))
	for _, r := range rows {
		if r.Action == "REVOKE_KEY" {
			assert.Equal(t, "admin-erin", r.CallerUserID)
		}
	}
}

func TestKeyAudit_NoCallerFallsBackToSystemLabel(t *testing.T) {
	reg := registerAgent(t, uid("key-audit-no-caller"))

	rotate(t, reg.AgentID, nil)

	rows := keyAuditRows(t, reg.AgentID)
	require.Equal(t, 1, countAction(rows, "REVOKE_KEY"))
	for _, r := range rows {
		if r.Action == "REVOKE_KEY" {
			assert.Equal(t, "system:key_rotation", r.CallerUserID)
		}
	}
}

// An oversized caller must not make the audit insert fail (caller_user_id is
// VARCHAR(255)); a dropped row would let a revoke skip the audit.
func TestKeyAudit_LongCallerStillAudited(t *testing.T) {
	reg := registerAgent(t, uid("key-audit-long-caller"))
	keyIDs := listKeyIDs(t, "identity_id="+reg.AgentID)
	require.Len(t, keyIDs, 1)

	resp := post(t, adminPath("/api-keys/"+keyIDs[0]+"/revoke"),
		map[string]any{"reason": "test"}, withCaller(strings.Repeat("x", 300)))
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	rows := keyAuditRows(t, reg.AgentID)
	require.Equal(t, 1, countAction(rows, "REVOKE_KEY"))
	for _, r := range rows {
		if r.Action == "REVOKE_KEY" {
			assert.Len(t, r.CallerUserID, 255)
		}
	}
}

func usageCount(t *testing.T, identityID string) int64 {
	t.Helper()
	var n int64
	err := testDB.NewSelect().Table("service_keys").ColumnExpr("COALESCE(SUM(usage_count), 0)").
		Where("identity_id = ?", identityID).Scan(context.Background(), &n)
	require.NoError(t, err)
	return n
}

// Key usage updates the row on every request; it must not write audit rows.
func TestKeyAudit_UsageWritesNoAuditRow(t *testing.T) {
	reg := registerAgent(t, uid("key-audit-usage"))
	before := len(keyAuditRows(t, reg.AgentID))

	for i := 0; i < 3; i++ {
		resp := post(t, "/oauth2/token", map[string]any{
			"grant_type": "api_key",
			"api_key":    reg.APIKey,
		}, nil)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		_ = resp.Body.Close()
	}
	// The usage update is fire-and-forget; count only once it has landed.
	require.Eventually(t, func() bool { return usageCount(t, reg.AgentID) >= 3 }, 5*time.Second, 50*time.Millisecond)

	assert.Equal(t, before, len(keyAuditRows(t, reg.AgentID)))
}

func TestListAPIKeys_IdentityIDFilter(t *testing.T) {
	a := registerAgent(t, uid("key-list-a"))
	b := registerAgent(t, uid("key-list-b"))

	idsA := listKeyIDs(t, "identity_id="+a.AgentID)
	require.Len(t, idsA, 1)
	assert.NotContains(t, idsA, listKeyIDs(t, "identity_id="+b.AgentID)[0])
	assert.Equal(t, idsA, listKeyIDs(t, "application_id="+a.AgentID), "identity_id is an alias of application_id")

	resp := get(t, adminPath("/api-keys?identity_id="+a.AgentID+"&application_id="+b.AgentID), adminHeaders())
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "conflicting filters must be rejected")
	_ = resp.Body.Close()

	resp = get(t, adminPath("/api-keys?identity_id=not-a-uuid"), adminHeaders())
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "a non-UUID filter is a client error, not a 500")
	_ = resp.Body.Close()
}
