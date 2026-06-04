package integration_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/domain"
)

// deleteCredentialPolicy issues DELETE /credential-policies/{id} and returns
// the HTTP status code. Body is drained/closed so the shared client stays
// healthy for subsequent requests.
func deleteCredentialPolicy(t *testing.T, id string, headers map[string]string) int {
	t.Helper()
	resp := doRequest(t, http.MethodDelete, adminPath("/credential-policies/"+id), nil, headers)
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

// countServiceKeysForPolicy counts service_keys rows referencing the given
// policy within a tenant, straight from the DB. Used to assert the reference
// state the in-use guard reads — and to prove that once the reference is gone,
// the policy deletes cleanly.
func countServiceKeysForPolicy(t *testing.T, policyID, accountID, projectID string) int {
	t.Helper()
	n, err := testDB.NewSelect().
		Model((*domain.APIKey)(nil)).
		Where("credential_policy_id = ?", policyID).
		Where("account_id = ?", accountID).
		Where("project_id = ?", projectID).
		Count(context.Background())
	require.NoError(t, err)
	return n
}

// TestDeleteCredentialPolicy_Unreferenced_Succeeds is the primary regression
// for the phantom-table bug. Before the fix, the Delete reference-check ran
// `SELECT count(*) FROM api_keys` — a table that does not exist — so EVERY
// credential-policy delete failed with a Postgres "relation api_keys does not
// exist" error that the handler mapped to 500. The keys table is service_keys
// (migration 006). With the fix, deleting an unreferenced policy returns 204.
func TestDeleteCredentialPolicy_Unreferenced_Succeeds(t *testing.T) {
	headers := adminHeaders()
	headers["X-User-ID"] = "test-user"

	policyID := createCredentialPolicy(t, uid("del-unref-cp"), headers)

	status := deleteCredentialPolicy(t, policyID, headers)
	assert.Equal(t, http.StatusNoContent, status,
		"deleting an unreferenced credential policy must return 204 (regression: phantom api_keys table previously forced a 500)")

	// A second delete of the now-absent policy must be a clean 404, not 500 —
	// proves the not-found path is wired through the service/handler mapping.
	status = deleteCredentialPolicy(t, policyID, headers)
	assert.Equal(t, http.StatusNotFound, status,
		"deleting an already-deleted policy must return 404")
}

// TestDeleteCredentialPolicy_InUse_Returns409 verifies the in-use path: a
// policy still referenced by a service key cannot be deleted and the handler
// returns 409 Conflict (not 500). Creating an API key with credential_policy_id
// set writes a service_keys row referencing the policy — exactly the reference
// the Delete guard must detect.
func TestDeleteCredentialPolicy_InUse_Returns409(t *testing.T) {
	headers := adminHeaders()
	headers["X-User-ID"] = "test-user"

	policyID := createCredentialPolicy(t, uid("del-inuse-cp"), headers)

	// Create a key that references the policy → seeds a service_keys row.
	resp := post(t, adminPath("/api-keys"), map[string]any{
		"name":                 "del-inuse-key",
		"product":              "del-inuse-test",
		"credential_policy_id": policyID,
	}, headers)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	_ = resp.Body.Close()

	require.Equal(t, 1, countServiceKeysForPolicy(t, policyID, testAccountID, testProjectID),
		"precondition: exactly one service key should reference the policy")

	status := deleteCredentialPolicy(t, policyID, headers)
	assert.Equal(t, http.StatusConflict, status,
		"deleting a policy still referenced by a service key must return 409 Conflict, not 500")

	// The policy must still exist after a refused delete.
	getResp := get(t, adminPath("/credential-policies/"+policyID), headers)
	assert.Equal(t, http.StatusOK, getResp.StatusCode,
		"a refused (409) delete must leave the policy intact")
	_ = getResp.Body.Close()
}

// TestDeleteCredentialPolicy_AfterReferenceRemoved_Succeeds proves the in-use
// guard is a real reference count, not an always-true short-circuit: once the
// referencing service_keys row is gone, the same policy deletes cleanly (204).
// The api-key surface only soft-revokes (the row, and its credential_policy_id,
// survive a revoke), so we remove the reference at the DB layer via the test
// bun handle the harness exposes for exactly this kind of repo-level setup.
func TestDeleteCredentialPolicy_AfterReferenceRemoved_Succeeds(t *testing.T) {
	headers := adminHeaders()
	headers["X-User-ID"] = "test-user"

	policyID := createCredentialPolicy(t, uid("del-freed-cp"), headers)

	resp := post(t, adminPath("/api-keys"), map[string]any{
		"name":                 "del-freed-key",
		"product":              "del-freed-test",
		"credential_policy_id": policyID,
	}, headers)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	created := decode(t, resp)
	keyID := created["id"].(string)
	require.NotEmpty(t, keyID)

	// While referenced, delete is refused.
	require.Equal(t, http.StatusConflict, deleteCredentialPolicy(t, policyID, headers))

	// Remove the reference directly, then the policy must delete cleanly.
	_, err := testDB.NewDelete().
		Model((*domain.APIKey)(nil)).
		Where("id = ?", keyID).
		Exec(context.Background())
	require.NoError(t, err)
	require.Equal(t, 0, countServiceKeysForPolicy(t, policyID, testAccountID, testProjectID),
		"precondition: reference must be gone before the clean-delete assertion")

	assert.Equal(t, http.StatusNoContent, deleteCredentialPolicy(t, policyID, headers),
		"once no service key references the policy, delete must return 204")
}

// TestDeleteCredentialPolicy_CrossTenant_NotFound verifies tenant isolation on
// delete: tenant B cannot delete tenant A's policy, and gets a 404 (not a 403
// or a 204) so existence in another tenant never leaks. Tenant A's policy must
// remain intact.
func TestDeleteCredentialPolicy_CrossTenant_NotFound(t *testing.T) {
	tenantA := tenantHeaders("acct-del-cp-a-"+uid(""), "proj-del-cp-a-"+uid(""))
	tenantB := tenantHeaders("acct-del-cp-b-"+uid(""), "proj-del-cp-b-"+uid(""))

	policyID := createCredentialPolicy(t, uid("del-xtenant-cp"), tenantA)

	status := deleteCredentialPolicy(t, policyID, tenantB)
	assert.Equal(t, http.StatusNotFound, status,
		"tenant B deleting tenant A's policy must get 404 — no cross-tenant deletion, no existence leak")

	// Tenant A's policy must survive the cross-tenant delete attempt.
	getResp := get(t, adminPath("/credential-policies/"+policyID), tenantA)
	assert.Equal(t, http.StatusOK, getResp.StatusCode,
		"cross-tenant delete attempt must not affect the owning tenant's policy")
	_ = getResp.Body.Close()
}
