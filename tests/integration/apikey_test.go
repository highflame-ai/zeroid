package integration_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createCredentialPolicy is a test helper that creates a credential policy
// scoped by the caller-supplied tenant headers and returns the policy ID.
// Uses a short name suffix to avoid unique-name collisions across parallel
// tests.
func createCredentialPolicy(t *testing.T, name string, headers map[string]string) string {
	t.Helper()
	resp := post(t, adminPath("/credential-policies"), map[string]any{
		"name":            name,
		"max_ttl_seconds": 3600,
	}, headers)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "createCredentialPolicy: expected 201")
	body := decode(t, resp)
	id, ok := body["id"].(string)
	require.True(t, ok, "createCredentialPolicy: response missing id")
	require.NotEmpty(t, id)
	return id
}

// tenantHeaders returns admin headers with the given account/project IDs,
// used for cross-tenant IDOR test scenarios. `X-User-ID` is required by
// EnsureServiceIdentity when the API-key path auto-provisions a service
// identity for a product, so we always populate it.
func tenantHeaders(accountID, projectID string) map[string]string {
	return map[string]string{
		"X-Account-ID": accountID,
		"X-Project-ID": projectID,
		"X-User-ID":    "test-user-" + accountID,
	}
}

func TestAPIKeyProductFilter(t *testing.T) {
	// Create keys with different products — no identity_id needed.
	// EnsureServiceIdentity auto-provisions a service identity per product.
	headers := adminHeaders()
	headers["X-User-ID"] = "test-user"

	respA := post(t, adminPath("/api-keys"), map[string]any{
		"name":    "analytics-key",
		"product": "analytics",
	}, headers)
	require.Equal(t, http.StatusCreated, respA.StatusCode)

	respB := post(t, adminPath("/api-keys"), map[string]any{
		"name":    "monitoring-key",
		"product": "monitoring",
	}, headers)
	require.Equal(t, http.StatusCreated, respB.StatusCode)

	// Second analytics key — should reuse the same service identity.
	respC := post(t, adminPath("/api-keys"), map[string]any{
		"name":    "analytics-key-2",
		"product": "analytics",
	}, headers)
	require.Equal(t, http.StatusCreated, respC.StatusCode)

	// Filter by product=analytics — should return 2 keys sharing the same identity.
	resp := get(t, adminPath("/api-keys?product=analytics"), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	keys := body["keys"].([]any)
	assert.Equal(t, 2, len(keys), "should return exactly 2 analytics keys")

	for _, k := range keys {
		m := k.(map[string]any)
		assert.Equal(t, "analytics", m["product"], "should only return analytics keys")
	}

	id1 := keys[0].(map[string]any)["identity_id"].(string)
	id2 := keys[1].(map[string]any)["identity_id"].(string)
	assert.Equal(t, id1, id2, "both analytics keys should share the same service identity")

	// Filter by product=monitoring — should return 1 key.
	resp = get(t, adminPath("/api-keys?product=monitoring"), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body = decode(t, resp)
	keys = body["keys"].([]any)
	assert.Equal(t, 1, len(keys), "should return exactly 1 monitoring key")
	assert.Equal(t, "monitoring", keys[0].(map[string]any)["product"])

	// No filter — returns all keys (at least 3 from this test + any from other tests).
	resp = get(t, adminPath("/api-keys"), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body = decode(t, resp)
	allKeys := body["keys"].([]any)
	assert.GreaterOrEqual(t, len(allKeys), 3, "should return at least all three created keys")
}

// TestCreateAPIKey_CustomCredentialPolicy_Propagates verifies that a
// caller-supplied credential_policy_id on POST /api-keys is persisted on the
// created key. Regression coverage for the propagation wiring in
// APIKeyService.CreateKey.
func TestCreateAPIKey_CustomCredentialPolicy_Propagates(t *testing.T) {
	headers := adminHeaders()
	headers["X-User-ID"] = "test-user" // required by EnsureServiceIdentity when auto-creating a service identity for the product.
	policyID := createCredentialPolicy(t, uid("cp-propagation"), headers)

	resp := post(t, adminPath("/api-keys"), map[string]any{
		"name":                 "propagation-key",
		"product":              "propagation-test",
		"credential_policy_id": policyID,
	}, headers)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	created := decode(t, resp)
	keyID := created["id"].(string)
	require.NotEmpty(t, keyID)

	// Fetch the key back and assert the policy ID was persisted.
	fetched := get(t, adminPath("/api-keys/"+keyID), headers)
	require.Equal(t, http.StatusOK, fetched.StatusCode)
	got := decode(t, fetched)
	assert.Equal(t, policyID, got["credential_policy_id"],
		"custom credential_policy_id supplied at creation must be stored on the key")
}

// TestCreateAPIKey_CrossTenantCredentialPolicyRejected verifies the IDOR guard:
// a caller in tenant B cannot associate a new API key with a credential policy
// that belongs to tenant A. GetPolicy is tenant-scoped and returns
// ErrPolicyNotFound for cross-tenant lookups — the handler must surface that
// as a 400 Bad Request, not a 500 and not a silent success.
func TestCreateAPIKey_CrossTenantCredentialPolicyRejected(t *testing.T) {
	tenantA := tenantHeaders("acct-tenant-a-"+uid(""), "proj-tenant-a-"+uid(""))
	tenantB := tenantHeaders("acct-tenant-b-"+uid(""), "proj-tenant-b-"+uid(""))

	// Tenant A creates a policy.
	foreignPolicyID := createCredentialPolicy(t, uid("cp-tenant-a"), tenantA)

	// Tenant B attempts to reference tenant A's policy ID on a new key.
	resp := post(t, adminPath("/api-keys"), map[string]any{
		"name":                 "cross-tenant-attempt",
		"product":              "idor-test",
		"credential_policy_id": foreignPolicyID,
	}, tenantB)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"cross-tenant credential_policy_id must be rejected with 400, not stored on the key")
}
