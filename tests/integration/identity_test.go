package integration_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRegisterIdentity verifies that a new identity can be created
// and the response contains the expected WIMSE URI format.
func TestRegisterIdentity(t *testing.T) {
	externalID := uid("research-agent")
	resp := post(t, "/api/v1/identities", map[string]any{
		"external_id":    externalID,
		"trust_level":    "unverified",
		"owner_user_id":  "user-test-owner",
		"allowed_scopes": []string{"research:read"},
	}, adminHeaders())
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	body := decode(t, resp)
	assert.Equal(t, externalID, body["external_id"])
	assert.Equal(t, testAccountID, body["account_id"])
	assert.Equal(t, testProjectID, body["project_id"])
	assert.Equal(t, "unverified", body["trust_level"])
	assert.Equal(t, "agent", body["identity_type"])
	assert.Equal(t, "user-test-owner", body["owner_user_id"])
	assert.Equal(t, "active", body["status"])

	wimseURI := body["wimse_uri"].(string)
	expected := "spiffe://" + testWIMSE + "/" + testAccountID + "/" + testProjectID + "/agent/" + externalID
	assert.Equal(t, expected, wimseURI)
}

// TestRegisterIdentityDuplicateReturns409 verifies that registering the same
// (account_id, project_id, external_id) tuple twice returns 409 Conflict.
func TestRegisterIdentityDuplicateReturns409(t *testing.T) {
	externalID := uid("dup-agent")
	registerIdentity(t, externalID, []string{"billing:read"})

	// Second registration with the same external_id — must be rejected.
	resp := post(t, "/api/v1/identities", map[string]any{
		"external_id":    externalID,
		"trust_level":    "unverified",
		"owner_user_id":  "user-test-owner",
		"allowed_scopes": []string{"billing:read"},
	}, adminHeaders())
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	resp.Body.Close()
}

// TestRegisterIdentityMissingExternalID verifies that omitting external_id returns 400/422.
func TestRegisterIdentityMissingExternalID(t *testing.T) {
	resp := post(t, "/api/v1/identities", map[string]any{
		"trust_level":    "unverified",
		"owner_user_id":  "user-test-owner",
		"allowed_scopes": []string{"billing:read"},
	}, adminHeaders())
	assert.True(t,
		resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnprocessableEntity,
		"expected 400 or 422 for missing external_id, got %d", resp.StatusCode,
	)
	resp.Body.Close()
}

// TestGetIdentity verifies that GET /api/v1/identities/{id} returns the identity.
func TestGetIdentity(t *testing.T) {
	externalID := uid("get-agent")
	identity := registerIdentity(t, externalID, []string{"billing:read"})

	resp := get(t, "/api/v1/identities/"+identity.ID, adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body := decode(t, resp)
	assert.Equal(t, identity.ID, body["id"])
	assert.Equal(t, externalID, body["external_id"])
	assert.Equal(t, identity.WIMSEURI, body["wimse_uri"])
}

// TestGetIdentityNotFound verifies that fetching an unknown ID returns 404.
func TestGetIdentityNotFound(t *testing.T) {
	resp := get(t, "/api/v1/identities/00000000-0000-0000-0000-000000000000", adminHeaders())
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
}

// TestListIdentities verifies that the list endpoint returns identities scoped to the tenant.
func TestListIdentities(t *testing.T) {
	// Register two identities in this test's tenant.
	registerIdentity(t, uid("list-a"), []string{"billing:read"})
	registerIdentity(t, uid("list-b"), []string{"data:read"})

	resp := get(t, "/api/v1/identities", adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)

	items, ok := body["identities"].([]any)
	require.True(t, ok, "response should have an 'identities' array")
	assert.GreaterOrEqual(t, len(items), 2, "should have at least the two just registered")
}

func TestListAgentsFilterByIdentityType(t *testing.T) {
	// Register an agent and an application.
	agentExt := uid("filter-agent")
	appExt := uid("filter-app")

	post(t, "/api/v1/agents/register", map[string]any{
		"external_id":   agentExt,
		"identity_type": "agent",
		"sub_type":      "autonomous",
		"trust_level":   "unverified",
		"name":          "Filter Agent",
		"created_by":    "test-user",
		"labels":        map[string]string{"product": "guardrails"},
	}, adminHeaders())

	post(t, "/api/v1/agents/register", map[string]any{
		"external_id":   appExt,
		"identity_type": "application",
		"sub_type":      "custom",
		"trust_level":   "unverified",
		"name":          "Filter App",
		"created_by":    "test-user",
		"labels":        map[string]string{"product": "guardrails"},
	}, adminHeaders())

	// Single type filter — only agents.
	resp := get(t, "/api/v1/agents/registry?identity_type=agent&label=product:guardrails", adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	agents := body["agents"].([]any)
	for _, a := range agents {
		m := a.(map[string]any)
		assert.Equal(t, "agent", m["identity_type"], "should only return agents")
	}

	// Multi-value filter — agents and applications (comma-separated).
	resp = get(t, "/api/v1/agents/registry?identity_type=agent,application&label=product:guardrails", adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body = decode(t, resp)
	both := body["agents"].([]any)
	types := map[string]bool{}
	for _, a := range both {
		m := a.(map[string]any)
		types[m["identity_type"].(string)] = true
	}
	assert.True(t, types["agent"], "should include agents")
	assert.True(t, types["application"], "should include applications")

	// No filter — returns all types.
	resp = get(t, "/api/v1/agents/registry?label=product:guardrails", adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body = decode(t, resp)
	all := body["agents"].([]any)
	assert.GreaterOrEqual(t, len(all), len(both), "no filter should return at least as many as filtered")
}

// TestUpdateIdentityTrustLevel verifies that PATCH /api/v1/identities/{id}
// can promote the trust level.
func TestUpdateIdentityTrustLevel(t *testing.T) {
	externalID := uid("trust-agent")
	identity := registerIdentity(t, externalID, []string{"billing:read"})

	resp, err := doRaw(t, http.MethodPatch, "/api/v1/identities/"+identity.ID, map[string]any{
		"trust_level": "verified_third_party",
	}, adminHeaders())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body := decode(t, resp)
	assert.Equal(t, "verified_third_party", body["trust_level"])
}

// TestDeleteIdentity verifies that DELETE /api/v1/identities/{id} deactivates the identity.
func TestDeleteIdentity(t *testing.T) {
	externalID := uid("delete-agent")
	identity := registerIdentity(t, externalID, []string{"billing:read"})

	resp, err := doRaw(t, http.MethodDelete, "/api/v1/identities/"+identity.ID, nil, adminHeaders())
	require.NoError(t, err)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp.Body.Close()
}

func TestServerGetIdentity(t *testing.T) {
	externalID := uid("get-identity-srv")
	identity := registerIdentity(t, externalID, nil)

	// Found: valid ID + tenant.
	got, err := testZeroIDServer.GetIdentity(context.Background(), identity.ID, testAccountID, testProjectID)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, identity.ID, got.ID)
	assert.Equal(t, externalID, got.ExternalID)

	// Wrong tenant — returns error, no identity.
	got, err = testZeroIDServer.GetIdentity(context.Background(), identity.ID, "wrong-account", testProjectID)
	assert.Error(t, err)
	assert.Nil(t, got)

	// Non-existent ID.
	got, err = testZeroIDServer.GetIdentity(context.Background(), "00000000-0000-0000-0000-000000000000", testAccountID, testProjectID)
	assert.Error(t, err)
	assert.Nil(t, got)
}

// doRaw is a variant that accepts a method string for PATCH/DELETE.
func doRaw(t *testing.T, method, path string, body any, headers map[string]string) (*http.Response, error) {
	t.Helper()
	return http.DefaultClient.Do(newRequest(t, method, path, body, headers))
}
