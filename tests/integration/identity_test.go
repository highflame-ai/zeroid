package integration_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRegisterIdentity verifies that a new identity can be created
// and the response contains the expected WIMSE URI format.
func TestRegisterIdentity(t *testing.T) {
	externalID := uid("research-agent")
	resp := post(t, adminPath("/identities"), map[string]any{
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
	resp := post(t, adminPath("/identities"), map[string]any{
		"external_id":    externalID,
		"trust_level":    "unverified",
		"owner_user_id":  "user-test-owner",
		"allowed_scopes": []string{"billing:read"},
	}, adminHeaders())
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	_ = resp.Body.Close()
}

// TestRegisterIdentityMissingExternalID verifies that omitting external_id returns 400/422.
func TestRegisterIdentityMissingExternalID(t *testing.T) {
	resp := post(t, adminPath("/identities"), map[string]any{
		"trust_level":    "unverified",
		"owner_user_id":  "user-test-owner",
		"allowed_scopes": []string{"billing:read"},
	}, adminHeaders())
	assert.True(t,
		resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnprocessableEntity,
		"expected 400 or 422 for missing external_id, got %d", resp.StatusCode,
	)
	_ = resp.Body.Close()
}

// TestGetIdentity verifies that GET /api/v1/identities/{id} returns the identity.
func TestGetIdentity(t *testing.T) {
	externalID := uid("get-agent")
	identity := registerIdentity(t, externalID, []string{"billing:read"})

	resp := get(t, adminPath("/identities/"+identity.ID), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body := decode(t, resp)
	assert.Equal(t, identity.ID, body["id"])
	assert.Equal(t, externalID, body["external_id"])
	assert.Equal(t, identity.WIMSEURI, body["wimse_uri"])
}

// TestGetIdentityNotFound verifies that fetching an unknown ID returns 404.
func TestGetIdentityNotFound(t *testing.T) {
	resp := get(t, adminPath("/identities/00000000-0000-0000-0000-000000000000"), adminHeaders())
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	_ = resp.Body.Close()
}

// TestListIdentities verifies that the list endpoint returns identities scoped to the tenant.
func TestListIdentities(t *testing.T) {
	// Register two identities in this test's tenant.
	registerIdentity(t, uid("list-a"), []string{"billing:read"})
	registerIdentity(t, uid("list-b"), []string{"data:read"})

	resp := get(t, adminPath("/identities"), adminHeaders())
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

	post(t, adminPath("/agents/register"), map[string]any{
		"external_id":   agentExt,
		"identity_type": "agent",
		"sub_type":      "autonomous",
		"trust_level":   "unverified",
		"name":          "Filter Agent",
		"created_by":    "test-user",
		"labels":        map[string]string{"product": "guardrails"},
	}, adminHeaders())

	post(t, adminPath("/agents/register"), map[string]any{
		"external_id":   appExt,
		"identity_type": "application",
		"sub_type":      "custom",
		"trust_level":   "unverified",
		"name":          "Filter App",
		"created_by":    "test-user",
		"labels":        map[string]string{"product": "guardrails"},
	}, adminHeaders())

	// Single type filter — only agents.
	resp := get(t, adminPath("/agents/registry?identity_type=agent&label=product:guardrails"), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	agents := body["agents"].([]any)
	for _, a := range agents {
		m := a.(map[string]any)
		assert.Equal(t, "agent", m["identity_type"], "should only return agents")
	}

	// Multi-value filter — agents and applications (comma-separated).
	resp = get(t, adminPath("/agents/registry?identity_type=agent,application&label=product:guardrails"), adminHeaders())
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
	resp = get(t, adminPath("/agents/registry?label=product:guardrails"), adminHeaders())
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

	resp, err := doRaw(t, http.MethodPatch, adminPath("/identities/"+identity.ID), map[string]any{
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

	resp, err := doRaw(t, http.MethodDelete, adminPath("/identities/"+identity.ID), nil, adminHeaders())
	require.NoError(t, err)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	_ = resp.Body.Close()
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

// ── Filter & Pagination Tests ───────────────────────────────────────────────

// TestListAgentsFilterByTrustLevel verifies that trust_level filter works server-side.
func TestListAgentsFilterByTrustLevel(t *testing.T) {
	fpExt := uid("trust-fp")
	uvExt := uid("trust-uv")

	// Register a first_party agent.
	post(t, adminPath("/agents/register"), map[string]any{
		"external_id":   fpExt,
		"identity_type": "agent",
		"sub_type":      "autonomous",
		"trust_level":   "first_party",
		"name":          "First Party Agent",
		"created_by":    "test-user",
		"labels":        map[string]string{"test": "trust-filter"},
	}, adminHeaders())

	// Register an unverified agent.
	post(t, adminPath("/agents/register"), map[string]any{
		"external_id":   uvExt,
		"identity_type": "agent",
		"sub_type":      "tool_agent",
		"trust_level":   "unverified",
		"name":          "Unverified Agent",
		"created_by":    "test-user",
		"labels":        map[string]string{"test": "trust-filter"},
	}, adminHeaders())

	// Filter by first_party only.
	resp := get(t, adminPath("/agents/registry?trust_level=first_party&label=test:trust-filter"), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	agents := body["agents"].([]any)
	for _, a := range agents {
		m := a.(map[string]any)
		assert.Equal(t, "first_party", m["trust_level"], "should only return first_party agents")
	}
	assert.GreaterOrEqual(t, len(agents), 1, "should have at least one first_party agent")

	// Filter by unverified — should not include first_party.
	resp = get(t, adminPath("/agents/registry?trust_level=unverified&label=test:trust-filter"), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body = decode(t, resp)
	agents = body["agents"].([]any)
	for _, a := range agents {
		m := a.(map[string]any)
		assert.Equal(t, "unverified", m["trust_level"], "should only return unverified agents")
	}
}

// TestListAgentsFilterByIsActive verifies that is_active filter works.
func TestListAgentsFilterByIsActive(t *testing.T) {
	activeExt := uid("active-a")
	inactiveExt := uid("active-b")

	// Register and keep one active.
	post(t, adminPath("/agents/register"), map[string]any{
		"external_id":   activeExt,
		"identity_type": "agent",
		"sub_type":      "autonomous",
		"trust_level":   "unverified",
		"name":          "Active Agent",
		"created_by":    "test-user",
		"labels":        map[string]string{"test": "active-filter"},
	}, adminHeaders())

	// Register and deactivate.
	resp := post(t, adminPath("/agents/register"), map[string]any{
		"external_id":   inactiveExt,
		"identity_type": "agent",
		"sub_type":      "tool_agent",
		"trust_level":   "unverified",
		"name":          "Inactive Agent",
		"created_by":    "test-user",
		"labels":        map[string]string{"test": "active-filter"},
	}, adminHeaders())
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	registered := decode(t, resp)
	agentID := registered["identity"].(map[string]any)["id"].(string)

	// Deactivate.
	deactivateResp, err := doRaw(t, http.MethodPost, adminPath("/agents/registry/"+agentID+"/deactivate"), nil, adminHeaders())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, deactivateResp.StatusCode)
	_ = deactivateResp.Body.Close()

	// is_active=true should exclude deactivated.
	resp = get(t, adminPath("/agents/registry?is_active=true&label=test:active-filter"), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	agents := body["agents"].([]any)
	for _, a := range agents {
		m := a.(map[string]any)
		assert.Equal(t, "active", m["status"], "is_active=true should only return active agents")
	}

	// is_active=false should only return non-active.
	resp = get(t, adminPath("/agents/registry?is_active=false&label=test:active-filter"), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body = decode(t, resp)
	agents = body["agents"].([]any)
	for _, a := range agents {
		m := a.(map[string]any)
		assert.NotEqual(t, "active", m["status"], "is_active=false should exclude active agents")
	}
}

// TestListAgentsSearch verifies that name/external_id search works.
func TestListAgentsSearch(t *testing.T) {
	searchTag := uid("search")
	ext1 := uid("search-alpha")
	ext2 := uid("search-beta")

	post(t, adminPath("/agents/register"), map[string]any{
		"external_id":   ext1,
		"identity_type": "agent",
		"sub_type":      "autonomous",
		"trust_level":   "unverified",
		"name":          "Alpha Research Bot " + searchTag,
		"created_by":    "test-user",
	}, adminHeaders())

	post(t, adminPath("/agents/register"), map[string]any{
		"external_id":   ext2,
		"identity_type": "agent",
		"sub_type":      "tool_agent",
		"trust_level":   "unverified",
		"name":          "Beta Trading Bot " + searchTag,
		"created_by":    "test-user",
	}, adminHeaders())

	// Search by name substring.
	resp := get(t, adminPath("/agents/registry?search=Alpha+Research"), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	agents := body["agents"].([]any)
	found := false
	for _, a := range agents {
		m := a.(map[string]any)
		if m["external_id"] == ext1 {
			found = true
		}
	}
	assert.True(t, found, "search should find Alpha Research Bot by name")

	// Search by external_id substring.
	resp = get(t, adminPath("/agents/registry?search=")+ext2[:20], adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body = decode(t, resp)
	agents = body["agents"].([]any)
	found = false
	for _, a := range agents {
		m := a.(map[string]any)
		if m["external_id"] == ext2 {
			found = true
		}
	}
	assert.True(t, found, "search should find agent by external_id substring")
}

// TestListAgentsPagination verifies limit and offset work correctly.
func TestListAgentsPagination(t *testing.T) {
	paginationLabel := uid("page")

	// Register 5 agents with a unique label.
	for i := 0; i < 5; i++ {
		post(t, adminPath("/agents/register"), map[string]any{
			"external_id":   uid(fmt.Sprintf("page-%d", i)),
			"identity_type": "agent",
			"sub_type":      "autonomous",
			"trust_level":   "unverified",
			"name":          fmt.Sprintf("Page Agent %d", i),
			"created_by":    "test-user",
			"labels":        map[string]string{"pagination": paginationLabel},
		}, adminHeaders())
	}

	// Request first page (limit=2).
	resp := get(t, adminPath("/agents/registry?limit=2&offset=0&label=pagination:")+paginationLabel, adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	page1 := body["agents"].([]any)
	assert.Equal(t, 2, len(page1), "first page should have 2 agents")
	assert.Equal(t, float64(5), body["total"], "total should be 5")

	// Request second page (limit=2, offset=2).
	resp = get(t, adminPath("/agents/registry?limit=2&offset=2&label=pagination:")+paginationLabel, adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body = decode(t, resp)
	page2 := body["agents"].([]any)
	assert.Equal(t, 2, len(page2), "second page should have 2 agents")

	// Pages should not overlap.
	page1IDs := map[string]bool{}
	for _, a := range page1 {
		page1IDs[a.(map[string]any)["id"].(string)] = true
	}
	for _, a := range page2 {
		id := a.(map[string]any)["id"].(string)
		assert.False(t, page1IDs[id], "page 2 should not contain agents from page 1")
	}

	// Request last page (offset=4, limit=2) — should return 1 agent.
	resp = get(t, adminPath("/agents/registry?limit=2&offset=4&label=pagination:")+paginationLabel, adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body = decode(t, resp)
	page3 := body["agents"].([]any)
	assert.Equal(t, 1, len(page3), "last page should have 1 agent")
}

// TestListIdentitiesEndpointFilters verifies that /api/v1/identities also supports filters.
func TestListIdentitiesEndpointFilters(t *testing.T) {
	ext := uid("id-filter")
	post(t, adminPath("/identities"), map[string]any{
		"external_id":    ext,
		"trust_level":    "first_party",
		"identity_type":  "application",
		"sub_type":       "chatbot",
		"owner_user_id":  "test-user",
		"name":           "Filterable App " + ext,
		"allowed_scopes": []string{"read:data"},
	}, adminHeaders())

	// Filter by identity_type.
	resp := get(t, adminPath("/identities?identity_type=application"), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	identities := body["identities"].([]any)
	for _, i := range identities {
		m := i.(map[string]any)
		assert.Equal(t, "application", m["identity_type"])
	}

	// Search by name.
	resp = get(t, adminPath("/identities?search=Filterable+App"), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body = decode(t, resp)
	identities = body["identities"].([]any)
	found := false
	for _, i := range identities {
		m := i.(map[string]any)
		if m["external_id"] == ext {
			found = true
		}
	}
	assert.True(t, found, "search should find the identity by name")

	// Pagination metadata present.
	assert.NotNil(t, body["total"], "response should include total")
	assert.NotNil(t, body["limit"], "response should include limit")
	assert.NotNil(t, body["offset"], "response should include offset")
}
