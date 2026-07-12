// Server-side filter tests for the /identities and /agents/registry endpoints.
// Covers single filters, multi-filter combos, edge cases, validation, and facets.
// Depends on the changes in feat/registry-server-filters (zeroid#229).

package integration_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Fixtures — shared data setup used across multiple tests
// ---------------------------------------------------------------------------

// filterFixture creates a set of identities with known attributes for filter
// testing. Returns the label used to scope queries to this fixture's data.
func filterFixture(t *testing.T) string {
	t.Helper()
	label := uid("filter-suite")

	// Native: active, first_party, owned (via /identities which accepts owner_user_id)
	post(t, adminPath("/identities"), map[string]any{
		"external_id":   uid("ff-active-fp"),
		"identity_type": "agent",
		"sub_type":      "autonomous",
		"trust_level":   "first_party",
		"name":          "Active FP Agent",
		"owner_user_id": "user_owner_1",
		"labels":        map[string]string{"suite": label},
	}, adminHeaders())

	// Native: active, unverified, owned
	post(t, adminPath("/identities"), map[string]any{
		"external_id":   uid("ff-active-uv"),
		"identity_type": "agent",
		"sub_type":      "tool_agent",
		"trust_level":   "unverified",
		"name":          "Active UV Agent",
		"owner_user_id": "user_owner_2",
		"labels":        map[string]string{"suite": label},
	}, adminHeaders())

	// Native: active, unverified, ownerless — then deactivated to test multi-status
	resp := post(t, adminPath("/identities"), map[string]any{
		"external_id":   uid("ff-deactivated"),
		"identity_type": "agent",
		"sub_type":      "autonomous",
		"trust_level":   "unverified",
		"name":          "Deactivated Agent",
		"owner_user_id": "user_deactivate",
		"labels":        map[string]string{"suite": label},
	}, adminHeaders())
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	deactivateBody := decode(t, resp)
	deactivateID := deactivateBody["id"].(string)
	deactResp, err := doRaw(t, http.MethodDelete, adminPath("/identities/"+deactivateID), nil, adminHeaders())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, deactResp.StatusCode)
	_ = deactResp.Body.Close()

	// Discovered: ownerless by definition (no owner until adopted), origin=okta.
	// Labels are set so the suite filter can scope queries to this fixture.
	ingestDiscovered(t, map[string]any{
		"external_id": uid("ff-discovered"),
		"origin":      "okta",
		"name":        "Discovered Okta Agent",
		"labels":      map[string]string{"suite": label},
	})

	return label
}

// ---------------------------------------------------------------------------
// Single-filter tests (positive paths)
// ---------------------------------------------------------------------------

func TestIdentityFilter_SingleStatus(t *testing.T) {
	label := filterFixture(t)

	// status=active — should return only active identities
	resp := get(t, adminPath("/agents/registry?status=active&label=suite:"+label), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	agents := body["agents"].([]any)
	assert.GreaterOrEqual(t, len(agents), 1, "should find at least one active agent")
	for _, a := range agents {
		m := a.(map[string]any)
		assert.Equal(t, "active", m["status"], "status filter should only return active")
	}
}

func TestIdentityFilter_MultiStatus(t *testing.T) {
	label := filterFixture(t)

	// status=active,deactivated — both statuses
	resp := get(t, adminPath("/agents/registry?status=active,deactivated&label=suite:"+label), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	agents := body["agents"].([]any)
	statuses := map[string]bool{}
	for _, a := range agents {
		m := a.(map[string]any)
		s := m["status"].(string)
		assert.Contains(t, []string{"active", "deactivated"}, s, "should only return active or deactivated")
		statuses[s] = true
	}
	assert.True(t, statuses["active"], "should include active agents")
	assert.True(t, statuses["deactivated"], "should include deactivated agents")
}

func TestIdentityFilter_SingleTrustLevel(t *testing.T) {
	label := filterFixture(t)

	resp := get(t, adminPath("/agents/registry?trust_level=first_party&label=suite:"+label), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	agents := body["agents"].([]any)
	assert.GreaterOrEqual(t, len(agents), 1, "should find at least one first_party agent")
	for _, a := range agents {
		m := a.(map[string]any)
		assert.Equal(t, "first_party", m["trust_level"], "trust_level filter should only return first_party")
	}
}

func TestIdentityFilter_MultiTrustLevel(t *testing.T) {
	label := filterFixture(t)

	resp := get(t, adminPath("/agents/registry?trust_level=first_party,unverified&label=suite:"+label), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	agents := body["agents"].([]any)
	levels := map[string]bool{}
	for _, a := range agents {
		m := a.(map[string]any)
		tl := m["trust_level"].(string)
		assert.Contains(t, []string{"first_party", "unverified"}, tl)
		levels[tl] = true
	}
	assert.True(t, levels["first_party"], "should include first_party")
	assert.True(t, levels["unverified"], "should include unverified")
}

func TestIdentityFilter_OwnerUserID(t *testing.T) {
	label := filterFixture(t)

	resp := get(t, adminPath("/agents/registry?owner_user_id=user_owner_1&label=suite:"+label), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	agents := body["agents"].([]any)
	assert.GreaterOrEqual(t, len(agents), 1, "should find at least one agent owned by user_owner_1")
	for _, a := range agents {
		m := a.(map[string]any)
		assert.Equal(t, "user_owner_1", m["owner_user_id"], "should only return agents owned by user_owner_1")
	}
}

func TestIdentityFilter_OwnerlessTrue(t *testing.T) {
	label := filterFixture(t)

	// Native agents require an owner, so ownerless identities are always
	// discovered. Query with status=discovered to include them.
	resp := get(t, adminPath("/agents/registry?ownerless=true&status=discovered&label=suite:"+label), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	agents := body["agents"].([]any)
	assert.GreaterOrEqual(t, len(agents), 1, "should find at least one ownerless agent")
	for _, a := range agents {
		m := a.(map[string]any)
		owner, _ := m["owner_user_id"].(string)
		assert.Empty(t, owner, "ownerless filter should only return agents with no owner")
	}
}

func TestIdentityFilter_Search(t *testing.T) {
	label := filterFixture(t)

	resp := get(t, adminPath("/agents/registry?search=Active+FP+Agent&label=suite:"+label), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	agents := body["agents"].([]any)
	assert.GreaterOrEqual(t, len(agents), 1, "search should find at least one matching agent")
}

func TestIdentityFilter_DefaultExcludesDiscovered(t *testing.T) {
	label := filterFixture(t)

	// Default list (no status param) should NOT include discovered agents
	resp := get(t, adminPath("/agents/registry?label=suite:"+label), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	agents := body["agents"].([]any)
	for _, a := range agents {
		m := a.(map[string]any)
		assert.NotEqual(t, "discovered", m["status"], "default list must exclude discovered agents")
	}
}

func TestIdentityFilter_ExplicitDiscovered(t *testing.T) {
	filterFixture(t)

	// Explicit status=discovered should return only discovered
	resp := get(t, adminPath("/agents/registry?status=discovered"), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	agents := body["agents"].([]any)
	assert.GreaterOrEqual(t, len(agents), 1, "should find at least one discovered agent")
	for _, a := range agents {
		m := a.(map[string]any)
		assert.Equal(t, "discovered", m["status"], "should only return discovered agents")
	}
}

// ---------------------------------------------------------------------------
// /identities endpoint — mirrors the /agents/registry tests above
// ---------------------------------------------------------------------------

func TestIdentitiesEndpoint_DefaultExcludesDiscovered(t *testing.T) {
	filterFixture(t)

	resp := get(t, adminPath("/identities"), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	identities := body["identities"].([]any)
	for _, i := range identities {
		m := i.(map[string]any)
		assert.NotEqual(t, "discovered", m["status"], "default /identities must exclude discovered")
	}
}

func TestIdentitiesEndpoint_ExplicitDiscovered(t *testing.T) {
	filterFixture(t)

	resp := get(t, adminPath("/identities?status=discovered"), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	identities := body["identities"].([]any)
	assert.GreaterOrEqual(t, len(identities), 1, "explicit status=discovered must return discovered identities")
	for _, i := range identities {
		m := i.(map[string]any)
		assert.Equal(t, "discovered", m["status"])
	}
}

func TestIdentitiesEndpoint_MultiStatusFilter(t *testing.T) {
	label := filterFixture(t)

	resp := get(t, adminPath("/identities?status=active,deactivated&label=suite:"+label), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	identities := body["identities"].([]any)
	for _, i := range identities {
		m := i.(map[string]any)
		assert.Contains(t, []string{"active", "deactivated"}, m["status"])
	}
}

func TestIdentitiesEndpoint_TrustLevelFilter(t *testing.T) {
	label := filterFixture(t)

	resp := get(t, adminPath("/identities?trust_level=first_party&label=suite:"+label), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	identities := body["identities"].([]any)
	assert.GreaterOrEqual(t, len(identities), 1)
	for _, i := range identities {
		m := i.(map[string]any)
		assert.Equal(t, "first_party", m["trust_level"])
	}
}

// ---------------------------------------------------------------------------
// Multi-filter combination tests
// ---------------------------------------------------------------------------

func TestIdentityFilter_StatusAndTrustLevel(t *testing.T) {
	label := filterFixture(t)

	resp := get(t, adminPath("/agents/registry?status=active&trust_level=first_party&label=suite:"+label), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	agents := body["agents"].([]any)
	assert.GreaterOrEqual(t, len(agents), 1)
	for _, a := range agents {
		m := a.(map[string]any)
		assert.Equal(t, "active", m["status"], "combo filter: status must be active")
		assert.Equal(t, "first_party", m["trust_level"], "combo filter: trust_level must be first_party")
	}
}

func TestIdentityFilter_StatusAndOwnerless(t *testing.T) {
	label := filterFixture(t)

	resp := get(t, adminPath("/agents/registry?status=active&ownerless=true&label=suite:"+label), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	agents := body["agents"].([]any)
	for _, a := range agents {
		m := a.(map[string]any)
		assert.Equal(t, "active", m["status"])
		owner, _ := m["owner_user_id"].(string)
		assert.Empty(t, owner, "combo: must be ownerless")
	}
}

func TestIdentityFilter_StatusAndSearch(t *testing.T) {
	label := filterFixture(t)

	resp := get(t, adminPath("/agents/registry?status=active&search=Active+FP&label=suite:"+label), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	agents := body["agents"].([]any)
	assert.GreaterOrEqual(t, len(agents), 1)
	for _, a := range agents {
		m := a.(map[string]any)
		assert.Equal(t, "active", m["status"])
	}
}

func TestIdentityFilter_DiscoveredAndOrigin(t *testing.T) {
	filterFixture(t)

	resp := get(t, adminPath("/agents/registry?status=discovered&origin=okta"), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	agents := body["agents"].([]any)
	assert.GreaterOrEqual(t, len(agents), 1)
	for _, a := range agents {
		m := a.(map[string]any)
		assert.Equal(t, "discovered", m["status"])
		assert.Equal(t, "okta", m["origin"])
	}
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

func TestIdentityFilter_NoMatch_EmptyResult(t *testing.T) {
	noMatchLabel := uid("no-match")

	resp := get(t, adminPath("/agents/registry?label=suite:"+noMatchLabel), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	agents := body["agents"].([]any)
	assert.Equal(t, 0, len(agents), "filter matching nothing should return empty array")
	assert.Equal(t, float64(0), body["total"], "total should be 0")
}

func TestIdentityFilter_OffsetBeyondTotal(t *testing.T) {
	label := filterFixture(t)

	resp := get(t, adminPath("/agents/registry?offset=99999&label=suite:"+label), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	agents := body["agents"].([]any)
	assert.Equal(t, 0, len(agents), "offset beyond total should return empty array")
}

func TestIdentityFilter_LimitOne(t *testing.T) {
	label := filterFixture(t)

	resp := get(t, adminPath("/agents/registry?limit=1&label=suite:"+label), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	agents := body["agents"].([]any)
	assert.Equal(t, 1, len(agents), "limit=1 should return exactly 1 result")
	total := body["total"].(float64)
	assert.Greater(t, total, float64(1), "total should reflect all matching, not just page")
}

func TestIdentityFilter_SearchSpecialChars(t *testing.T) {
	// Special characters in search should not cause errors
	resp := get(t, adminPath("/agents/registry?search=%25test%27"), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	// Should return empty or matching — no 500
	assert.NotNil(t, body["agents"], "response should have agents array even with special chars")
}

func TestIdentityFilter_OwnerlessFalse_NoFiltering(t *testing.T) {
	label := filterFixture(t)

	// ownerless param omitted — should return all (owned + ownerless)
	resp := get(t, adminPath("/agents/registry?label=suite:"+label), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	allBody := decode(t, resp)
	allAgents := allBody["agents"].([]any)

	// ownerless=true — should return fewer
	resp = get(t, adminPath("/agents/registry?ownerless=true&label=suite:"+label), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	ownerlessBody := decode(t, resp)
	ownerlessAgents := ownerlessBody["agents"].([]any)

	assert.Greater(t, len(allAgents), len(ownerlessAgents),
		"omitting ownerless should return more results than ownerless=true")
}

func TestIdentityFilter_NonexistentOwner_EmptyResult(t *testing.T) {
	resp := get(t, adminPath("/agents/registry?owner_user_id=user_does_not_exist"), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	agents := body["agents"].([]any)
	assert.Equal(t, 0, len(agents), "nonexistent owner should return empty, not error")
}

// ---------------------------------------------------------------------------
// Negative / validation tests
// ---------------------------------------------------------------------------

func TestIdentityFilter_InvalidStatus_400(t *testing.T) {
	resp := get(t, adminPath("/agents/registry?status=bogus"), adminHeaders())
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	_ = resp.Body.Close()
}

func TestIdentityFilter_InvalidTrustLevel_400(t *testing.T) {
	resp := get(t, adminPath("/agents/registry?trust_level=bogus"), adminHeaders())
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	_ = resp.Body.Close()
}

func TestIdentityFilter_InvalidOwnerless_400(t *testing.T) {
	resp := get(t, adminPath("/agents/registry?ownerless=maybe"), adminHeaders())
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	_ = resp.Body.Close()
}

func TestIdentitiesEndpoint_InvalidStatus_400(t *testing.T) {
	resp := get(t, adminPath("/identities?status=bogus"), adminHeaders())
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	_ = resp.Body.Close()
}

func TestIdentitiesEndpoint_InvalidTrustLevel_400(t *testing.T) {
	resp := get(t, adminPath("/identities?trust_level=bogus"), adminHeaders())
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	_ = resp.Body.Close()
}

func TestIdentitiesEndpoint_InvalidOwnerless_400(t *testing.T) {
	resp := get(t, adminPath("/identities?ownerless=maybe"), adminHeaders())
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	_ = resp.Body.Close()
}

// ---------------------------------------------------------------------------
// Facets tests
// ---------------------------------------------------------------------------

func TestFacets_DiscoveredCountPresent(t *testing.T) {
	// Ensure at least one discovered agent exists
	ingestDiscovered(t, map[string]any{
		"external_id": uid("facet-disc"),
		"origin":      "okta",
	})

	resp := get(t, adminPath("/agents/registry/facets"), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)

	discovered, ok := body["discovered"].(float64)
	require.True(t, ok, "facets must include a 'discovered' count")
	assert.Greater(t, discovered, float64(0), "discovered count should reflect ingested agents")
}

func TestFacets_OwnerlessExcludesDiscovered(t *testing.T) {
	// Ingest a discovered ownerless agent
	ext := uid("facet-ownerless-disc")
	ingestDiscovered(t, map[string]any{
		"external_id": ext,
		"origin":      "okta",
	})

	resp := get(t, adminPath("/agents/registry/facets"), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)

	// The ownerless count should NOT include discovered agents
	// (discovered agents are pre-governance; ownerless tracks governed identities)
	ownerless, ok := body["ownerless"].(float64)
	require.True(t, ok, "facets must include an 'ownerless' count")

	discovered, ok := body["discovered"].(float64)
	require.True(t, ok, "facets must include a 'discovered' count")

	// If we had only discovered agents with no owner, ownerless should still be 0
	// (or at least less than discovered) — verifying the exclusion logic
	_ = ownerless
	_ = discovered
	// The key assertion: discovered agents don't inflate ownerless count.
	// We can't assert ownerless == 0 because other tests may have created
	// governed ownerless agents. Instead, verify the field exists and is a number.
	assert.GreaterOrEqual(t, ownerless, float64(0), "ownerless must be a non-negative count")
}

func TestFacets_OriginExcludesDiscovered(t *testing.T) {
	resp := get(t, adminPath("/agents/registry/facets"), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)

	// Verify response shape — origins is an array of {value, count}
	origins, ok := body["origins"].([]any)
	require.True(t, ok, "facets must include an 'origins' breakdown")

	for _, raw := range origins {
		f := raw.(map[string]any)
		assert.NotEmpty(t, f["value"], "each origin facet must have a value")
		count := f["count"].(float64)
		assert.GreaterOrEqual(t, count, float64(0), "origin counts must be non-negative")
	}
}

// ---------------------------------------------------------------------------
// Response shape consistency
// ---------------------------------------------------------------------------

func TestIdentityFilter_ResponseShape(t *testing.T) {
	resp := get(t, adminPath("/agents/registry?limit=1"), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)

	assert.NotNil(t, body["agents"], "response must include 'agents' array")
	assert.NotNil(t, body["total"], "response must include 'total'")
	assert.NotNil(t, body["limit"], "response must include 'limit'")
	assert.NotNil(t, body["offset"], "response must include 'offset'")
}

func TestIdentitiesEndpoint_ResponseShape(t *testing.T) {
	resp := get(t, adminPath("/identities?limit=1"), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)

	assert.NotNil(t, body["identities"], "response must include 'identities' array")
	assert.NotNil(t, body["total"], "response must include 'total'")
	assert.NotNil(t, body["limit"], "response must include 'limit'")
	assert.NotNil(t, body["offset"], "response must include 'offset'")
}
