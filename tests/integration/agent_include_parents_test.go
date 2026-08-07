// Tests for GET /agents/registry?include_parents=true — parent hydration that
// lets a paginated/filtered caller nest sub-agents under their parent agent even
// when the parent is off-page or filtered out.

package integration_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// registerAgentWithParent registers an agent via POST /agents/register, scoped to
// `suite` via a label, and returns its id. A non-empty parentExternalID makes it a
// sub-agent (its metadata carries parent_external_id).
func registerAgentWithParent(t *testing.T, suite, externalID, parentExternalID string) string {
	t.Helper()

	meta := map[string]any{}
	if parentExternalID != "" {
		meta["parent_external_id"] = parentExternalID
	}

	resp := post(t, adminPath("/agents/register"), map[string]any{
		"external_id": externalID,
		"name":        externalID,
		"sub_type":    "autonomous",
		"trust_level": "first_party",
		"created_by":  "test-user",
		"labels":      map[string]string{"suite": suite},
		"metadata":    meta,
	}, adminHeaders())
	require.Equal(t, http.StatusCreated, resp.StatusCode, "registerAgentWithParent: expected 201")

	body := decode(t, resp)
	ident := body["identity"].(map[string]any)

	return ident["id"].(string)
}

// agentFamily creates a parent agent (created first, so it sorts older) and a
// sub-agent whose parent_external_id points at it, both scoped to a fresh suite
// label. Returns the suite label, the parent external_id, the sub-agent
// external_id, and the parent's identity id.
func agentFamily(t *testing.T) (suite, parentExt, childExt, parentID string) {
	t.Helper()

	suite = uid("agent-nest")
	parentExt = uid("agent-parent")
	childExt = parentExt + "-sub-a1"
	parentID = registerAgentWithParent(t, suite, parentExt, "")
	registerAgentWithParent(t, suite, childExt, parentExt)

	return suite, parentExt, childExt, parentID
}

func agentExternalIDs(agents []any) []string {
	out := make([]string, 0, len(agents))
	for _, a := range agents {
		out = append(out, a.(map[string]any)["external_id"].(string))
	}

	return out
}

// TestListAgents_IncludeParents_HydratesFilteredOutParent is the core case: the
// parent agent is DEACTIVATED, so status=active filters it out of the page
// entirely. include_parents must still hydrate it so a caller can nest the
// (active) sub-agent under it.
func TestListAgents_IncludeParents_HydratesFilteredOutParent(t *testing.T) {
	suite, parentExt, childExt, parentID := agentFamily(t)

	// Deactivate the parent agent (DELETE = deactivate, per the identities API).
	deact, err := doRaw(t, http.MethodDelete, adminPath("/identities/"+parentID), nil, adminHeaders())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, deact.StatusCode)
	_ = deact.Body.Close()

	resp := get(t, adminPath("/agents/registry?label=suite:"+suite+"&status=active&include_parents=true"), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)

	// The status=active page contains only the sub-agent — the parent is filtered out.
	agents := body["agents"].([]any)
	require.Equal(t, []string{childExt}, agentExternalIDs(agents))

	// ...but the parent agent is hydrated as context so a caller can nest.
	require.Contains(t, body, "parents")
	parents := body["parents"].([]any)
	require.Len(t, parents, 1, "filtered-out parent agent must be hydrated")
	parent := parents[0].(map[string]any)
	assert.Equal(t, parentExt, parent["external_id"])
	assert.NotEqual(t, "active", parent["status"], "hydrated parent is the deactivated agent")
}

// TestListAgents_IncludeParents_HydratesOffPageParent covers pagination: the
// parent agent is simply on another page (limit=1), not filtered out.
func TestListAgents_IncludeParents_HydratesOffPageParent(t *testing.T) {
	suite, parentExt, childExt, _ := agentFamily(t)

	// limit=1 + created_at DESC: page 1 holds the newer sub-agent; the parent is
	// on page 2.
	resp := get(t, adminPath("/agents/registry?label=suite:"+suite+"&limit=1&include_parents=true"), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)

	agents := body["agents"].([]any)
	require.Equal(t, []string{childExt}, agentExternalIDs(agents))
	assert.Equal(t, float64(2), body["total"], "total counts real rows only, not hydrated parents")

	parents := body["parents"].([]any)
	require.Len(t, parents, 1, "off-page parent agent must be hydrated")
	assert.Equal(t, parentExt, parents[0].(map[string]any)["external_id"])
}

// TestListAgents_IncludeParents_OmittedByDefault: without include_parents the
// server must not hydrate — parents is absent/empty, preserving legacy behavior.
func TestListAgents_IncludeParents_OmittedByDefault(t *testing.T) {
	suite, _, childExt, _ := agentFamily(t)

	resp := get(t, adminPath("/agents/registry?label=suite:"+suite+"&limit=1"), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)

	agents := body["agents"].([]any)
	require.Equal(t, []string{childExt}, agentExternalIDs(agents))

	if p, ok := body["parents"]; ok {
		assert.Empty(t, p, "parents must be empty/absent unless include_parents=true")
	}
}
