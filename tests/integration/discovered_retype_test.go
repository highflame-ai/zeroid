package integration_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestDiscoveredRetype_ApplicationToMCPServer pins the CAP-DSC-003 fix: a
// still-discovered application is re-typed to mcp_server on a later sync (its
// identity_type was previously frozen at first ingestion), and the WIMSE URI —
// which embeds identity_type as a path segment — is rebuilt in lockstep so
// by-URI resolution stays correct.
func TestDiscoveredRetype_ApplicationToMCPServer(t *testing.T) {
	ext := uid("okta-mcp-app")

	// First sync: discovered as a generic OAuth application (pre-typing state).
	first := ingestDiscovered(t, map[string]any{
		"external_id":   ext,
		"origin":        "okta",
		"identity_type": "application",
		"name":          "Acme Connector",
	})["identity"].(map[string]any)
	require.Equal(t, "application", first["identity_type"])
	require.Equal(t, "discovered", first["status"])
	oldURI := first["wimse_uri"].(string)
	require.Contains(t, oldURI, "/application/", "URI embeds identity_type")

	// Re-sync: same external_id, now classified as an MCP server.
	second := ingestDiscovered(t, map[string]any{
		"external_id":   ext,
		"origin":        "okta",
		"identity_type": "mcp_server",
		"name":          "Acme Connector",
	})["identity"].(map[string]any)
	require.Equal(t, first["id"], second["id"], "re-sync must reconcile the same row")
	require.Equal(t, "mcp_server", second["identity_type"], "still-discovered row must be re-typed on re-sync")
	newURI := second["wimse_uri"].(string)
	require.Contains(t, newURI, "/mcp_server/", "wimse_uri must be rebuilt to reflect the new type")
	require.NotEqual(t, oldURI, newURI, "wimse_uri must change when identity_type changes")

	// The rebuild is persisted and resolvable: the new URI resolves to this row,
	// the stale one no longer does.
	newResp := get(t, adminPath("/identities/by-wimse")+"?uri="+url.QueryEscape(newURI), adminHeaders())
	require.Equal(t, http.StatusOK, newResp.StatusCode, "new wimse_uri must resolve")
	_ = newResp.Body.Close()

	oldResp := get(t, adminPath("/identities/by-wimse")+"?uri="+url.QueryEscape(oldURI), adminHeaders())
	require.Equal(t, http.StatusNotFound, oldResp.StatusCode, "stale wimse_uri must no longer resolve")
	_ = oldResp.Body.Close()
}

// TestDiscoveredRetype_AdoptedRowNotRetyped pins the guard: once a row is adopted
// (out of the discovered inbox) its type may be human-curated, so a later sync
// must NOT re-type it, and its WIMSE URI must stay put.
func TestDiscoveredRetype_AdoptedRowNotRetyped(t *testing.T) {
	ext := uid("okta-adopted-mcp")

	first := ingestDiscovered(t, map[string]any{
		"external_id":   ext,
		"origin":        "okta",
		"identity_type": "application",
		"name":          "Adopted App",
	})["identity"].(map[string]any)
	id := first["id"].(string)
	adoptedURI := first["wimse_uri"].(string)

	// Adopt it (discovered → pending): assigns an accountable owner.
	resp, err := doRaw(t, http.MethodPost, adminPath("/identities/"+id+"/adopt"),
		map[string]any{"owner_user_id": "user-owner-1"}, adminHeaders())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "adopt should succeed with just an owner")
	_ = resp.Body.Close()

	// A later sync now classifying it as mcp_server must be ignored for the type.
	after := ingestDiscovered(t, map[string]any{
		"external_id":   ext,
		"origin":        "okta",
		"identity_type": "mcp_server",
		"name":          "Adopted App",
	})["identity"].(map[string]any)
	require.Equal(t, id, after["id"])
	require.Equal(t, "application", after["identity_type"], "adopted rows must never be re-typed on re-sync")
	require.Equal(t, adoptedURI, after["wimse_uri"], "adopted row's wimse_uri must stay put")
}
