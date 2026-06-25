// Discovery inventory lifecycle (see docs/identity-lifecycle.md):
// ingest a discovered identity, reconcile idempotently, then drive it through
// adopt / dismiss. Pins the `discovered` state + `origin` provenance contract
// the discovery service and Studio depend on.

package integration_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ingestDiscovered POSTs /identities/discovered and returns the decoded body
// ({identity, created}).
func ingestDiscovered(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	resp := post(t, adminPath("/identities/discovered"), body, adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode, "ingest discovered: expected 200")
	return decode(t, resp)
}

// TestDiscovered_IngestCreatesDiscoveredState verifies a discovered identity is
// created owner-less, credential-less, in the `discovered` state with external
// origin — the posture-only entry state.
func TestDiscovered_IngestCreatesDiscoveredState(t *testing.T) {
	ext := uid("okta-agent")
	out := ingestDiscovered(t, map[string]any{
		"external_id": ext,
		"origin":      "okta",
		"name":        "Okta Service Account",
	})
	assert.Equal(t, true, out["created"], "first ingest should report created=true")

	identity := out["identity"].(map[string]any)
	assert.Equal(t, ext, identity["external_id"])
	assert.Equal(t, "discovered", identity["status"], "discovered identities enter in the discovered state")
	assert.Equal(t, "okta", identity["origin"])
	assert.Equal(t, "", identity["owner_user_id"], "discovered identities are owner-optional")
	// WIMSE URI is still minted on the IdP object id (the reconciliation key).
	assert.Contains(t, identity["wimse_uri"].(string), "/"+ext)
}

// TestDiscovered_IngestIsIdempotent verifies a re-sync reconciles to the SAME
// row (created=false) and refreshes descriptive fields without duplicating.
func TestDiscovered_IngestIsIdempotent(t *testing.T) {
	ext := uid("entra-agent")
	first := ingestDiscovered(t, map[string]any{
		"external_id": ext,
		"origin":      "entra",
		"name":        "v1 name",
	})
	firstID := first["identity"].(map[string]any)["id"].(string)

	second := ingestDiscovered(t, map[string]any{
		"external_id": ext,
		"origin":      "entra",
		"name":        "v2 name",
	})
	assert.Equal(t, false, second["created"], "re-ingest should report created=false")
	secondIdentity := second["identity"].(map[string]any)
	assert.Equal(t, firstID, secondIdentity["id"], "re-ingest must reconcile to the same row")
	assert.Equal(t, "v2 name", secondIdentity["name"], "re-ingest refreshes descriptive fields")
}

// TestDiscovered_IngestRejectsNativeOrigin verifies the ingest endpoint refuses
// a native origin — discovered identities are external by definition.
func TestDiscovered_IngestRejectsNativeOrigin(t *testing.T) {
	resp := post(t, adminPath("/identities/discovered"), map[string]any{
		"external_id": uid("bad"),
		"origin":      "native",
	}, adminHeaders())
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	_ = resp.Body.Close()
}

// TestDiscovered_IngestConflictsWithNative verifies discovery cannot clobber a
// natively-registered identity that shares an external_id.
func TestDiscovered_IngestConflictsWithNative(t *testing.T) {
	ext := uid("shared-id")
	registerIdentity(t, ext, nil) // native, active

	resp := post(t, adminPath("/identities/discovered"), map[string]any{
		"external_id": ext,
		"origin":      "okta",
		"name":        "should not overwrite native",
	}, adminHeaders())
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	_ = resp.Body.Close()
}

// TestDiscovered_AdoptAssignsOwnerAndPends verifies adopt moves discovered →
// pending and assigns the owner.
func TestDiscovered_AdoptAssignsOwnerAndPends(t *testing.T) {
	ext := uid("adopt-me")
	out := ingestDiscovered(t, map[string]any{"external_id": ext, "origin": "okta"})
	id := out["identity"].(map[string]any)["id"].(string)

	resp, err := doRaw(t, http.MethodPost, adminPath("/identities/"+id+"/adopt"), map[string]any{
		"owner_user_id": "user-adopter",
	}, adminHeaders())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	assert.Equal(t, "pending", body["status"], "adopt moves discovered → pending")
	assert.Equal(t, "user-adopter", body["owner_user_id"])
	assert.Equal(t, "okta", body["origin"], "origin is immutable provenance — adoption keeps it")
}

// TestDiscovered_AdoptWithoutOwnerRejected verifies adoption via a raw PATCH to
// status=pending on an owner-less discovered identity is rejected — adoption is
// the act of making an external agent accountable.
func TestDiscovered_AdoptWithoutOwnerRejected(t *testing.T) {
	ext := uid("ownerless")
	out := ingestDiscovered(t, map[string]any{"external_id": ext, "origin": "okta"})
	id := out["identity"].(map[string]any)["id"].(string)

	resp, err := doRaw(t, http.MethodPatch, adminPath("/identities/"+id), map[string]any{
		"status": "pending",
	}, adminHeaders())
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"adopting an owner-less discovered identity must be rejected")
	_ = resp.Body.Close()
}

// TestDiscovered_Dismiss verifies dismiss archives a discovered identity
// (discovered → deactivated) and is idempotent.
func TestDiscovered_Dismiss(t *testing.T) {
	ext := uid("dismiss-me")
	out := ingestDiscovered(t, map[string]any{"external_id": ext, "origin": "okta"})
	id := out["identity"].(map[string]any)["id"].(string)

	resp, err := doRaw(t, http.MethodPost, adminPath("/identities/"+id+"/dismiss"), nil, adminHeaders())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "deactivated", decode(t, resp)["status"], "dismiss archives discovered → deactivated")

	// Idempotent: a second dismiss is a no-op success.
	resp, err = doRaw(t, http.MethodPost, adminPath("/identities/"+id+"/dismiss"), nil, adminHeaders())
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()
}

// TestDiscovered_ListFilters verifies the discovery-inventory filters:
// status=discovered (the adoption inbox), origin=<idp>, and origin=external.
func TestDiscovered_ListFilters(t *testing.T) {
	ext := uid("filterable")
	ingestDiscovered(t, map[string]any{"external_id": ext, "origin": "okta"})

	found := func(path string) bool {
		resp := get(t, adminPath(path), adminHeaders())
		require.Equal(t, http.StatusOK, resp.StatusCode)
		body := decode(t, resp)
		for _, raw := range body["identities"].([]any) {
			if raw.(map[string]any)["external_id"] == ext {
				return true
			}
		}
		return false
	}

	assert.True(t, found("/identities?status=discovered&limit=100"), "status=discovered must surface it")
	assert.True(t, found("/identities?origin=okta&limit=100"), "origin=okta must surface it")
	assert.True(t, found("/identities?origin=external&limit=100"), "origin=external must surface it")
}

// TestDiscovered_NativeRegistrationUnchanged is a regression guard: a normal
// registration is still origin=native, status=active.
func TestDiscovered_NativeRegistrationUnchanged(t *testing.T) {
	ext := uid("native-regress")
	resp := post(t, adminPath("/identities"), map[string]any{
		"external_id":   ext,
		"owner_user_id": "user-test-owner",
	}, adminHeaders())
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	body := decode(t, resp)
	assert.Equal(t, "active", body["status"])
	assert.Equal(t, "native", body["origin"])
}

// TestDiscovered_ReingestDoesNotRegressAdopted pins the headline upsert
// guarantee: once a discovered identity is adopted, a connector re-sync refreshes
// descriptive fields but never regresses lifecycle or drops the owner.
func TestDiscovered_ReingestDoesNotRegressAdopted(t *testing.T) {
	ext := uid("adopted-resync")
	out := ingestDiscovered(t, map[string]any{"external_id": ext, "origin": "okta", "name": "v1"})
	id := out["identity"].(map[string]any)["id"].(string)

	resp, err := doRaw(t, http.MethodPost, adminPath("/identities/"+id+"/adopt"), map[string]any{
		"owner_user_id": "user-owner",
	}, adminHeaders())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "pending", decode(t, resp)["status"])

	// Re-sync must reconcile to the same row, keep it pending, keep the owner,
	// and still refresh descriptive fields.
	second := ingestDiscovered(t, map[string]any{"external_id": ext, "origin": "okta", "name": "v2"})
	assert.Equal(t, false, second["created"])
	got := second["identity"].(map[string]any)
	assert.Equal(t, id, got["id"], "re-sync reconciles to the same row")
	assert.Equal(t, "pending", got["status"], "re-sync must not regress an adopted identity")
	assert.Equal(t, "user-owner", got["owner_user_id"], "re-sync must preserve the owner")
	assert.Equal(t, "v2", got["name"], "re-sync still refreshes descriptive fields")
}

// TestDiscovered_ReingestDoesNotResurrectDismissed verifies a deliberately
// dismissed agent is not silently brought back by a later sync.
func TestDiscovered_ReingestDoesNotResurrectDismissed(t *testing.T) {
	ext := uid("dismissed-resync")
	out := ingestDiscovered(t, map[string]any{"external_id": ext, "origin": "okta"})
	id := out["identity"].(map[string]any)["id"].(string)

	resp, err := doRaw(t, http.MethodPost, adminPath("/identities/"+id+"/dismiss"), nil, adminHeaders())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "deactivated", decode(t, resp)["status"])

	second := ingestDiscovered(t, map[string]any{"external_id": ext, "origin": "okta"})
	assert.Equal(t, false, second["created"])
	assert.Equal(t, "deactivated", second["identity"].(map[string]any)["status"],
		"a dismissed identity must stay dismissed on re-sync")
}

// TestDiscovered_AdoptThenActivate walks the full path to a usable identity:
// discovered → pending (adopt) → active.
func TestDiscovered_AdoptThenActivate(t *testing.T) {
	ext := uid("activate-me")
	out := ingestDiscovered(t, map[string]any{"external_id": ext, "origin": "okta"})
	id := out["identity"].(map[string]any)["id"].(string)

	resp, err := doRaw(t, http.MethodPost, adminPath("/identities/"+id+"/adopt"), map[string]any{
		"owner_user_id": "user-owner",
	}, adminHeaders())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "pending", decode(t, resp)["status"])

	resp, err = doRaw(t, http.MethodPatch, adminPath("/identities/"+id), map[string]any{
		"status": "active",
	}, adminHeaders())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "active", decode(t, resp)["status"], "pending → active completes the path to a usable identity")
}

// TestDiscovered_DismissNonDiscoveredRejected verifies dismiss is only for
// discovered identities — a live native identity is deactivated via DELETE.
func TestDiscovered_DismissNonDiscoveredRejected(t *testing.T) {
	reg := registerIdentity(t, uid("native-dismiss"), nil)
	resp, err := doRaw(t, http.MethodPost, adminPath("/identities/"+reg.ID+"/dismiss"), nil, adminHeaders())
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"dismiss must refuse a non-discovered identity")
	_ = resp.Body.Close()
}

// TestDiscovered_Facets verifies the discovery posture facets: the origin
// breakdown and the ownerless count.
func TestDiscovered_Facets(t *testing.T) {
	ingestDiscovered(t, map[string]any{"external_id": uid("facet-okta"), "origin": "okta"})

	resp := get(t, adminPath("/agents/registry/facets"), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)

	origins, ok := body["origins"].([]any)
	require.True(t, ok, "facets must include an origins breakdown")
	var oktaCount float64
	for _, raw := range origins {
		f := raw.(map[string]any)
		if f["value"] == "okta" {
			oktaCount = f["count"].(float64)
		}
	}
	assert.Greater(t, oktaCount, float64(0), "origins facet must count the okta-discovered identity")

	ownerless, ok := body["ownerless"].(float64)
	require.True(t, ok, "facets must include an ownerless count")
	assert.Greater(t, ownerless, float64(0), "ownerless count must reflect the ownerless discovered identity")
}

// TestDiscovered_IngestRejectsInvalidOriginShape verifies an origin that isn't a
// clean lowercase identifier is rejected (consistently, regardless of whether a
// row already exists).
func TestDiscovered_IngestRejectsInvalidOriginShape(t *testing.T) {
	resp := post(t, adminPath("/identities/discovered"), map[string]any{
		"external_id": uid("bad-shape"),
		"origin":      "Okta-Prod",
	}, adminHeaders())
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	_ = resp.Body.Close()
}

// TestDiscovered_ListRejectsInvalidStatusFilter verifies the list endpoint
// validates the status filter rather than silently returning nothing.
func TestDiscovered_ListRejectsInvalidStatusFilter(t *testing.T) {
	resp := get(t, adminPath("/identities?status=bogus"), adminHeaders())
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	_ = resp.Body.Close()
}

// TestDiscovered_AgentsEndpointSurfacesOrigin pins that the /agents/registry
// list (the endpoint admin/Studio proxy for the inventory) surfaces `origin` on
// each agent and honors the origin/status filters — not just the /identities
// surface. Without this the unified native∪discovered inventory wouldn't reach
// Studio through admin.
func TestDiscovered_AgentsEndpointSurfacesOrigin(t *testing.T) {
	ext := uid("agents-origin")
	ingestDiscovered(t, map[string]any{"external_id": ext, "origin": "okta"})

	find := func(path string) (bool, string, string) {
		resp := get(t, adminPath(path), adminHeaders())
		require.Equal(t, http.StatusOK, resp.StatusCode)
		body := decode(t, resp)
		for _, raw := range body["agents"].([]any) {
			a := raw.(map[string]any)
			if a["external_id"] == ext {
				return true, a["origin"].(string), a["status"].(string)
			}
		}
		return false, "", ""
	}

	ok, origin, status := find("/agents/registry?origin=okta&limit=100")
	assert.True(t, ok, "origin=okta filter must surface the discovered agent via /agents/registry")
	assert.Equal(t, "okta", origin, "the agents endpoint must surface origin")
	assert.Equal(t, "discovered", status)

	okStatus, _, _ := find("/agents/registry?status=discovered&limit=100")
	assert.True(t, okStatus, "status=discovered filter must work on /agents/registry")

	// Invalid origin filter is rejected (not silently empty).
	bad := get(t, adminPath("/agents/registry?origin=Okta-Prod"), adminHeaders())
	assert.Equal(t, http.StatusBadRequest, bad.StatusCode)
	_ = bad.Body.Close()
}

// ── Connector-sync: bulk ingest + stale prune ────────────────────────────────

// ingestBatch POSTs /identities/discovered/batch and returns the decoded
// {created, reconciled, failed} summary.
func ingestBatch(t *testing.T, agents []map[string]any) map[string]any {
	t.Helper()
	resp := post(t, adminPath("/identities/discovered/batch"), map[string]any{"agents": agents}, adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode, "bulk ingest: expected 200")
	return decode(t, resp)
}

// pruneStale POSTs /identities/discovered/prune and returns the deactivated count.
func pruneStale(t *testing.T, origin, sourceID, notSeenSince string) int {
	t.Helper()
	resp := post(t, adminPath("/identities/discovered/prune"), map[string]any{
		"origin": origin, "source_id": sourceID, "not_seen_since": notSeenSince,
	}, adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode, "prune: expected 200")
	return int(decode(t, resp)["deactivated"].(float64))
}

// identityStatus GETs an identity by id and returns its status.
func identityStatus(t *testing.T, id string) string {
	t.Helper()
	resp := get(t, adminPath("/identities/"+id), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	return decode(t, resp)["status"].(string)
}

// TestDiscovered_BulkIngest verifies bulk upsert creates all agents and a
// re-batch reconciles them (idempotent).
func TestDiscovered_BulkIngest(t *testing.T) {
	src := uid("bulk-src")
	a, b := uid("bulk-a"), uid("bulk-b")
	res := ingestBatch(t, []map[string]any{
		{"external_id": a, "origin": "okta", "source_id": src, "name": "A"},
		{"external_id": b, "origin": "entra", "source_id": src, "name": "B"},
	})
	assert.Equal(t, float64(2), res["created"])
	assert.Equal(t, float64(0), res["reconciled"])
	assert.Empty(t, res["failed"], "no failures expected")

	res2 := ingestBatch(t, []map[string]any{
		{"external_id": a, "origin": "okta", "source_id": src},
		{"external_id": b, "origin": "entra", "source_id": src},
	})
	assert.Equal(t, float64(0), res2["created"], "re-batch creates nothing")
	assert.Equal(t, float64(2), res2["reconciled"], "re-batch reconciles both")
}

// TestDiscovered_SourceIDRoundtrip verifies source_id is stored and returned.
func TestDiscovered_SourceIDRoundtrip(t *testing.T) {
	src := uid("conn-id")
	out := ingestDiscovered(t, map[string]any{"external_id": uid("with-src"), "origin": "okta", "source_id": src})
	identity := out["identity"].(map[string]any)
	assert.Equal(t, src, identity["source_id"], "source_id set on ingest")

	resp := get(t, adminPath("/identities/"+identity["id"].(string)), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, src, decode(t, resp)["source_id"], "source_id round-trips through GET")
}

// TestDiscovered_PruneStale verifies a sync's prune deactivates exactly the
// discovered rows it no longer saw (last updated before the sync start), and
// leaves the re-seen ones discovered.
func TestDiscovered_PruneStale(t *testing.T) {
	src := uid("prune-src")
	keepExt, staleExt := uid("keep"), uid("stale")
	keep := ingestDiscovered(t, map[string]any{"external_id": keepExt, "origin": "okta", "source_id": src})
	stale := ingestDiscovered(t, map[string]any{"external_id": staleExt, "origin": "okta", "source_id": src})
	keepID := keep["identity"].(map[string]any)["id"].(string)
	staleID := stale["identity"].(map[string]any)["id"].(string)

	// The connector records the sync start, then re-ingests only what it still
	// sees ("keep"), advancing keep's updated_at past the sync start.
	syncStart := time.Now().UTC()
	ingestDiscovered(t, map[string]any{"external_id": keepExt, "origin": "okta", "source_id": src})

	n := pruneStale(t, "okta", src, syncStart.Format(time.RFC3339Nano))
	assert.Equal(t, 1, n, "exactly the not-re-seen identity is pruned")
	assert.Equal(t, "discovered", identityStatus(t, keepID), "re-seen identity stays discovered")
	assert.Equal(t, "deactivated", identityStatus(t, staleID), "stale identity is deactivated")
}

// TestDiscovered_PruneIsSourceScoped verifies a prune for one source never
// touches another connector's agents of the same origin.
func TestDiscovered_PruneIsSourceScoped(t *testing.T) {
	srcA, srcB := uid("connA"), uid("connB")
	a := ingestDiscovered(t, map[string]any{"external_id": uid("a"), "origin": "okta", "source_id": srcA})
	b := ingestDiscovered(t, map[string]any{"external_id": uid("b"), "origin": "okta", "source_id": srcB})
	aID := a["identity"].(map[string]any)["id"].(string)
	bID := b["identity"].(map[string]any)["id"].(string)

	// not_seen_since in the future → every source-A discovered row is stale.
	future := time.Now().UTC().Add(time.Hour)
	n := pruneStale(t, "okta", srcA, future.Format(time.RFC3339Nano))
	assert.Equal(t, 1, n, "prune only affects source A")
	assert.Equal(t, "deactivated", identityStatus(t, aID))
	assert.Equal(t, "discovered", identityStatus(t, bID), "source B is untouched by source A's prune")
}

// TestDiscovered_PruneLeavesAdoptedUntouched verifies prune only acts on
// still-discovered rows — an adopted identity is never auto-deactivated.
func TestDiscovered_PruneLeavesAdoptedUntouched(t *testing.T) {
	src := uid("adopt-src")
	out := ingestDiscovered(t, map[string]any{"external_id": uid("adopted"), "origin": "okta", "source_id": src})
	id := out["identity"].(map[string]any)["id"].(string)

	resp, err := doRaw(t, http.MethodPost, adminPath("/identities/"+id+"/adopt"), map[string]any{"owner_user_id": "user-owner"}, adminHeaders())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	future := time.Now().UTC().Add(time.Hour)
	pruneStale(t, "okta", src, future.Format(time.RFC3339Nano))
	assert.Equal(t, "pending", identityStatus(t, id), "prune never touches an adopted identity")
}

// TestDiscovered_PruneRejectsNativeOrigin verifies a prune can't be scoped to
// native — it only operates on discovered (external) inventory.
func TestDiscovered_PruneRejectsNativeOrigin(t *testing.T) {
	resp := post(t, adminPath("/identities/discovered/prune"), map[string]any{
		"origin": "native", "source_id": "conn-x", "not_seen_since": time.Now().UTC().Format(time.RFC3339Nano),
	}, adminHeaders())
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	_ = resp.Body.Close()
}

// TestDiscovered_PruneRejectsBadTimestamp verifies not_seen_since must be RFC3339.
func TestDiscovered_PruneRejectsBadTimestamp(t *testing.T) {
	resp := post(t, adminPath("/identities/discovered/prune"), map[string]any{
		"origin": "okta", "source_id": "conn-x", "not_seen_since": "not-a-timestamp",
	}, adminHeaders())
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	_ = resp.Body.Close()
}
