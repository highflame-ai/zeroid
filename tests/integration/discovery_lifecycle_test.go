// Discovery inventory lifecycle (see docs/identity-lifecycle.md):
// ingest a discovered identity, reconcile idempotently, then drive it through
// adopt / dismiss. Pins the `discovered` state + `origin` provenance contract
// the discovery service and Studio depend on.

package integration_test

import (
	"net/http"
	"testing"

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
