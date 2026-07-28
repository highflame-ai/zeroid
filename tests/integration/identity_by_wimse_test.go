package integration_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// byWIMSEPath builds GET /api/v1/identities/by-wimse?uri=<wimseURI> with the
// URI query-encoded. Test callers MUST go through this rather than string-
// concatenation so the `/` characters inside the SPIFFE path don't accidentally
// land as extra path segments.
func byWIMSEPath(wimseURI string) string {
	q := url.Values{}
	q.Set("uri", wimseURI)
	return adminPath("/identities/by-wimse") + "?" + q.Encode()
}

// TestGetIdentityByWIMSE_Found verifies the happy path: a freshly registered
// identity is resolvable by its WIMSE URI and the response payload matches the
// identity returned at registration time.
func TestGetIdentityByWIMSE_Found(t *testing.T) {
	externalID := uid("by-wimse-found")
	identity := registerIdentity(t, externalID, []string{"billing:read"})

	resp := get(t, byWIMSEPath(identity.WIMSEURI), adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode, "expected 200 for known WIMSE URI")

	body := decode(t, resp)
	assert.Equal(t, identity.ID, body["id"])
	assert.Equal(t, identity.WIMSEURI, body["wimse_uri"])
	assert.Equal(t, externalID, body["external_id"])
	assert.Equal(t, testAccountID, body["account_id"])
	assert.Equal(t, testProjectID, body["project_id"])
	// status must round-trip — this is the field firehog gates on.
	assert.Equal(t, "active", body["status"])
}

// TestGetIdentityByWIMSE_TenantScoping verifies cross-tenant isolation:
// an identity created in tenant A is NOT visible to a caller presenting
// tenant B's headers, even with the exact WIMSE URI. Returns 404, not 403
// (existence disclosure) and not 200.
func TestGetIdentityByWIMSE_TenantScoping(t *testing.T) {
	// Tenant A is the default test tenant (testAccountID / testProjectID).
	externalID := uid("by-wimse-iso")
	identity := registerIdentity(t, externalID, []string{"billing:read"})

	// Tenant B: a fresh isolated tenant.
	tenantB := tenantHeaders("acct-by-wimse-b-"+uid(""), "proj-by-wimse-b-"+uid(""))

	resp := get(t, byWIMSEPath(identity.WIMSEURI), tenantB)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode,
		"cross-tenant lookup must return 404, not 200 (leak) or 403 (existence disclosure)")
	_ = resp.Body.Close()
}

// TestGetIdentityByWIMSE_NotFound verifies that a well-formed URI with no
// matching identity returns 404 with the structured error contract.
func TestGetIdentityByWIMSE_NotFound(t *testing.T) {
	wimse := "spiffe://" + testWIMSE + "/" + testAccountID + "/" + testProjectID + "/agent/does-not-exist-" + uid("")
	resp := get(t, byWIMSEPath(wimse), adminHeaders())
	require.Equal(t, http.StatusNotFound, resp.StatusCode)

	body := decode(t, resp)
	// huma RFC 9457 problem-details: detail carries the failure code.
	assert.Equal(t, "identity_not_found", body["detail"])
	// errors[0].value echoes the offending URI for callers that log it.
	if errs, ok := body["errors"].([]any); ok && len(errs) > 0 {
		first := errs[0].(map[string]any)
		assert.Equal(t, wimse, first["value"])
		assert.Equal(t, "query.uri", first["location"])
	} else {
		t.Fatalf("expected errors[0] payload, got %v", body)
	}
}

// TestGetIdentityByWIMSE_InvalidURI exercises the shape validator: anything
// that isn't a valid spiffe:// URI returns 400 with the invalid_wimse_uri
// error code, before the store is touched.
func TestGetIdentityByWIMSE_InvalidURI(t *testing.T) {
	cases := []struct {
		name string
		uri  string
	}{
		{"not_a_uri", "not-a-uri"},
		{"missing_scheme", testWIMSE + "/" + testAccountID + "/" + testProjectID + "/agent/x"},
		{"wrong_scheme", "https://" + testWIMSE + "/" + testAccountID + "/" + testProjectID + "/agent/x"},
		{"missing_path", "spiffe://" + testWIMSE},
		{"trailing_slash_only", "spiffe://" + testWIMSE + "/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := get(t, byWIMSEPath(tc.uri), adminHeaders())
			require.Equal(t, http.StatusBadRequest, resp.StatusCode,
				"expected 400 for %q, got %d", tc.uri, resp.StatusCode)
			body := decode(t, resp)
			assert.Equal(t, "invalid_wimse_uri", body["detail"])
			if errs, ok := body["errors"].([]any); ok && len(errs) > 0 {
				first := errs[0].(map[string]any)
				assert.Equal(t, tc.uri, first["value"])
				assert.Equal(t, "query.uri", first["location"])
			} else {
				t.Fatalf("expected errors[0] payload, got %v", body)
			}
		})
	}
}

// TestGetIdentityByWIMSE_AuthRequired verifies that omitting the tenant
// headers (X-Account-ID / X-Project-ID) returns 401, mirroring every other
// tenant-scoped admin endpoint. This is the same "missing tenant context"
// gate used by GET /identities/{id} and friends.
func TestGetIdentityByWIMSE_AuthRequired(t *testing.T) {
	wimse := "spiffe://" + testWIMSE + "/" + testAccountID + "/" + testProjectID + "/agent/any"
	// No headers — tenant context will be absent.
	resp := get(t, byWIMSEPath(wimse), nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"missing tenant headers must yield 401, got %d", resp.StatusCode)
	_ = resp.Body.Close()
}
