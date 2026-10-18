// OAuth client admin routes and tenant scope. A client row has no tenant
// columns, but a client linked to an identity (identity_id) takes that
// identity's tenant, and the link decides where client_credentials and ID-JAG
// tokens are minted. A caller in another tenant must not see, rotate or delete
// such a client; an unlinked client stays global.
package integration_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// registerClientIn registers a confidential client in the tenant headers name,
// linked to a fresh identity in that tenant when link is true, and returns the
// client's UUID.
func registerClientIn(t *testing.T, headers map[string]string, link bool) string {
	t.Helper()
	clientID := uid("tenant-scope-client")
	body := map[string]any{
		"client_id": clientID, "name": clientID, "confidential": true,
		"grant_types": []string{"client_credentials"}, "scopes": []string{"data:read"},
	}
	if link {
		body["identity_id"] = registerIdentityIn(t, headers, uid("tenant-scope-identity"), []string{"data:read"}).ID
	}
	resp := post(t, adminPath("/oauth/clients"), body, headers)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	client, ok := decode(t, resp)["client"].(map[string]any)
	require.True(t, ok)
	return client["id"].(string)
}

func listedClientIDs(t *testing.T, headers map[string]string) map[string]bool {
	t.Helper()
	resp := get(t, adminPath("/oauth/clients"), headers)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	ids := map[string]bool{}
	for _, c := range decode(t, resp)["clients"].([]any) {
		ids[c.(map[string]any)["id"].(string)] = true
	}
	return ids
}

func TestOAuthClientAdminRoutes_TenantScoped(t *testing.T) {
	tenantA := tenantHeaders(uid("acct-a"), uid("proj-a"))
	tenantB := tenantHeaders(uid("acct-b"), uid("proj-b"))
	linked := registerClientIn(t, tenantA, true)
	unlinked := registerClientIn(t, tenantA, false)

	t.Run("get is not found for a client linked into another tenant", func(t *testing.T) {
		require.Equal(t, http.StatusOK, get(t, adminPath("/oauth/clients/"+linked), tenantA).StatusCode)
		require.Equal(t, http.StatusNotFound, get(t, adminPath("/oauth/clients/"+linked), tenantB).StatusCode)
	})

	t.Run("rotate-secret is not found for a client linked into another tenant", func(t *testing.T) {
		resp := post(t, adminPath("/oauth/clients/"+linked+"/rotate-secret"), nil, tenantB)
		require.Equal(t, http.StatusNotFound, resp.StatusCode)
		resp = post(t, adminPath("/oauth/clients/"+linked+"/rotate-secret"), nil, tenantA)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("list leaves out clients linked into another tenant", func(t *testing.T) {
		require.True(t, listedClientIDs(t, tenantA)[linked])
		require.False(t, listedClientIDs(t, tenantB)[linked])
	})

	t.Run("an unlinked client stays global", func(t *testing.T) {
		require.Equal(t, http.StatusOK, get(t, adminPath("/oauth/clients/"+unlinked), tenantB).StatusCode)
		require.True(t, listedClientIDs(t, tenantB)[unlinked])
		resp := post(t, adminPath("/oauth/clients/"+unlinked+"/rotate-secret"), nil, tenantB)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("delete from another tenant leaves the client in place", func(t *testing.T) {
		resp := doRequest(t, http.MethodDelete, adminPath("/oauth/clients/"+linked), nil, tenantB)
		require.Equal(t, http.StatusOK, resp.StatusCode, "answers like a missing client")
		require.Equal(t, http.StatusOK, get(t, adminPath("/oauth/clients/"+linked), tenantA).StatusCode)

		resp = doRequest(t, http.MethodDelete, adminPath("/oauth/clients/"+linked), nil, tenantA)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, http.StatusNotFound, get(t, adminPath("/oauth/clients/"+linked), tenantA).StatusCode)
	})
}
