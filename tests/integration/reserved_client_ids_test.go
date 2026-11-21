// Client ids reserved for the operator: no tenant-facing registration path
// may take one; only Server.EnsureClient may.
package integration_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	zeroid "github.com/highflame-ai/zeroid"
)

// ── Reserved client ids ──────────────────────────────────────────────────────

func TestReservedClientIDs_RefusedOnTenantRegistration(t *testing.T) {
	for _, id := range []string{testReservedClientID, "Platform-Gateway", testReservedClientPrefix + uid("x")} {
		for name, headers := range map[string]map[string]string{"tenant": adminHeaders(), "no tenant": nil} {
			t.Run(id+"/"+name, func(t *testing.T) {
				resp := post(t, adminPath("/oauth/clients"), map[string]any{
					"client_id": id, "name": id, "grant_types": []string{"authorization_code"},
				}, headers)
				body := decode(t, resp)
				assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "%v", body)
			})
		}
	}

	t.Run("the operator's seeding path may register one", func(t *testing.T) {
		id := testReservedClientPrefix + uid("seeded")
		require.NoError(t, testZeroIDServer.EnsureClient(context.Background(), zeroid.OAuthClientConfig{
			ClientID: id, Name: id, GrantTypes: []string{"authorization_code"}, RedirectURIs: []string{testRedirectURI},
		}))
		assert.True(t, testZeroIDServer.IsReservedClientID(id))
		assert.False(t, testZeroIDServer.IsReservedClientID(uid("ordinary")))
	})
}

// A trusted-issuer binding registers the presenting client under the subject
// key (or the client_id it names). It must never take a reserved id.
func TestReservedClientIDs_RefusedOnBinding(t *testing.T) {
	f := newDBFederation(t)
	tn := newTITenant(t)
	rowID := f.entraRow(t, tn, uid("res-tid"), nil)["id"].(string)
	agent := tn.agent(t)

	for _, key := range []string{testReservedClientID, testReservedClientPrefix + uid("bind")} {
		status, body := f.bind(t, tn, rowID, key, agent.id, true)
		assert.Equal(t, http.StatusBadRequest, status, "%v", body)
		assert.Equal(t, "reserved_client_id", body["code"])
	}

	// The binding transaction rolled back: nothing was registered.
	var n int
	require.NoError(t, testDB.NewRaw("SELECT count(*) FROM oauth_clients WHERE client_id = ?", testReservedClientID).
		Scan(context.Background(), &n))
	assert.Zero(t, n)
}
