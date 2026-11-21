// Client ids reserved for the operator: no tenant-facing registration path
// may take one; only Server.EnsureClient may.
package integration_test

import (
	"context"
	"encoding/json"
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

// On a token exchange client_id is the actor identity's external_id, a name
// its tenant chose, not a client that authenticated. A reserved name is not
// written there, so an identity named after a reserved client cannot mint a
// token that reads as that client.
func TestReservedClientIDs_NotWrittenAsExchangeClientID(t *testing.T) {
	tn := newTenant(t, "")
	scopes := []string{"data:read"}
	policyID := tn.policy(t, scopes)
	root, _ := tn.workloadRoot(t, policyID, scopes)

	ordinary := uid("plain-actor")
	body, _ := tn.exchange(t, policyID, ordinary, scopes, root)
	assert.Equal(t, ordinary, decodeJWTPayload(t, body["access_token"].(string))["client_id"],
		"control: an ordinary actor's external_id is the client_id")

	body, _ = tn.exchange(t, policyID, testReservedClientPrefix+uid("actor"), scopes, root)
	assert.NotContains(t, decodeJWTPayload(t, body["access_token"].(string)), "client_id")
}

// The deployment's own service acting in an exchange keeps its client_id: the
// reserved client of that name is linked to the acting identity itself.
func TestReservedClientIDs_ExchangeKeepsClientIDOfItsOwnLinkedClient(t *testing.T) {
	ctx := context.Background()
	tn := newTenant(t, "")
	scopes := []string{"data:read"}
	policyID := tn.policy(t, scopes)
	root, _ := tn.workloadRoot(t, policyID, scopes)

	extID := testReservedClientPrefix + uid("own")
	key := generateKey(t)
	wimse := tn.register(t, extID, policyID, ecPublicKeyPEM(t, key), scopes)
	var identityID string
	require.NoError(t, testDB.NewRaw("SELECT id FROM identities WHERE external_id = ? AND account_id = ?", extID, tn.account).
		Scan(ctx, &identityID))
	jwks, err := json.Marshal(clientJWKS(t, generateKey(t)))
	require.NoError(t, err)
	require.NoError(t, testZeroIDServer.EnsureClient(ctx, zeroid.OAuthClientConfig{
		ClientID: extID, Name: extID, IdentityID: identityID,
		TokenEndpointAuthMethod: "private_key_jwt", JWKS: jwks, GrantTypes: []string{"client_credentials"},
	}))

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": root,
		"actor_token":   buildAssertion(t, key, wimse),
		"scope":         "data:read",
	}, nil)
	body := decode(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", body)
	assert.Equal(t, extID, decodeJWTPayload(t, body["access_token"].(string))["client_id"])
}
