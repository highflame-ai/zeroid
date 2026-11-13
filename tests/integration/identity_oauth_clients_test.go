// An identity's OAuth clients: GET and DELETE /identities/{id}/oauth-clients.
// A client carries no tenant, so the identity, resolved in the caller's
// tenant, is what scopes both routes. Deleting a client frees its client_id,
// which a one-client-per-identity model needs before the id can be linked to
// another identity.
package integration_test

import (
	"crypto/ecdsa"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/internal/mockidp"
)

// TestIdentityOAuthClients_MoveIdPAppToAnotherAgent is the move that a key
// client used to block: an IdP app bound to agent A, with A's key-based client,
// is bound to agent B instead, keeping the same client_id.
func TestIdentityOAuthClients_MoveIdPAppToAnotherAgent(t *testing.T) {
	f := newDBFederation(t)
	tn := newTITenant(t)
	tid, appID, aliceOID := uid("move-tid"), uid("move-app"), uid("move-oid")
	rowID := f.entraRow(t, tn, tid, nil)["id"].(string)
	f.member(f.idp.EntraIssuer(tid), aliceOID, "user_hf_alice")
	a, b := tn.agent(t), tn.agent(t)

	status, body := f.bind(t, tn, rowID, appID, a.id, true)
	require.Equal(t, http.StatusCreated, status, "%v", body)
	aBinding := body["id"].(string)

	// Removing the link keeps A's client, so B cannot have the client_id.
	status, _ = f.call(t, http.MethodDelete, "/external-issuers/"+rowID+"/bindings/"+aBinding, nil, tn.headers)
	require.Equal(t, http.StatusNoContent, status)
	status, body = f.bind(t, tn, rowID, appID, b.id, true)
	require.Equal(t, http.StatusConflict, status, "%v", body)
	require.Equal(t, "client_conflict", body["code"])

	// A's owner finds and deletes A's client.
	status, body = f.call(t, http.MethodGet, "/identities/"+a.id+"/oauth-clients", nil, tn.headers)
	require.Equal(t, http.StatusOK, status, "%v", body)
	clients := body["clients"].([]any)
	require.Len(t, clients, 1)
	require.Equal(t, appID, clients[0].(map[string]any)["client_id"])
	status, _ = f.call(t, http.MethodDelete, "/identities/"+a.id+"/oauth-clients/"+clients[0].(map[string]any)["id"].(string), nil, tn.headers)
	require.Equal(t, http.StatusOK, status)

	// Now B links the app with its own key-based client, and the exchange
	// mints for B.
	status, body = f.bind(t, tn, rowID, appID, b.id, true)
	require.Equal(t, http.StatusCreated, status, "%v", body)
	assert.Equal(t, map[string]any{"client_id": appID, "created": true}, body["oauth_client"])

	idToken, _, err := f.idp.Mint(mockidp.MintRequest{
		Profile: mockidp.ProfileEntraIDToken, Tenant: tid,
		Claims: map[string]any{"aud": appID, "oid": aliceOID, "tid": tid},
	})
	require.NoError(t, err)
	exchange := func(key *ecdsa.PrivateKey) tokenResponse {
		return postFederation(t, f.http.URL, merged(idTokenExchangeBody(idToken), clientCreds(t, appID, key),
			map[string]any{"resource": "https://gateway.example/mcp/tools", "scope": "tools:read"}))
	}

	resp := exchange(b.key)
	require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)
	assert.Equal(t, []string{b.wimse}, actChain(t, decodeIssuedTokenClaims(t, resp.AccessToken)), "the token's actor is B")

	refused := exchange(a.key)
	assert.Equal(t, http.StatusUnauthorized, refused.StatusCode, "A's key no longer authenticates the client: body=%s", refused.RawBody)
	assert.Empty(t, refused.AccessToken)
}

// linkedClient registers a client linked to identityID in the tenant headers
// name and returns its UUID.
func linkedClient(t *testing.T, clientID, identityID string, headers map[string]string) string {
	t.Helper()
	resp := post(t, adminPath("/oauth/clients"), map[string]any{
		"client_id": clientID, "name": clientID, "confidential": true,
		"grant_types": []string{"client_credentials"}, "scopes": []string{"data:read"},
		"identity_id": identityID,
	}, headers)
	body := decode(t, resp)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "%v", body)
	id, _ := body["client"].(map[string]any)["id"].(string)
	require.NotEmpty(t, id)
	return id
}

// identityClientIDs lists an identity's clients by client_id.
func identityClientIDs(t *testing.T, identityID string, headers map[string]string) (int, []string) {
	t.Helper()
	resp := get(t, adminPath("/identities/"+identityID+"/oauth-clients"), headers)
	body := decode(t, resp)
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil
	}
	var ids []string
	for _, c := range body["clients"].([]any) {
		ids = append(ids, c.(map[string]any)["client_id"].(string))
	}
	return resp.StatusCode, ids
}

func deleteIdentityClient(t *testing.T, identityID, clientUUID string, headers map[string]string) int {
	t.Helper()
	resp := doRequest(t, http.MethodDelete, adminPath("/identities/"+identityID+"/oauth-clients/"+clientUUID), nil, headers)
	_ = resp.Body.Close()
	return resp.StatusCode
}

func clientExists(t *testing.T, clientUUID string) bool {
	t.Helper()
	resp := get(t, adminPath("/oauth/clients/"+clientUUID), nil)
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func TestIdentityOAuthClients(t *testing.T) {
	t.Run("lists only the identity's own clients", func(t *testing.T) {
		a := registerIdentityIn(t, adminHeaders(), uid("ioc-a"), []string{"data:read"})
		b := registerIdentityIn(t, adminHeaders(), uid("ioc-b"), []string{"data:read"})
		aClient := uid("ioc-a-client")
		linkedClient(t, aClient, a.ID, adminHeaders())
		linkedClient(t, uid("ioc-b-client"), b.ID, adminHeaders())

		status, ids := identityClientIDs(t, a.ID, adminHeaders())
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, []string{aClient}, ids)
	})

	t.Run("an identity with no clients lists an empty array", func(t *testing.T) {
		a := registerIdentityIn(t, adminHeaders(), uid("ioc-none"), []string{"data:read"})
		resp := get(t, adminPath("/identities/"+a.ID+"/oauth-clients"), adminHeaders())
		body := decode(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, []any{}, body["clients"])
		require.Equal(t, float64(0), body["total"])
	})

	t.Run("deleting frees the client_id for another identity", func(t *testing.T) {
		a := registerIdentityIn(t, adminHeaders(), uid("ioc-move-a"), []string{"data:read"})
		b := registerIdentityIn(t, adminHeaders(), uid("ioc-move-b"), []string{"data:read"})
		clientID := uid("ioc-move-client")
		aClientUUID := linkedClient(t, clientID, a.ID, adminHeaders())

		// While a holds it, the id cannot be registered for b.
		taken := post(t, adminPath("/oauth/clients"), map[string]any{
			"client_id": clientID, "name": clientID, "confidential": true,
			"grant_types": []string{"client_credentials"}, "identity_id": b.ID,
		}, adminHeaders())
		_ = taken.Body.Close()
		require.Equal(t, http.StatusConflict, taken.StatusCode)

		require.Equal(t, http.StatusOK, deleteIdentityClient(t, a.ID, aClientUUID, adminHeaders()))
		require.False(t, clientExists(t, aClientUUID))
		_, ids := identityClientIDs(t, a.ID, adminHeaders())
		require.Empty(t, ids)

		linkedClient(t, clientID, b.ID, adminHeaders())
		_, ids = identityClientIDs(t, b.ID, adminHeaders())
		require.Equal(t, []string{clientID}, ids)
	})

	t.Run("refuses a client linked to another identity", func(t *testing.T) {
		a := registerIdentityIn(t, adminHeaders(), uid("ioc-own-a"), []string{"data:read"})
		b := registerIdentityIn(t, adminHeaders(), uid("ioc-own-b"), []string{"data:read"})
		bClientUUID := linkedClient(t, uid("ioc-own-b-client"), b.ID, adminHeaders())

		require.Equal(t, http.StatusNotFound, deleteIdentityClient(t, a.ID, bClientUUID, adminHeaders()))
		require.True(t, clientExists(t, bClientUUID), "a's route must not delete b's client")
	})

	t.Run("refuses a client linked to no identity", func(t *testing.T) {
		a := registerIdentityIn(t, adminHeaders(), uid("ioc-unlinked-a"), []string{"data:read"})
		unlinked := registerOAuthClient(t, uid("ioc-unlinked-client"), []string{"data:read"})
		resp := get(t, adminPath("/oauth/clients"), nil)
		var unlinkedUUID string
		for _, c := range decode(t, resp)["clients"].([]any) {
			if c.(map[string]any)["client_id"] == unlinked.ClientID {
				unlinkedUUID = c.(map[string]any)["id"].(string)
			}
		}
		require.NotEmpty(t, unlinkedUUID)

		require.Equal(t, http.StatusNotFound, deleteIdentityClient(t, a.ID, unlinkedUUID, adminHeaders()))
		require.True(t, clientExists(t, unlinkedUUID))
	})

	t.Run("another tenant sees neither the identity nor its clients", func(t *testing.T) {
		a := registerIdentityIn(t, adminHeaders(), uid("ioc-tenant-a"), []string{"data:read"})
		aClientUUID := linkedClient(t, uid("ioc-tenant-client"), a.ID, adminHeaders())
		other := map[string]string{"X-Account-ID": "acct-other-ioc", "X-Project-ID": testProjectID}

		status, _ := identityClientIDs(t, a.ID, other)
		require.Equal(t, http.StatusNotFound, status)
		require.Equal(t, http.StatusNotFound, deleteIdentityClient(t, a.ID, aClientUUID, other))
		require.True(t, clientExists(t, aClientUUID))
	})

	t.Run("a deactivated identity's clients can still be listed and deleted", func(t *testing.T) {
		a := registerIdentityIn(t, adminHeaders(), uid("ioc-deact"), []string{"data:read"})
		clientID := uid("ioc-deact-client")
		aClientUUID := linkedClient(t, clientID, a.ID, adminHeaders())
		deact := doRequest(t, http.MethodDelete, adminPath("/identities/"+a.ID), nil, adminHeaders())
		_ = deact.Body.Close()
		require.Equal(t, http.StatusOK, deact.StatusCode)

		_, ids := identityClientIDs(t, a.ID, adminHeaders())
		require.Equal(t, []string{clientID}, ids, "deactivation keeps the client linked")
		require.Equal(t, http.StatusOK, deleteIdentityClient(t, a.ID, aClientUUID, adminHeaders()))
		require.False(t, clientExists(t, aClientUUID))
	})

	t.Run("an approval-channel client is removed only from a trusted context", func(t *testing.T) {
		ch := registerChannel(t, "approval_channel", "")
		resp := registerClient(t, uid("ioc-chan-client"), ch.ID, channelWriteHeaders())
		body := decode(t, resp)
		require.Equal(t, http.StatusCreated, resp.StatusCode, "%v", body)
		chClientUUID, _ := body["client"].(map[string]any)["id"].(string)

		require.Equal(t, http.StatusForbidden, deleteIdentityClient(t, ch.ID, chClientUUID, adminHeaders()))
		require.True(t, clientExists(t, chClientUUID))
		require.Equal(t, http.StatusOK, deleteIdentityClient(t, ch.ID, chClientUUID, channelWriteHeaders()))
		require.False(t, clientExists(t, chClientUUID))
	})
}
