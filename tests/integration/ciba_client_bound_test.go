package integration_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	zeroid "github.com/highflame-ai/zeroid"
)

// cibaRequestCount returns how many bc-authorize rows exist for clientID, so a
// refusal can be shown to have persisted nothing (and so fired no prompt).
func cibaRequestCount(t *testing.T, clientID string) int {
	t.Helper()
	n, err := testDB.NewSelect().Table("backchannel_auth_requests").Where("client_id = ?", clientID).Count(context.Background())
	require.NoError(t, err)
	return n
}

// TestCIBAPublicClientInitiator: a public client's bc-authorize request is
// accepted only from a caller the deployer's TrustedServiceValidator accepts.
func TestCIBAPublicClientInitiator(t *testing.T) {
	root := func(clientID string) map[string]any {
		return map[string]any{
			"client_id": clientID, "account_id": testAccountID, "project_id": testProjectID,
			"login_hint": "user-a", "scope": "openid",
			"binding_message": "approve the request",
		}
	}

	t.Run("UnauthenticatedRootGrant_Refused", func(t *testing.T) {
		clientID := uid("ciba-pub-untrusted")
		registerCIBATestClient(clientID, "openid")
		resp := post(t, "/oauth2/bc-authorize", root(clientID), nil)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		require.Equal(t, "invalid_client", decode(t, resp)["error"])
		require.Zero(t, cibaRequestCount(t, clientID), "a refused request must persist nothing and fire no prompt")
	})

	t.Run("UnauthenticatedRefusedBeforeScope", func(t *testing.T) {
		// An over-scoped request from an untrusted caller gets the same
		// invalid_client as any other: nothing about the client's registration
		// is revealed before the caller is authenticated.
		clientID := uid("ciba-pub-untrusted-scope")
		registerCIBATestClient(clientID, "openid")
		body := root(clientID)
		body["scope"] = "openid tools:admin"
		resp := post(t, "/oauth2/bc-authorize", body, nil)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		require.Equal(t, "invalid_client", decode(t, resp)["error"])
	})

	t.Run("TrustedCaller_Accepted", func(t *testing.T) {
		clientID := uid("ciba-pub-trusted")
		registerCIBATestClient(clientID, "openid")
		resp := post(t, "/oauth2/bc-authorize", root(clientID), cibaInitiatorHeaders())
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.NotEmpty(t, decode(t, resp)["auth_req_id"])
	})

	t.Run("ConfidentialClient_Unaffected", func(t *testing.T) {
		// A confidential client authenticates with its secret and needs no
		// trusted-service caller; an empty registration still means no
		// client-level ceiling for it.
		c := newConfidentialCIBAClient(t)
		resp := bcAuthorizeAs(t, c, map[string]any{"login_hint": "user-a", "scope": "openid tools:read"})
		require.Equal(t, http.StatusOK, resp.StatusCode, "body=%v", decode(t, resp))
	})
}

// TestCIBAScopeBoundByClient: the scope of a CIBA request must be within the
// client's registered scopes, at bc-authorize and again at issuance, and
// redemption cannot add to it.
func TestCIBAScopeBoundByClient(t *testing.T) {
	bcAuthorize := func(t *testing.T, clientID, scope string) *http.Response {
		t.Helper()
		return post(t, "/oauth2/bc-authorize", map[string]any{
			"client_id": clientID, "account_id": testAccountID, "project_id": testProjectID,
			"login_hint": "user-a", "scope": scope,
		}, cibaInitiatorHeaders())
	}

	t.Run("OverScoped_InvalidScope", func(t *testing.T) {
		clientID := uid("ciba-scope-over")
		registerCIBATestClient(clientID, "openid", "tools:read")
		resp := bcAuthorize(t, clientID, "openid tools:read tools:write")
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		body := decode(t, resp)
		require.Equal(t, "invalid_scope", body["error"])
		require.Contains(t, body["error_description"], "tools:write")
		require.Zero(t, cibaRequestCount(t, clientID))
	})

	t.Run("RegisteredSubset_Accepted", func(t *testing.T) {
		clientID := uid("ciba-scope-ok")
		registerCIBATestClient(clientID, "tools:read", "tools:write")
		resp := bcAuthorize(t, clientID, "openid tools:read")
		require.Equal(t, http.StatusOK, resp.StatusCode, "openid is always permitted; tools:read is registered")
	})

	t.Run("PublicWithoutRegisteredScopes_OpenIDOnly", func(t *testing.T) {
		clientID := uid("ciba-scope-none")
		registerCIBATestClient(clientID)
		resp := bcAuthorize(t, clientID, "openid")
		require.Equal(t, http.StatusOK, resp.StatusCode)
		resp = bcAuthorize(t, clientID, "openid tools:read")
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		require.Equal(t, "invalid_scope", decode(t, resp)["error"])
	})

	t.Run("ConfidentialWithRegisteredScopes_Bounded", func(t *testing.T) {
		c := newConfidentialCIBAClient(t)
		require.NoError(t, testZeroIDServer.EnsureClient(context.Background(), zeroid.OAuthClientConfig{
			ClientID: c.ID, Name: c.ID, GrantTypes: []string{zeroidGrantTypeCIBA}, Scopes: []string{"tools:read"},
		}))
		resp := bcAuthorizeAs(t, c, map[string]any{"login_hint": "user-a", "scope": "tools:admin"})
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		require.Equal(t, "invalid_scope", decode(t, resp)["error"])
	})

	t.Run("RedeemCannotWiden", func(t *testing.T) {
		clientID := uid("ciba-scope-redeem")
		registerCIBATestClient(clientID, "openid", "tools:read", "tools:admin")
		resp := bcAuthorize(t, clientID, "openid tools:read")
		require.Equal(t, http.StatusOK, resp.StatusCode)
		id := decode(t, resp)["auth_req_id"].(string)
		approveInTenant(t, id, "user-a", adminHeaders())

		// A scope parameter on the poll is not part of the CIBA grant and
		// changes nothing: the token carries what the human approved.
		tok := post(t, "/oauth2/token", map[string]any{
			"grant_type": zeroidGrantTypeCIBA, "auth_req_id": id, "client_id": clientID,
			"scope": "openid tools:read tools:admin",
		}, nil)
		require.Equal(t, http.StatusOK, tok.StatusCode)
		claims := decodeJWTPayload(t, decode(t, tok)["access_token"].(string))
		require.ElementsMatch(t, []any{"openid", "tools:read"}, claims["scopes"])
	})

	t.Run("RegistrationNarrowedWhilePending_RefusedBeforeBurn", func(t *testing.T) {
		clientID := uid("ciba-scope-narrowed")
		registerCIBATestClient(clientID, "openid", "tools:read", "tools:write")
		resp := bcAuthorize(t, clientID, "openid tools:write")
		require.Equal(t, http.StatusOK, resp.StatusCode)
		id := decode(t, resp)["auth_req_id"].(string)
		approveInTenant(t, id, "user-a", adminHeaders())

		registerCIBATestClient(clientID, "openid", "tools:read")
		status, body := pollCIBARaw(t, cibaClient{ID: clientID}, id)
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "invalid_scope", body["error"])

		// The refusal came before the single-use claim: restoring the
		// registration makes the same approval redeemable.
		registerCIBATestClient(clientID, "openid", "tools:read", "tools:write")
		status, body = pollCIBARaw(t, cibaClient{ID: clientID}, id)
		require.Equal(t, http.StatusOK, status, "body=%v", body)
	})
}
