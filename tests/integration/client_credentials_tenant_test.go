// client_credentials without account_id / project_id.
//
// RFC 6749 §4.4.2 defines the request as grant_type and scope, plus client
// authentication. No conformant client sends a Highflame tenant, and the MCP
// interop event's machine-to-machine flow (WSO2's MCP playground among them)
// sends exactly that request. The tenant is derived from the identity the
// client's REGISTRATION links to (identity_id). A request that names a tenant
// keeps the original external_id rule, which other tests cover.
package integration_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// registerLinkedCCClient creates an identity and a client_credentials client
// whose registration links to it, both in the tenant headers name, and
// returns the client's id and secret.
func registerLinkedCCClient(t *testing.T, headers map[string]string, link bool) (clientID, secret string) {
	t.Helper()
	identity := registerIdentityIn(t, headers, uid("cc-derive-identity"), []string{"data:read"})
	clientID = uid("cc-derive-client")
	body := map[string]any{
		"client_id": clientID, "name": clientID, "confidential": true,
		"grant_types": []string{"client_credentials"}, "scopes": []string{"data:read"},
	}
	if link {
		body["identity_id"] = identity.ID
	}
	resp := post(t, adminPath("/oauth/clients"), body, headers)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	raw := decode(t, resp)
	return clientID, raw["client_secret"].(string)
}

func ccToken(t *testing.T, body map[string]any) (int, map[string]any) {
	t.Helper()
	resp := post(t, "/oauth2/token", body, nil)
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	return resp.StatusCode, out
}

func TestClientCredentials_TenantDerivedFromLinkedIdentity(t *testing.T) {
	t.Run("a request naming no tenant mints into the linked identity's tenant", func(t *testing.T) {
		clientID, secret := registerLinkedCCClient(t, adminHeaders(), true)

		status, body := ccToken(t, map[string]any{
			"grant_type": "client_credentials", "client_id": clientID, "client_secret": secret, "scope": "data:read",
		})
		require.Equal(t, http.StatusOK, status, "%v", body)
		claims := decodeIssuedTokenClaims(t, body["access_token"].(string))
		require.Equal(t, testAccountID, claims["account_id"])
		require.Equal(t, testProjectID, claims["project_id"])
		require.Equal(t, clientID, claims["client_id"])
	})

	t.Run("the derived tenant is the link's, not the default one", func(t *testing.T) {
		acct, proj := uid("acct-cc"), uid("proj-cc")
		clientID, secret := registerLinkedCCClient(t, tenantHeaders(acct, proj), true)

		status, body := ccToken(t, map[string]any{
			"grant_type": "client_credentials", "client_id": clientID, "client_secret": secret,
		})
		require.Equal(t, http.StatusOK, status, "%v", body)
		claims := decodeIssuedTokenClaims(t, body["access_token"].(string))
		require.Equal(t, acct, claims["account_id"])
		require.Equal(t, proj, claims["project_id"])

		// The request named no tenant, so the response is the only place an
		// embedder attributing issuance (AuthN's metering) can learn it.
		require.Equal(t, acct, body["account_id"], "response must name the derived tenant")
		require.Equal(t, proj, body["project_id"], "response must name the derived tenant")
	})

	t.Run("a client linking no identity is told how to fix it", func(t *testing.T) {
		clientID, secret := registerLinkedCCClient(t, adminHeaders(), false)

		status, body := ccToken(t, map[string]any{
			"grant_type": "client_credentials", "client_id": clientID, "client_secret": secret,
		})
		require.Equal(t, http.StatusBadRequest, status, "%v", body)
		require.Equal(t, "invalid_request", body["error"])
		require.Contains(t, body["error_description"], "links no identity")
		require.NotContains(t, body, "access_token")
	})

	t.Run("half a tenant is malformed", func(t *testing.T) {
		clientID, secret := registerLinkedCCClient(t, adminHeaders(), true)

		status, body := ccToken(t, map[string]any{
			"grant_type": "client_credentials", "client_id": clientID, "client_secret": secret,
			"account_id": testAccountID,
		})
		require.Equal(t, http.StatusBadRequest, status, "%v", body)
		require.Equal(t, "invalid_request", body["error"])
	})

	// Derivation must not run, or leak anything, for a caller that has not
	// authenticated: the tenant is the client's, so only the client learns it.
	t.Run("a wrong secret is invalid_client before any tenant is derived", func(t *testing.T) {
		clientID, _ := registerLinkedCCClient(t, adminHeaders(), true)

		status, body := ccToken(t, map[string]any{
			"grant_type": "client_credentials", "client_id": clientID, "client_secret": "wrong",
		})
		require.Equal(t, http.StatusUnauthorized, status, "%v", body)
		require.Equal(t, "invalid_client", body["error"])
	})
}
