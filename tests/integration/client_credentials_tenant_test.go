// client_credentials without account_id / project_id.
//
// RFC 6749 §4.4.2 defines the request as grant_type and scope, plus client
// authentication. No conformant client sends a Highflame tenant, and the MCP
// interop event's machine-to-machine flow (WSO2's MCP playground among them)
// sends exactly that request. The tenant is derived from the identity the
// client's REGISTRATION links to (identity_id). For a linked client, a request
// that names a tenant must name the link's, and the token is still for the
// linked identity. An unlinked client keeps the original external_id rule.
package integration_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// registerLinkedCCClient creates an identity and a client_credentials client
// whose registration links to it, both in the tenant headers name, and
// returns the client's id and secret.
func registerLinkedCCClient(t *testing.T, headers map[string]string, link bool) (clientID, secret string) {
	t.Helper()
	clientID, secret, _ = registerLinkedCCClientWithIdentity(t, headers, link)
	return clientID, secret
}

// registerLinkedCCClientWithIdentity is registerLinkedCCClient that also
// returns the external_id of the identity the client links (or would link).
func registerLinkedCCClientWithIdentity(t *testing.T, headers map[string]string, link bool) (clientID, secret, linkedExternalID string) {
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
	return clientID, raw["client_secret"].(string), identity.ExternalID
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

// A linked client's registration decides its identity and tenant even when the
// request names one. Naming the link's tenant is redundant and accepted;
// naming another is refused, never quietly answered by that tenant's
// external_id match (which would let the caller choose between identities).
func TestClientCredentials_LinkedClientNamingATenant(t *testing.T) {
	requireSubIs := func(t *testing.T, accessToken, externalID string) {
		t.Helper()
		sub, _ := decodeIssuedTokenClaims(t, accessToken)["sub"].(string)
		require.True(t, strings.HasSuffix(sub, "/"+externalID),
			"token must be for identity %q, got sub %q", externalID, sub)
	}

	t.Run("naming the link's tenant mints for the linked identity", func(t *testing.T) {
		acct, proj := uid("acct-ccm"), uid("proj-ccm")
		headers := tenantHeaders(acct, proj)
		clientID, secret, linkedExt := registerLinkedCCClientWithIdentity(t, headers, true)
		// A second identity in the same tenant answers the old external_id
		// rule. The link must win over it.
		registerIdentityIn(t, headers, clientID, []string{"data:read"})

		status, body := ccToken(t, map[string]any{
			"grant_type": "client_credentials", "client_id": clientID, "client_secret": secret,
			"account_id": acct, "project_id": proj,
		})
		require.Equal(t, http.StatusOK, status, "%v", body)
		requireSubIs(t, body["access_token"].(string), linkedExt)
		require.Equal(t, acct, body["account_id"])
		require.Equal(t, proj, body["project_id"])
	})

	t.Run("naming another tenant is invalid_request and mints nothing", func(t *testing.T) {
		acct, proj := uid("acct-ccx"), uid("proj-ccx")
		clientID, secret := registerLinkedCCClient(t, tenantHeaders(acct, proj), true)
		// The other tenant holds an identity whose external_id is this
		// client's id: under the old rule it would have been minted for.
		otherAcct, otherProj := uid("acct-ccy"), uid("proj-ccy")
		registerIdentityIn(t, tenantHeaders(otherAcct, otherProj), clientID, []string{"data:read"})

		for name, tenant := range map[string][2]string{
			"other account and project":    {otherAcct, otherProj},
			"right account, other project": {acct, otherProj},
			"other account, right project": {otherAcct, proj},
		} {
			t.Run(name, func(t *testing.T) {
				status, body := ccToken(t, map[string]any{
					"grant_type": "client_credentials", "client_id": clientID, "client_secret": secret,
					"account_id": tenant[0], "project_id": tenant[1],
				})
				require.Equal(t, http.StatusBadRequest, status, "%v", body)
				require.Equal(t, "invalid_request", body["error"])
				require.Contains(t, body["error_description"], "does not match")
				require.NotContains(t, body, "access_token")
				// The derived tenant is not echoed.
				require.NotContains(t, body["error_description"], acct)
				require.NotContains(t, body["error_description"], proj)
			})
		}
	})

	t.Run("an unlinked client naming a tenant keeps the external_id rule", func(t *testing.T) {
		acct, proj := uid("acct-ccu"), uid("proj-ccu")
		headers := tenantHeaders(acct, proj)
		clientID, secret := registerLinkedCCClient(t, headers, false)
		registerIdentityIn(t, headers, clientID, []string{"data:read"})

		status, body := ccToken(t, map[string]any{
			"grant_type": "client_credentials", "client_id": clientID, "client_secret": secret,
			"account_id": acct, "project_id": proj,
		})
		require.Equal(t, http.StatusOK, status, "%v", body)
		requireSubIs(t, body["access_token"].(string), clientID)
		require.Equal(t, acct, body["account_id"])
		require.Equal(t, proj, body["project_id"])
	})
}
