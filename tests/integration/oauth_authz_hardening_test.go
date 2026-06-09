package integration_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file proves the OAuth grant/endpoint authorization-hardening fixes:
//
//  1. Confidential clients must authenticate (client_secret) on the
//     refresh_token grant (RFC 6749 §6/§10.4). Public clients are unaffected.
//  2. A client_credentials client registered with zero scopes cannot widen its
//     authority by requesting arbitrary scopes (RFC 6749 §3.3).
//  3. A refresh with a wrong client_id does NOT brick the session — the
//     original refresh token remains usable (pre-rotation validation, §10.4).
//  4. Introspection (RFC 7662) / revocation (RFC 7009) verify presented client
//     credentials (reject a wrong secret) while leaving the existing tenant-
//     header internal path working.
//
// Each test is named with the shared prefix TestOAuthAuthzHardening_ so the
// suite can be run in isolation:
//
//	go test ./tests/integration/ -run 'TestOAuthAuthzHardening' -count=1

// registerConfidentialClient registers a confidential OAuth client with the
// given grant types + scopes via the admin endpoint and returns its
// credentials. Mirrors registerOAuthClient but lets the caller choose grants
// and supply a redirect URI (needed for the authorization_code path).
func registerConfidentialClient(t *testing.T, clientID string, grantTypes, scopes, redirectURIs []string) oauthClientResp {
	t.Helper()
	resp := post(t, adminPath("/oauth/clients"), map[string]any{
		"client_id":     clientID,
		"name":          clientID + "-client",
		"confidential":  true,
		"grant_types":   grantTypes,
		"scopes":        scopes,
		"redirect_uris": redirectURIs,
	}, nil)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "registerConfidentialClient: expected 201")
	raw := decode(t, resp)
	client := raw["client"].(map[string]any)
	return oauthClientResp{
		ClientID:     client["client_id"].(string),
		ClientSecret: raw["client_secret"].(string),
	}
}

// mintConfidentialRefreshToken runs a confidential authorization_code exchange
// (PKCE + client_secret) and returns the issued refresh token. The client must
// be registered with both authorization_code and refresh_token grants.
func mintConfidentialRefreshToken(t *testing.T, client oauthClientResp, userID string) string {
	t.Helper()
	verifier, challenge := buildPKCEPair(t)
	code := buildAuthCode(t, client.ClientID, userID, testRedirectURI, challenge, []string{"data:read"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "authorization_code",
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
		"code":          code,
		"code_verifier": verifier,
		"redirect_uri":  testRedirectURI,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "confidential authorization_code exchange should succeed")
	tok := decode(t, resp)
	rt, ok := tok["refresh_token"].(string)
	require.True(t, ok, "confidential client with refresh_token grant must receive a refresh token")
	require.NotEmpty(t, rt)
	return rt
}

// TestOAuthAuthzHardening_ConfidentialRefreshRequiresSecret proves finding #1:
// a confidential client must present its client_secret on the refresh_token
// grant. A missing or wrong secret → invalid_client; the correct secret works.
// (Fails if the VerifyConfidentialClientAuth call in refreshToken is reverted.)
func TestOAuthAuthzHardening_ConfidentialRefreshRequiresSecret(t *testing.T) {
	clientID := uid("conf-refresh")
	client := registerConfidentialClient(t,
		clientID,
		[]string{"authorization_code", "refresh_token"},
		[]string{"data:read"},
		[]string{testRedirectURI},
	)

	// Missing secret → invalid_client.
	rt := mintConfidentialRefreshToken(t, client, "user-conf-1")
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": rt,
		"client_id":     client.ClientID,
		// no client_secret
	}, nil)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "confidential refresh without secret must be rejected")
	body := decode(t, resp)
	assert.Equal(t, "invalid_client", body["error"])

	// The failed (no-secret) attempt must NOT have consumed the token —
	// presenting it again WITH the correct secret must still succeed.
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": rt,
		"client_id":     client.ClientID,
		"client_secret": "definitely-the-wrong-secret",
	}, nil)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "confidential refresh with wrong secret must be rejected")
	body = decode(t, resp)
	assert.Equal(t, "invalid_client", body["error"])

	// Correct secret rotates successfully — proves the earlier failures left
	// the token untouched (also covers the session-bricking fix).
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": rt,
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "confidential refresh with correct secret must succeed")
	refreshed := decode(t, resp)
	assert.NotEmpty(t, refreshed["access_token"])
	assert.NotEmpty(t, refreshed["refresh_token"])
}

// TestOAuthAuthzHardening_PublicRefreshStillWorks proves the confidential-auth
// gate does not regress public clients: the existing public MCP client (no
// secret) still rotates refresh tokens normally.
func TestOAuthAuthzHardening_PublicRefreshStillWorks(t *testing.T) {
	verifier, challenge := buildPKCEPair(t)
	code := buildAuthCode(t, testMCPClientID, "user-pub-rt", testRedirectURI, challenge, []string{"data:read"})
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "authorization_code",
		"client_id":     testMCPClientID,
		"code":          code,
		"code_verifier": verifier,
		"redirect_uri":  testRedirectURI,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	rt := decode(t, resp)["refresh_token"].(string)

	// Public client refreshes with NO client_secret — must still work.
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": rt,
		"client_id":     testMCPClientID,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "public client refresh must still work without a secret")
	assert.NotEmpty(t, decode(t, resp)["access_token"])
}

// TestOAuthAuthzHardening_ScopelessClientCannotWiden proves finding #3: a
// client_credentials client registered with an empty scope set cannot mint
// arbitrary scopes by requesting them. Expect invalid_scope.
// (Fails if intersectScopes' empty-allow-list passthrough is reached from
// clientCredentials, i.e. if the deny guard is reverted.)
func TestOAuthAuthzHardening_ScopelessClientCannotWiden(t *testing.T) {
	agentID := uid("scopeless")
	registerIdentity(t, agentID, []string{}) // identity with no scopes
	client := registerOAuthClient(t, agentID, []string{})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
		"scope":         "admin:everything billing:write",
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "scope-less client must not be granted requested scopes")
	body := decode(t, resp)
	assert.Equal(t, "invalid_scope", body["error"])
}

// TestOAuthAuthzHardening_WrongClientIDDoesNotBrickSession proves finding #4:
// a refresh presented with a WRONG client_id is rejected WITHOUT consuming the
// token — the original refresh token (and thus the family) stays usable.
// (Fails if the client_id binding check / client resolution runs AFTER
// RotateRefreshToken.) The wrong client_id here is unknown, so per RFC 6749
// §5.2 it's rejected as invalid_client at client resolution (fail-closed:
// an unresolvable named client must not skip confidential-client auth) before
// the token is ever touched.
func TestOAuthAuthzHardening_WrongClientIDDoesNotBrickSession(t *testing.T) {
	// Use the existing public MCP client to mint a refresh token.
	verifier, challenge := buildPKCEPair(t)
	code := buildAuthCode(t, testMCPClientID, "user-brick", testRedirectURI, challenge, []string{"data:read"})
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "authorization_code",
		"client_id":     testMCPClientID,
		"code":          code,
		"code_verifier": verifier,
		"redirect_uri":  testRedirectURI,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	rt := decode(t, resp)["refresh_token"].(string)

	// Refresh with a WRONG (unknown) client_id → rejected, token NOT consumed.
	// An unknown client is invalid_client per RFC 6749 §5.2; the security
	// property under test is that the token survives the rejection.
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": rt,
		"client_id":     "some-other-client",
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_client", decode(t, resp)["error"])

	// The original token must STILL be usable with the correct client_id —
	// the wrong-client_id attempt must not have bricked the session.
	resp = post(t, "/oauth2/token", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": rt,
		"client_id":     testMCPClientID,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"original refresh token must still be usable after a wrong-client_id attempt (session not bricked)")
	refreshed := decode(t, resp)
	assert.NotEmpty(t, refreshed["access_token"])
	assert.NotEmpty(t, refreshed["refresh_token"])
}

// TestOAuthAuthzHardening_IntrospectionClientAuth proves finding #5 for
// introspection (RFC 7662): a credentialed call with a WRONG secret is rejected
// with invalid_client, a credentialed call with the CORRECT secret works, and
// the existing tenant-header (no-credential) path is unchanged.
func TestOAuthAuthzHardening_IntrospectionClientAuth(t *testing.T) {
	// Mint a token to introspect (client_credentials, scoped client).
	agentID := uid("introspect-auth")
	registerIdentity(t, agentID, []string{"data:read"})
	client := registerOAuthClient(t, agentID, []string{"data:read"})
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	accessToken := decode(t, resp)["access_token"].(string)

	// Credentialed introspection with a WRONG secret → invalid_client.
	resp = post(t, "/oauth2/token/introspect", map[string]any{
		"token":         accessToken,
		"client_id":     client.ClientID,
		"client_secret": "wrong-secret",
	}, adminHeaders())
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "wrong-secret introspection must be rejected")
	assert.Equal(t, "invalid_client", decode(t, resp)["error"])

	// Credentialed introspection with the CORRECT secret → active token.
	resp = post(t, "/oauth2/token/introspect", map[string]any{
		"token":         accessToken,
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
	}, adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.True(t, decode(t, resp)["active"].(bool), "correct-secret introspection must report the token active")

	// Existing tenant-header path (NO client credentials) → unchanged.
	result := introspect(t, accessToken)
	assert.True(t, result["active"].(bool), "no-credential introspection (internal path) must still work")
}

// TestOAuthAuthzHardening_RevocationClientAuth proves finding #5 for revocation
// (RFC 7009): a credentialed call with a WRONG secret is rejected with
// invalid_client (the token is NOT revoked), while the existing no-credential
// internal path still revokes (and preserves the RFC 7009 §2.2 200 contract).
func TestOAuthAuthzHardening_RevocationClientAuth(t *testing.T) {
	agentID := uid("revoke-auth")
	registerIdentity(t, agentID, []string{"data:read"})
	client := registerOAuthClient(t, agentID, []string{"data:read"})

	mint := func() string {
		resp := post(t, "/oauth2/token", map[string]any{
			"grant_type":    "client_credentials",
			"account_id":    testAccountID,
			"project_id":    testProjectID,
			"client_id":     client.ClientID,
			"client_secret": client.ClientSecret,
			"scope":         "data:read",
		}, nil)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		return decode(t, resp)["access_token"].(string)
	}

	// Wrong-secret revocation → invalid_client, token NOT revoked.
	tokenA := mint()
	resp := post(t, "/oauth2/token/revoke", map[string]any{
		"token":         tokenA,
		"client_id":     client.ClientID,
		"client_secret": "wrong-secret",
	}, adminHeaders())
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "wrong-secret revocation must be rejected")
	assert.Equal(t, "invalid_client", decode(t, resp)["error"])
	// Token must still be active — the rejected call must not have revoked it.
	assert.True(t, introspect(t, tokenA)["active"].(bool), "wrong-secret revocation must not revoke the token")

	// Existing no-credential internal path → revokes, returns 200.
	revokeResp := post(t, "/oauth2/token/revoke", map[string]string{"token": tokenA}, adminHeaders())
	require.Equal(t, http.StatusOK, revokeResp.StatusCode, "no-credential revocation (internal path) must still return 200")
	_ = revokeResp.Body.Close()
	assert.False(t, introspect(t, tokenA)["active"].(bool), "no-credential revocation must revoke the token")
}
