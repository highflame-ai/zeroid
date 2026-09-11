package integration_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// End-to-end proof that a client registered for an unenforceable authentication
// method cannot authenticate at all (zeroid#206 scope item 2).
//
// The bug this closes is a SILENT DOWNGRADE, not a missing feature. Registration
// accepts `token_endpoint_auth_method: private_key_jwt` and stores the client's
// key material, but derives client_type from the separate `confidential` flag.
// So the row lands client_type=public with an empty secret hash — precisely the
// shape verifyConfidentialClientAuth's public-client pass-through allows. Before
// this fix, such a client authenticated with NOTHING on authorization_code,
// refresh_token, CIBA redemption, introspection and revocation.
//
// The asymmetry is the reason it is worth failing loudly rather than waiting for
// the RFC 7523 §2.2 implementation: a deployer who chose private_key_jwt
// specifically to avoid shared secrets got WEAKER authentication than one who
// chose a secret, with no error anywhere to say so.
func TestClientAuthDowngrade_UnimplementedMethodCannotAuthenticate(t *testing.T) {
	clientID := uid("pkjwt-downgrade")

	// Register exactly the shape that produces the downgrade: confidential
	// false (so no secret is minted) with an explicit key-based auth method.
	reg := post(t, adminPath("/oauth/clients"), map[string]any{
		"client_id":                  clientID,
		"name":                       clientID + "-client",
		"confidential":               false,
		"token_endpoint_auth_method": "private_key_jwt",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"redirect_uris":              []string{testRedirectURI},
		"scopes":                     []string{"data:read"},
	}, nil)
	require.Equal(t, http.StatusCreated, reg.StatusCode,
		"registration still accepts private_key_jwt — this test asserts what happens at AUTH time, "+
			"not that registration rejects it (that is scope item 3)")
	body := decode(t, reg)
	_ = reg.Body.Close()

	// Pin the downgraded shape itself, so this test keeps meaning something if
	// registration behaviour changes: no secret was issued, and the client is
	// public despite having been registered for key-based authentication.
	assert.Empty(t, body["client_secret"],
		"no secret is minted for a key-based client — which is exactly why the "+
			"public-client pass-through used to accept it")

	t.Run("authorization_code exchange with no client authentication is refused", func(t *testing.T) {
		verifier, challenge := buildPKCEPair(t)
		code := buildAuthCode(t, clientID, uid("pkjwt-user"), testRedirectURI, challenge,
			[]string{"data:read"})

		resp := post(t, "/oauth2/token", map[string]any{
			"grant_type":    "authorization_code",
			"client_id":     clientID,
			"code":          code,
			"code_verifier": verifier,
			"redirect_uri":  testRedirectURI,
			// Deliberately NO client_secret and NO client_assertion. Before the
			// fix this returned 200 with a token.
		}, nil)
		defer func() { _ = resp.Body.Close() }()

		require.Equal(t, http.StatusUnauthorized, resp.StatusCode,
			"a client registered for private_key_jwt must not be able to redeem a code "+
				"with no client authentication whatsoever")
		got := decode(t, resp)
		assert.Equal(t, "invalid_client", got["error"],
			"RFC 6749 §5.2 assigns invalid_client to failed or absent client authentication — "+
				"the client is well-formed and known, it simply cannot authenticate as registered")
		assert.Contains(t, got["error_description"], "private_key_jwt",
			"the refusal should name the method so an integrator can act on it")
	})

	t.Run("introspection with client_id alone is refused", func(t *testing.T) {
		// The same downgrade reached token INSPECTION: the no-secret branch
		// resolves the client as public and returned nil. Introspection has no
		// redirect_uri binding to fall back on, so this half mattered
		// independently of token issuance.
		resp := post(t, "/oauth2/token/introspect", map[string]any{
			"token":     "zid_at_whatever",
			"client_id": clientID,
		}, nil)
		defer func() { _ = resp.Body.Close() }()

		require.Equal(t, http.StatusUnauthorized, resp.StatusCode,
			"a key-based client must not satisfy introspection auth by presenting only its client_id")
		assert.Equal(t, "invalid_client", decode(t, resp)["error"])
	})
}

// TestClientAuthDowngrade_ImplementedMethodsAreUnaffected is the control.
//
// Without it, the assertions above would pass against a change that simply broke
// client authentication for everyone. It also pins the compatibility claim made
// when this landed: every client in dev1 and prod at the time was registered
// `token_endpoint_auth_method=none`, so the hardening had no blast radius.
func TestClientAuthDowngrade_ImplementedMethodsAreUnaffected(t *testing.T) {
	t.Run("a public client (none) still exchanges a code", func(t *testing.T) {
		verifier, challenge := buildPKCEPair(t)
		code := buildAuthCode(t, testMCPClientID, uid("pkjwt-control"), testRedirectURI,
			challenge, []string{"data:read"})

		resp := post(t, "/oauth2/token", map[string]any{
			"grant_type":    "authorization_code",
			"client_id":     testMCPClientID,
			"code":          code,
			"code_verifier": verifier,
			"redirect_uri":  testRedirectURI,
		}, nil)
		defer func() { _ = resp.Body.Close() }()

		require.Equal(t, http.StatusOK, resp.StatusCode,
			"an ordinary public PKCE client must be entirely unaffected")
		assert.NotEmpty(t, decode(t, resp)["access_token"])
	})

	t.Run("a confidential client with its secret still gets a token", func(t *testing.T) {
		ext := uid("pkjwt-conf")
		registerAgent(t, ext)
		client := registerOAuthClient(t, ext, []string{"data:read"})

		resp := post(t, "/oauth2/token", map[string]any{
			"grant_type":    "client_credentials",
			"account_id":    testAccountID,
			"project_id":    testProjectID,
			"client_id":     client.ClientID,
			"client_secret": client.ClientSecret,
		}, nil)
		defer func() { _ = resp.Body.Close() }()

		require.Equal(t, http.StatusOK, resp.StatusCode,
			"client_secret_basic is implemented and must keep working")
		assert.NotEmpty(t, decode(t, resp)["access_token"])
	})
}
