package integration_test

import (
	"crypto/ecdsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// clientJWKS renders key's PUBLIC half as a one-key JWK Set — what a client
// publishes in its `jwks` member at registration.
func clientJWKS(t *testing.T, key *ecdsa.PrivateKey) map[string]any {
	t.Helper()
	pub, err := jwk.Import[jwk.Key](&key.PublicKey)
	require.NoError(t, err)
	require.NoError(t, pub.Set(jwk.KeyIDKey, "itest-key"))
	set := jwk.NewSet()
	require.NoError(t, set.AddKey(pub))
	raw, err := json.Marshal(set)
	require.NoError(t, err)
	var out map[string]any
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

// clientAssertionFor builds an RFC 7523 §2.2 client-authentication JWT.
// Deliberately emits NO `kid` header: kid is OPTIONAL per RFC 7515 §4.1.4 and
// real clients with a single published key routinely omit it, so this pins the
// kid-less path that jwx rejects by default.
func clientAssertionFor(t *testing.T, key *ecdsa.PrivateKey, clientID string) string {
	t.Helper()
	now := time.Now()
	tok, err := jwt.NewBuilder().
		Issuer(clientID).
		Subject(clientID).
		Audience([]string{testIssuer}).
		IssuedAt(now).
		Expiration(now.Add(2 * time.Minute)).
		JwtID(uid("cla")).
		Build()
	require.NoError(t, err)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), key))
	require.NoError(t, err)
	return string(signed)
}

// End-to-end coverage of RFC 7523 §2.2 private_key_jwt client authentication
// (zeroid#206).
//
// The bug this closes began as a SILENT DOWNGRADE. Registration accepted
// `token_endpoint_auth_method: private_key_jwt` and stored the client's key
// material, but derived client_type from the separate `confidential` flag — so
// the row landed client_type=public with an empty secret hash, precisely the
// shape verifyConfidentialClientAuth's public-client pass-through allows. Such a
// client authenticated with NOTHING on authorization_code, refresh_token, CIBA
// redemption, introspection and revocation.
//
// #346 closed that by refusing the method outright. This asserts the finished
// state: the method WORKS with a valid assertion, and still refuses every
// weaker credential.
func TestPrivateKeyJWT_ClientAuthentication(t *testing.T) {
	clientID := uid("pkjwt")
	key := generateKey(t)

	reg := post(t, adminPath("/oauth/clients"), map[string]any{
		"client_id":                  clientID,
		"name":                       clientID + "-client",
		"confidential":               false,
		"token_endpoint_auth_method": "private_key_jwt",
		"jwks":                       clientJWKS(t, key),
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"redirect_uris":              []string{testRedirectURI},
		"scopes":                     []string{"data:read"},
	}, nil)
	require.Equal(t, http.StatusCreated, reg.StatusCode, "private_key_jwt registration with jwks must succeed")
	body := decode(t, reg)
	_ = reg.Body.Close()

	// No secret is minted for a key-based client — which is exactly why the
	// public-client pass-through used to accept it with nothing at all.
	assert.Empty(t, body["client_secret"])

	t.Run("a valid client_assertion authenticates", func(t *testing.T) {
		verifier, challenge := buildPKCEPair(t)
		code := buildAuthCode(t, clientID, uid("pkjwt-user"), testRedirectURI, challenge, []string{"data:read"})

		resp := post(t, "/oauth2/token", map[string]any{
			"grant_type":            "authorization_code",
			"client_id":             clientID,
			"code":                  code,
			"code_verifier":         verifier,
			"redirect_uri":          testRedirectURI,
			"client_assertion":      clientAssertionFor(t, key, clientID),
			"client_assertion_type": clientAssertionType,
		}, nil)
		defer func() { _ = resp.Body.Close() }()

		require.Equal(t, http.StatusOK, resp.StatusCode, "a correctly signed assertion must authenticate the client")
		assert.NotEmpty(t, decode(t, resp)["access_token"])
	})

	// A conformant client may omit client_id entirely: RFC 7523 §3 already
	// carries the identifier in the assertion's iss. Insisting on client_id
	// rejects those clients as "unknown client".
	t.Run("client_id may be omitted — iss identifies the client", func(t *testing.T) {
		verifier, challenge := buildPKCEPair(t)
		code := buildAuthCode(t, clientID, uid("pkjwt-noid"), testRedirectURI, challenge, []string{"data:read"})

		resp := post(t, "/oauth2/token", map[string]any{
			"grant_type":            "authorization_code",
			"code":                  code,
			"code_verifier":         verifier,
			"redirect_uri":          testRedirectURI,
			"client_assertion":      clientAssertionFor(t, key, clientID),
			"client_assertion_type": clientAssertionType,
		}, nil)
		defer func() { _ = resp.Body.Close() }()

		require.Equal(t, http.StatusOK, resp.StatusCode,
			"a private_key_jwt client that omits client_id must still authenticate")
	})

	t.Run("no client authentication at all is refused", func(t *testing.T) {
		verifier, challenge := buildPKCEPair(t)
		code := buildAuthCode(t, clientID, uid("pkjwt-none"), testRedirectURI, challenge, []string{"data:read"})

		resp := post(t, "/oauth2/token", map[string]any{
			"grant_type":    "authorization_code",
			"client_id":     clientID,
			"code":          code,
			"code_verifier": verifier,
			"redirect_uri":  testRedirectURI,
			// Deliberately NO client_secret and NO client_assertion. Before
			// #346 this returned 200 with a token.
		}, nil)
		defer func() { _ = resp.Body.Close() }()

		require.Equal(t, http.StatusUnauthorized, resp.StatusCode,
			"a client registered for private_key_jwt must not redeem a code with no client authentication")
		got := decode(t, resp)
		assert.Equal(t, "invalid_client", got["error"])
		assert.Contains(t, got["error_description"], "private_key_jwt",
			"the refusal should name the method so an integrator can act on it")
	})

	t.Run("an assertion signed by an unregistered key is refused", func(t *testing.T) {
		verifier, challenge := buildPKCEPair(t)
		code := buildAuthCode(t, clientID, uid("pkjwt-bad"), testRedirectURI, challenge, []string{"data:read"})

		resp := post(t, "/oauth2/token", map[string]any{
			"grant_type":            "authorization_code",
			"client_id":             clientID,
			"code":                  code,
			"code_verifier":         verifier,
			"redirect_uri":          testRedirectURI,
			"client_assertion":      clientAssertionFor(t, generateKey(t), clientID),
			"client_assertion_type": clientAssertionType,
		}, nil)
		defer func() { _ = resp.Body.Close() }()

		require.Equal(t, http.StatusUnauthorized, resp.StatusCode,
			"an assertion signed by a key the client never published must not authenticate")
		assert.Equal(t, "invalid_client", decode(t, resp)["error"])
	})

	// The assertion is single-use. Replaying it is the attack the jti ledger
	// exists to stop, and it is invisible in any purely functional test.
	t.Run("the same assertion cannot be redeemed twice", func(t *testing.T) {
		assertion := clientAssertionFor(t, key, clientID)

		exchange := func(user string) int {
			verifier, challenge := buildPKCEPair(t)
			code := buildAuthCode(t, clientID, user, testRedirectURI, challenge, []string{"data:read"})
			resp := post(t, "/oauth2/token", map[string]any{
				"grant_type":            "authorization_code",
				"client_id":             clientID,
				"code":                  code,
				"code_verifier":         verifier,
				"redirect_uri":          testRedirectURI,
				"client_assertion":      assertion,
				"client_assertion_type": clientAssertionType,
			}, nil)
			defer func() { _ = resp.Body.Close() }()
			return resp.StatusCode
		}

		require.Equal(t, http.StatusOK, exchange(uid("pkjwt-r1")))
		require.Equal(t, http.StatusUnauthorized, exchange(uid("pkjwt-r2")),
			"a replayed client_assertion must be refused")
	})

	t.Run("introspection with client_id alone is refused", func(t *testing.T) {
		// The same downgrade reached token INSPECTION: the no-secret branch
		// resolved the client as public and returned nil. Introspection has no
		// redirect_uri binding to fall back on, so this half matters
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

	t.Run("introspection accepts a valid client_assertion", func(t *testing.T) {
		resp := post(t, "/oauth2/token/introspect", map[string]any{
			"token":                 "zid_at_whatever",
			"client_id":             clientID,
			"client_assertion":      clientAssertionFor(t, key, clientID),
			"client_assertion_type": clientAssertionType,
		}, nil)
		defer func() { _ = resp.Body.Close() }()

		// The token itself is nonsense, so the RFC 7662 answer is
		// {"active": false} — but the CLIENT authenticated, which is what this
		// asserts. A 401 here would mean key-based clients cannot introspect.
		require.Equal(t, http.StatusOK, resp.StatusCode,
			"a private_key_jwt client must be able to authenticate to introspection")
		assert.Equal(t, false, decode(t, resp)["active"])
	})
}

// Registration-time contract for private_key_jwt (zeroid#206 scope item 3).
// Before this, token_endpoint_auth_method was stored verbatim — any string at
// all landed in the column and was never consulted at authentication time.
func TestPrivateKeyJWT_RegistrationContract(t *testing.T) {
	t.Run("private_key_jwt without key material is refused", func(t *testing.T) {
		resp := post(t, adminPath("/oauth/clients"), map[string]any{
			"client_id":                  uid("pkjwt-nokeys"),
			"name":                       "no-keys",
			"confidential":               false,
			"token_endpoint_auth_method": "private_key_jwt",
		}, nil)
		defer func() { _ = resp.Body.Close() }()
		// 400, not 500: the caller's metadata is wrong, not the server.
		require.Equal(t, http.StatusBadRequest, resp.StatusCode,
			"registering a key-based client with no key produces a client that can never authenticate")
	})

	t.Run("an unenforceable method is refused", func(t *testing.T) {
		for _, method := range []string{"tls_client_auth", "client_secret_jwt", "private-key-jwt"} {
			resp := post(t, adminPath("/oauth/clients"), map[string]any{
				"client_id":                  uid("pkjwt-bad-method"),
				"name":                       "bad-method",
				"confidential":               false,
				"token_endpoint_auth_method": method,
			}, nil)
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
				"method %q is not enforceable and must not be registrable", method)
			_ = resp.Body.Close()
		}
	})

	t.Run("jwks and jwks_uri together are refused", func(t *testing.T) {
		resp := post(t, adminPath("/oauth/clients"), map[string]any{
			"client_id":                  uid("pkjwt-both"),
			"name":                       "both-key-sources",
			"confidential":               false,
			"token_endpoint_auth_method": "private_key_jwt",
			"jwks":                       clientJWKS(t, generateKey(t)),
			"jwks_uri":                   "https://client.example.com/jwks.json",
		}, nil)
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusBadRequest, resp.StatusCode, "RFC 7591 §2 forbids both")
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

// A private_key_jwt client that publishes a `jwks_uri` instead of an inline
// `jwks` must be able to authenticate.
//
// This exists because the inline-only tests could not have caught the bug it
// pins. `jwks` is a nullable jsonb column and bun writes a nil json.RawMessage
// as JSON `null`, not SQL NULL — so a jwks_uri-only client reads back with a
// four-byte `null` in its JWKS field. A length check on that field saw "inline
// key set present", concluded the row carried BOTH sources, and refused the
// client as an ambiguous registration. It could never have authenticated.
//
// In-memory unit tests are structurally blind to this: a hand-built
// domain.OAuthClient has a genuinely nil JWKS, while a database round trip does
// not. Only a test that actually persists and reloads the client sees it.
func TestPrivateKeyJWT_JWKSURIClient(t *testing.T) {
	clientID := uid("pkjwt-uri")
	key := generateKey(t)

	jwksBody, err := json.Marshal(clientJWKS(t, key))
	require.NoError(t, err)
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksBody)
	}))
	defer jwksServer.Close()

	reg := post(t, adminPath("/oauth/clients"), map[string]any{
		"client_id":                  clientID,
		"name":                       clientID + "-client",
		"confidential":               false,
		"token_endpoint_auth_method": "private_key_jwt",
		"jwks_uri":                   jwksServer.URL,
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"redirect_uris":              []string{testRedirectURI},
		"scopes":                     []string{"data:read"},
	}, nil)
	require.Equal(t, http.StatusCreated, reg.StatusCode, "jwks_uri registration must succeed")
	_ = reg.Body.Close()

	verifier, challenge := buildPKCEPair(t)
	code := buildAuthCode(t, clientID, uid("pkjwt-uri-user"), testRedirectURI, challenge, []string{"data:read"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":            "authorization_code",
		"client_id":             clientID,
		"code":                  code,
		"code_verifier":         verifier,
		"redirect_uri":          testRedirectURI,
		"client_assertion":      clientAssertionFor(t, key, clientID),
		"client_assertion_type": clientAssertionType,
	}, nil)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode,
		"a jwks_uri-backed client must authenticate — the keys are fetched, not stored inline")
	assert.NotEmpty(t, decode(t, resp)["access_token"])
}
