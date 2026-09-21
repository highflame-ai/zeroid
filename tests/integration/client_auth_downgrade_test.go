package integration_test

import (
	"context"
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

	"github.com/google/uuid"
	"github.com/highflame-ai/zeroid/internal/service"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
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

// A private_key_jwt client must never also hold a client_secret.
//
// `confidential` and `token_endpoint_auth_method` are independent registration
// inputs, and the secret is minted off the former before the latter is read. The
// combination therefore produced a client holding BOTH credentials — refused on
// authorization_code, refresh_token and CIBA (which enforce the registered
// method), but ACCEPTED on client_credentials and ID-JAG redemption, which
// verified the secret directly. The weaker credential won on whichever grant
// happened not to check.
func TestPrivateKeyJWT_CannotAlsoHoldASecret(t *testing.T) {
	resp := post(t, adminPath("/oauth/clients"), map[string]any{
		"client_id":                  uid("pkjwt-conf-contradiction"),
		"name":                       "confidential-and-key-based",
		"confidential":               true,
		"token_endpoint_auth_method": "private_key_jwt",
		"jwks":                       clientJWKS(t, generateKey(t)),
		"grant_types":                []string{"client_credentials"},
	}, nil)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"registering a key-based client as confidential would mint a secret it must not have")
}

// The other half of the same defect: a key-based client could not use
// client_credentials AT ALL, because that grant went straight to a bcrypt
// compare against an empty stored hash. DCR defaults grant_types to
// ["client_credentials"], so a conformant private_key_jwt DCR registration
// produced a client that could authenticate nowhere.
func TestPrivateKeyJWT_ClientCredentialsWithAssertion(t *testing.T) {
	// client_credentials resolves an identity by client_id, so the client must
	// be backed by a registered agent — same pairing the control test uses.
	clientID := uid("pkjwt-cc")
	registerAgent(t, clientID)
	key := generateKey(t)

	reg := post(t, adminPath("/oauth/clients"), map[string]any{
		"client_id":                  clientID,
		"name":                       clientID + "-client",
		"confidential":               false,
		"token_endpoint_auth_method": "private_key_jwt",
		"jwks":                       clientJWKS(t, key),
		"grant_types":                []string{"client_credentials"},
		"scopes":                     []string{"data:read"},
	}, nil)
	require.Equal(t, http.StatusCreated, reg.StatusCode)
	_ = reg.Body.Close()

	t.Run("a valid assertion authenticates", func(t *testing.T) {
		resp := post(t, "/oauth2/token", map[string]any{
			"grant_type":            "client_credentials",
			"account_id":            testAccountID,
			"project_id":            testProjectID,
			"client_id":             clientID,
			"client_assertion":      clientAssertionFor(t, key, clientID),
			"client_assertion_type": clientAssertionType,
		}, nil)
		defer func() { _ = resp.Body.Close() }()

		require.Equal(t, http.StatusOK, resp.StatusCode,
			"a key-based client must be able to use the grant DCR gives it by default")
		assert.NotEmpty(t, decode(t, resp)["access_token"])
	})

	t.Run("no credential at all is refused", func(t *testing.T) {
		resp := post(t, "/oauth2/token", map[string]any{
			"grant_type": "client_credentials",
			"account_id": testAccountID,
			"project_id": testProjectID,
			"client_id":  clientID,
		}, nil)
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

// jwks_uri decides who may authenticate as the client, so it must not be
// fetched over cleartext: anyone on the path could substitute the key set and
// then mint valid assertions at will. (The suite sets
// client_auth.allow_private_jwks_endpoints, which is what permits the loopback
// http fixture above — so this asserts the non-loopback production rule.)
func TestPrivateKeyJWT_JWKSURIMustNotBePlaintextRemote(t *testing.T) {
	for _, bad := range []string{"ftp://keys.example.com/jwks", "not-a-url", "/relative/jwks.json"} {
		resp := post(t, adminPath("/oauth/clients"), map[string]any{
			"client_id":                  uid("pkjwt-badscheme"),
			"name":                       "bad-jwks-uri",
			"confidential":               false,
			"token_endpoint_auth_method": "private_key_jwt",
			"jwks_uri":                   bad,
		}, nil)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "jwks_uri %q must be refused", bad)
		_ = resp.Body.Close()
	}
}

// A private_key_jwt client registered via DCR must survive RFC 7592 management,
// and must be able to read back the key material it has to restate.
//
// Before this, a PUT changing only client_name returned 200 and silently: flipped
// token_endpoint_auth_method to the RFC 7591 §2 default (client_secret_basic),
// wiped the registered key material, and left the client with NO credential at
// all — a key-based client is never issued a secret, and DCR has no endpoint to
// obtain one. The registrant could not recover; only an admin rotate-secret
// revived it. That was newly reachable, because DCR could not produce a
// key-based client until this PR.
func TestPrivateKeyJWT_DCRManagementDoesNotBrickTheClient(t *testing.T) {
	iat := issueClientRegisterToken(t)
	key := generateKey(t)

	reg := post(t, "/oauth2/register", map[string]any{
		"client_name":                "dcr-key-client",
		"grant_types":                []string{"client_credentials"},
		"scope":                      "data:read",
		"token_endpoint_auth_method": "private_key_jwt",
		"jwks":                       clientJWKS(t, key),
	}, map[string]string{"Authorization": "Bearer " + iat})
	require.Equal(t, http.StatusCreated, reg.StatusCode)
	body := decode(t, reg)
	_ = reg.Body.Close()

	clientID, _ := body["client_id"].(string)
	regToken, _ := body["registration_access_token"].(string)
	require.NotEmpty(t, clientID)
	assert.Empty(t, body["client_secret"], "a key-based DCR client gets no secret")

	mgmt := map[string]string{"Authorization": "Bearer " + regToken}

	t.Run("GET echoes the registered key material", func(t *testing.T) {
		// Without this the client cannot discover what it must restate on PUT,
		// making every PUT a choice between a 400 and losing its keys.
		resp := get(t, "/oauth2/register/"+clientID, mgmt)
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		got := decode(t, resp)
		assert.NotNil(t, got["jwks"], "GET must echo jwks for metadata-roundtrip fidelity")
		assert.Equal(t, "private_key_jwt", got["token_endpoint_auth_method"])
	})

	t.Run("a name-only PUT is refused, not silently destructive", func(t *testing.T) {
		resp := doRequest(t, http.MethodPut, "/oauth2/register/"+clientID, map[string]any{
			"client_name": "renamed",
		}, mgmt)
		defer func() { _ = resp.Body.Close() }()

		require.Equal(t, http.StatusBadRequest, resp.StatusCode,
			"a PUT omitting the auth method would strip this client's only credential")
		assert.Equal(t, "invalid_client_metadata", decode(t, resp)["error"])
	})

	t.Run("the client still authenticates after the refused PUT", func(t *testing.T) {
		resp := post(t, "/oauth2/token/introspect", map[string]any{
			"token":                 "zid_at_whatever",
			"client_id":             clientID,
			"client_assertion":      clientAssertionFor(t, key, clientID),
			"client_assertion_type": clientAssertionType,
		}, nil)
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusOK, resp.StatusCode,
			"the refused PUT must have left the client's key material intact")
	})

	t.Run("a PUT that restates the method and keys succeeds", func(t *testing.T) {
		resp := doRequest(t, http.MethodPut, "/oauth2/register/"+clientID, map[string]any{
			"client_name":                "renamed-properly",
			"grant_types":                []string{"client_credentials"},
			"scope":                      "data:read",
			"token_endpoint_auth_method": "private_key_jwt",
			"jwks":                       clientJWKS(t, key),
		}, mgmt)
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "renamed-properly", decode(t, resp)["client_name"])
	})
}

// A client registered for a SECRET-based method but never ISSUED a secret
// authenticated with nothing at all — the same downgrade as the private_key_jwt
// case, in a shape both earlier fixes walked past.
//
// The admin API accepts {confidential: false, token_endpoint_auth_method:
// "client_secret_basic"}: `confidential` is what mints the secret, and the
// method column is applied afterwards and independently (RegisterClient), so the
// row lands client_type=public with an EMPTY secret hash. That is precisely the
// shape verifyConfidentialClientAuth's public-client pass-through waves through.
//
// Neither #346 nor #347 caught it. rejectUnimplementedClientAuth passes the
// client — the server genuinely implements client_secret_basic — and
// enforceRegisteredClientAuthMethod returns nil for a secret-based client that
// presents nothing, because it only refuses ASSERTIONS. The old test
// `ClientType != "confidential" && ClientSecret == ""` was then true on both
// halves, and the grant proceeded unauthenticated.
//
// Asking the REGISTERED METHOD instead closes it: the method says this client
// authenticates with a secret, so one is demanded, and bcrypt against an empty
// stored hash refuses whatever is offered.
//
// This is a real behaviour change for such rows — before, they were issued
// tokens for free. Pinned here because nothing else fails if
// RequiresClientAuthentication is ever "simplified" back to the client_type /
// client_secret test it replaced.
func TestClientAuthDowngrade_SecretMethodWithoutASecret(t *testing.T) {
	clientID := uid("nosecret")

	reg := post(t, adminPath("/oauth/clients"), map[string]any{
		"client_id": clientID,
		"name":      clientID + "-client",
		// The contradiction: a secret-based method, but no secret minted.
		"confidential":               false,
		"token_endpoint_auth_method": "client_secret_basic",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"redirect_uris":              []string{testRedirectURI},
		"scopes":                     []string{"data:read"},
	}, nil)
	// REGISTRATION NOW REFUSES THE SHAPE. An earlier revision of this test
	// asserted 201 here and told whoever added the guard to invert it; this is
	// that inversion.
	//
	// Both halves still matter and both are still asserted. Refusing at
	// registration is what stops a NEW client being created that can authenticate
	// nowhere. The subtests below still pin the authentication behaviour, because
	// rows in this shape may already exist — nothing refused them until now — and
	// the fail-open they used to get is the actual defect.
	require.Equal(t, http.StatusBadRequest, reg.StatusCode,
		"a secret-based method with confidential=false describes a client that could never "+
			"authenticate; registration must say so rather than create it")
	_ = reg.Body.Close()

	// Reproduce the legacy row directly, which is the only way to exercise the
	// authentication path now that the front door is shut: this is exactly what
	// RegisterClient used to write for the request above.
	seedLegacyUnauthenticatableClient(t, clientID)

	t.Run("authorization_code is refused without a secret", func(t *testing.T) {
		verifier, challenge := buildPKCEPair(t)
		code := buildAuthCode(t, clientID, uid("nosecret-user"), testRedirectURI,
			challenge, []string{"data:read"})

		resp := post(t, "/oauth2/token", map[string]any{
			"grant_type":    "authorization_code",
			"client_id":     clientID,
			"code":          code,
			"code_verifier": verifier,
			"redirect_uri":  testRedirectURI,
		}, nil)
		defer func() { _ = resp.Body.Close() }()

		// Pre-fix this returned 200 with an access_token AND a refresh_token,
		// for a caller holding only a stolen code and a client_id.
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode,
			"a client registered for client_secret_basic must not authenticate with nothing")
		assert.Equal(t, "invalid_client", decode(t, resp)["error"])
	})

	t.Run("a wrong secret is refused too, not just an absent one", func(t *testing.T) {
		// Guards the lazy fix: demanding a non-empty client_secret but never
		// verifying it would pass this client on any string at all, since its
		// stored hash is empty.
		verifier, challenge := buildPKCEPair(t)
		code := buildAuthCode(t, clientID, uid("nosecret-wrong"), testRedirectURI,
			challenge, []string{"data:read"})

		resp := post(t, "/oauth2/token", map[string]any{
			"grant_type":    "authorization_code",
			"client_id":     clientID,
			"code":          code,
			"code_verifier": verifier,
			"redirect_uri":  testRedirectURI,
			"client_secret": "anything-at-all",
		}, nil)
		defer func() { _ = resp.Body.Close() }()

		require.Equal(t, http.StatusUnauthorized, resp.StatusCode,
			"bcrypt against an empty stored hash must fail closed")
		assert.Equal(t, "invalid_client", decode(t, resp)["error"])
	})

	t.Run("CIBA bc-authorize is refused without a secret", func(t *testing.T) {
		// The other call site the predicate replaced (backchannel.go). Driven at
		// the service layer for the same reason TestCIBAHardening is: it is the
		// tighter loop, and it pins the SITE rather than one grant's routing.
		//
		// Not merely a token downgrade here — bc-authorize fires the deployer's
		// notifier, so an unauthenticated initiator could spam real approval
		// prompts at real users under this client's identity.
		bcSvc := service.NewBackchannelService(
			postgres.NewBackchannelRequestRepository(testDB),
			service.NewOAuthClientService(postgres.NewOAuthClientRepository(testDB)),
			nil, nil, service.DefaultBackchannelConfig(),
		)

		_, err := bcSvc.CreateAuthRequest(context.Background(), service.CreateAuthRequestInput{
			ClientID:  clientID,
			AccountID: testAccountID,
			ProjectID: testProjectID,
			GroupHint: "finance_lead",
			Scope:     "openid",
		})
		require.Error(t, err, "bc-authorize must not accept an unauthenticated secret-based client")
		assert.Contains(t, err.Error(), "client_secret is required")
	})
}

// seedLegacyUnauthenticatableClient writes the row RegisterClient produced for
// {confidential: false, token_endpoint_auth_method: client_secret_basic} before
// that combination was refused: registered for secret-based authentication, with
// an EMPTY secret hash.
//
// Written through the repository rather than the API on purpose. The API is now
// closed, and the point of the subtests is that rows already in this shape must
// not authenticate with nothing — closing the front door does not retire the
// question for rows that predate it.
func seedLegacyUnauthenticatableClient(t *testing.T, clientID string) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, postgres.NewOAuthClientRepository(testDB).Create(ctx, &domain.OAuthClient{
		ID:                           uuid.New().String(),
		ClientID:                     clientID,
		Name:                         clientID + "-legacy",
		ClientType:                   "public",
		TokenEndpointAuthMethod:      "client_secret_basic",
		ClientSecret:                 "", // the whole defect: none was ever minted
		BackchannelTokenDeliveryMode: "poll",
		GrantTypes:                   []string{"authorization_code", "refresh_token"},
		RedirectURIs:                 []string{testRedirectURI},
		Scopes:                       []string{"data:read"},
		IsActive:                     true,
	}))
	t.Cleanup(func() {
		_, _ = testDB.NewDelete().Model((*domain.OAuthClient)(nil)).
			Where("client_id = ?", clientID).Exec(context.Background())
	})
}
