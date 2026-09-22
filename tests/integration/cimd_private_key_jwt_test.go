// End-to-end coverage for the CONFIDENTIAL half of CIMD: a client that
// pre-registers nothing, publishes `private_key_jwt` + a key set in its metadata
// document, and authenticates at the token endpoint with an RFC 7523 §2.2
// assertion verified against that document (zeroid#264).
//
// WHY THIS FILE EXISTS. Before it, the two halves were covered and their join
// was not. TestSynthesizeCIMDClient proves a document declaring private_key_jwt
// synthesizes a confidential client carrying its keys;
// TestVerifyClientAssertion_* proves an assertion verifies against a client's
// key material. Nothing anywhere — in this repo or the MCP interop matrix —
// carried one client through /oauth2/authorize AND then authenticated it at
// /oauth2/token. That join is the whole feature: the document is fetched during
// authorize, and the keys it published have to still decide who may
// authenticate one HTTP request later, for a client that was never persisted.
//
// The downgrade case below is the one with teeth. A CIMD client is SYNTHESIZED,
// not registered, so nothing at registration vetted it — and the public-PKCE
// path it shares is precisely the pass-through that let a private_key_jwt client
// authenticate with nothing at all before zeroid#206/#346. That the synthesized
// client is refused without its assertion is the property, and it cannot be
// asserted anywhere upstream of the token endpoint.
//
// Inline `jwks` rather than `jwks_uri` throughout, deliberately: `jwks_uri`
// means a SECOND outbound fetch, from the SSRF-guarded ClientJWKSCache that
// takes no injection hook, so it cannot reach an httptest server. The
// interop matrix covers that arm against a fixture origin with a genuinely
// trusted CA (test_row_jwks_uri_support); this covers the arm that a Go test
// can prove hermetically. Both arms converge on the same
// clientVerificationKeys → verifyClientAssertion path.
package integration_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	zeroid "github.com/highflame-ai/zeroid"
)

const (
	// The CIMD test server's own issuer. Distinct from testIssuer so a client
	// assertion minted for one server can never be accepted by the other —
	// audience binding is the control keeping an assertion from being replayed
	// against a different AS, and sharing the value would hide a break in it.
	cimdTestIssuer = "https://cimd.zeroid.test"

	// Loopback, because it has to be. With cimd.allowed_domains empty (the
	// default, and what this server runs), a self-asserted client heading for a
	// REMOTE https callback is refused the redirect outright; loopback and
	// private-use callbacks are exempt since they deliver to the requester's own
	// device. An ordinary desktop/CLI MCP client is exactly this shape.
	cimdTestRedirectURI = "http://127.0.0.1:9000/cb"
)

// newCIMDDocumentOrigin serves `doc` — already-encoded JSON — as the metadata
// document at every path, over TLS. The `%CLIENT_ID%` placeholder is replaced
// with the self-referencing client_id for the path being requested, which is
// what CIMD requires the document's own client_id member to be.
//
// Returns the origin's base URL and an HTTP client that trusts its cert.
func newCIMDDocumentOrigin(t *testing.T, doc string) (base string, client *http.Client) {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientID := "https://" + r.Host + r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, strings.ReplaceAll(doc, "%CLIENT_ID%", clientID))
	}))
	t.Cleanup(ts.Close)
	return ts.URL, ts.Client()
}

// newCIMDZeroID spins up a second zeroid.Server against the shared Postgres,
// with its CIMD document fetcher pointed at an origin the test controls.
//
// Mirrors newFederationServer (external_idp_test.go) — same reason, different
// fetcher: an httptest TLS origin's cert is trusted by nothing, and no Config
// field can express "trust this one". WithCIMDHTTPClient is the CIMD sibling of
// WithExternalIssuerJWKSOption.
//
// A PrincipalResolver is registered because /oauth2/authorize is unservable
// without one — zeroid ships no built-in resolver (it was removed as a privilege
// escalation), so a bare server 503s the endpoint this whole flow starts at.
func newCIMDZeroID(t *testing.T, docClient *http.Client) *httptest.Server {
	t.Helper()
	require.NoError(t, initFederationKeyMaterial(), "init key material")

	cfg := zeroid.Config{
		Server: zeroid.ServerConfig{Port: "0", Env: "test", ShutdownTimeoutSeconds: 5},
		Database: zeroid.DatabaseConfig{
			URL:          sharedDBURL,
			MaxOpenConns: 5,
			MaxIdleConns: 2,
		},
		Keys: zeroid.KeysConfig{
			PrivateKeyPath:    fedKeyPaths.privPath,
			PublicKeyPath:     fedKeyPaths.pubPath,
			KeyID:             "cimd-test-key-1",
			RSAPrivateKeyPath: fedKeyPaths.rsaPriv,
			RSAPublicKeyPath:  fedKeyPaths.rsaPub,
			RSAKeyID:          "cimd-test-rsa-1",
		},
		Token: zeroid.TokenConfig{
			Issuer:         cimdTestIssuer,
			DefaultTTL:     3600,
			MaxTTL:         90 * 24 * 3600,
			HMACSecret:     testHMACSecret,
			AuthCodeIssuer: cimdTestIssuer,
		},
		// Enabled + no allowed_domains: the out-of-the-box posture, and the one
		// a zero-registration MCP client actually meets.
		CIMD:        zeroid.CIMDConfig{Enabled: true},
		Telemetry:   zeroid.TelemetryConfig{Enabled: false},
		Logging:     zeroid.LoggingConfig{Level: "warn"},
		WIMSEDomain: testWIMSE,
	}

	srv, err := zeroid.NewServer(cfg, zeroid.WithCIMDHTTPClient(docClient))
	require.NoError(t, err, "build CIMD test server")

	srv.RegisterPrincipalResolver("cimd-test-stub", func(_ context.Context, req *zeroid.AuthorizeRequest) (*zeroid.Principal, error) {
		acct := req.Form("test_principal_account")
		if acct == "" {
			return nil, zeroid.ErrPrincipalNotApplicable
		}
		return &zeroid.Principal{
			AccountID: acct,
			ProjectID: req.Form("test_principal_project"),
			UserID:    req.Form("test_principal_user"),
		}, nil
	})

	httpSrv := httptest.NewServer(srv.Router())
	t.Cleanup(httpSrv.Close)
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	return httpSrv
}

// cimdAuthorize drives /oauth2/authorize on the given server and returns the
// raw response (302 on success — the code rides in Location).
func cimdAuthorize(t *testing.T, baseURL string, form url.Values) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		baseURL+"/oauth2/authorize", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// cimdAssertionFor builds an RFC 7523 §2.2 client-authentication JWT addressed
// to the CIMD test server. Separate from clientAssertionFor (which is bound to
// testIssuer) so both servers keep their own audience.
func cimdAssertionFor(t *testing.T, key *ecdsa.PrivateKey, clientID string) string {
	t.Helper()
	now := time.Now()
	tok, err := jwt.NewBuilder().
		Issuer(clientID).
		Subject(clientID).
		Audience([]string{cimdTestIssuer}).
		IssuedAt(now).
		Expiration(now.Add(2 * time.Minute)).
		JwtID(uid("cimd-cla")).
		Build()
	require.NoError(t, err)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), key))
	require.NoError(t, err)
	return string(signed)
}

// authorizeAndGetCode runs the browser leg and returns the issued code, failing
// the test if no code came back.
func authorizeAndGetCode(t *testing.T, srvURL, clientID, challenge string) string {
	t.Helper()
	resp := cimdAuthorize(t, srvURL, url.Values{
		"client_id":              {clientID},
		"redirect_uri":           {cimdTestRedirectURI},
		"response_type":          {"code"},
		"code_challenge":         {challenge},
		"code_challenge_method":  {"S256"},
		"test_principal_account": {"acct-cimd-pkjwt"},
		"test_principal_project": {"proj-cimd-pkjwt"},
		"test_principal_user":    {"user-cimd-pkjwt"},
	})
	require.Equal(t, http.StatusFound, resp.StatusCode,
		"a confidential CIMD client must be able to obtain an authorization code: "+
			"MayObtainAuthorizationCode admits a key-based client regardless of client_type")

	u, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	code := u.Query().Get("code")
	require.NotEmpty(t, code, "Location must carry ?code= (got %q)", resp.Header.Get("Location"))
	return code
}

// privateKeyJWTDoc renders a CIMD document for a private_key_jwt client
// publishing `key`'s public half inline.
func privateKeyJWTDoc(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	jwks, err := json.Marshal(clientJWKS(t, key))
	require.NoError(t, err)
	return fmt.Sprintf(`{
		"client_id": "%%CLIENT_ID%%",
		"client_name": "cimd private_key_jwt client",
		"redirect_uris": [%q],
		"grant_types": ["authorization_code", "refresh_token"],
		"token_endpoint_auth_method": "private_key_jwt",
		"jwks": %s
	}`, cimdTestRedirectURI, jwks)
}

func TestCIMD_PrivateKeyJWTClient(t *testing.T) {
	key := generateKey(t)
	base, docClient := newCIMDDocumentOrigin(t, privateKeyJWTDoc(t, key))
	srvURL := newCIMDZeroID(t, docClient).URL
	clientID := base + "/.well-known/oauth-client"

	// THE ACCEPTANCE CASE. Everything this feature claims, in one flow: a client
	// the server has never seen publishes keys, gets a code, and trades it for a
	// token using only a signature over those keys.
	t.Run("completes the authorization_code flow with a client assertion", func(t *testing.T) {
		verifier, challenge := buildPKCEPair(t)
		code := authorizeAndGetCode(t, srvURL, clientID, challenge)

		tok := postFederation(t, srvURL, map[string]any{
			"grant_type":            "authorization_code",
			"client_id":             clientID,
			"code":                  code,
			"code_verifier":         verifier,
			"redirect_uri":          cimdTestRedirectURI,
			"client_assertion":      cimdAssertionFor(t, key, clientID),
			"client_assertion_type": clientAssertionType,
		})
		require.Equal(t, http.StatusOK, tok.StatusCode,
			"the assertion must verify against the key set the metadata document published: %s", tok.RawBody)
		require.NotEmpty(t, tok.AccessToken)

		claims := decodeIssuedTokenClaims(t, tok.AccessToken)
		assert.Equal(t, "acct-cimd-pkjwt", claims["account_id"],
			"tenant context from the PrincipalResolver must survive the exchange")
		assert.Equal(t, cimdTestIssuer, claims["iss"])
	})

	// THE DOWNGRADE GUARD, and the reason this file is not just the case above.
	// A CIMD client reaches the token endpoint through the same resolution path
	// as a public PKCE client — it just carries different key material — so
	// "presents no credential" has to be refused by something that reads the
	// SYNTHESIZED client's method. If it ever passes, the feature has silently
	// become public-PKCE-with-extra-JSON: the code alone would mint, and the
	// published key set would be decoration.
	t.Run("is refused when it presents no client assertion", func(t *testing.T) {
		verifier, challenge := buildPKCEPair(t)
		code := authorizeAndGetCode(t, srvURL, clientID, challenge)

		tok := postFederation(t, srvURL, map[string]any{
			"grant_type":    "authorization_code",
			"client_id":     clientID,
			"code":          code,
			"code_verifier": verifier,
			"redirect_uri":  cimdTestRedirectURI,
		})
		require.NotEqual(t, http.StatusOK, tok.StatusCode,
			"a CIMD client that published private_key_jwt must not authenticate with a bare valid code: %s", tok.RawBody)
		assert.Equal(t, "invalid_client", tok.Error, "body=%s", tok.RawBody)
		// The message, not just the code: a 401 here is also what an unknown
		// client_id or a burnt code produces, so status alone would pass against
		// an implementation that rejected for entirely the wrong reason.
		assert.Contains(t, tok.RawBody, "private_key_jwt",
			"the refusal must name the method the document declared")
	})

	// Possession of the published key is what authenticates — not possession of
	// the document, which is public by construction. Anyone can read the
	// client_id URL; only the publisher holds the private half.
	t.Run("is refused when the assertion is signed by a foreign key", func(t *testing.T) {
		verifier, challenge := buildPKCEPair(t)
		code := authorizeAndGetCode(t, srvURL, clientID, challenge)

		tok := postFederation(t, srvURL, map[string]any{
			"grant_type":            "authorization_code",
			"client_id":             clientID,
			"code":                  code,
			"code_verifier":         verifier,
			"redirect_uri":          cimdTestRedirectURI,
			"client_assertion":      cimdAssertionFor(t, generateKey(t), clientID),
			"client_assertion_type": clientAssertionType,
		})
		require.NotEqual(t, http.StatusOK, tok.StatusCode,
			"an assertion signed by a key the document never published must not authenticate: %s", tok.RawBody)
		assert.Equal(t, "invalid_client", tok.Error, "body=%s", tok.RawBody)
	})
}

// A document declaring private_key_jwt with NO key material is refused at
// resolution, before a code is ever issued.
//
// Worth its own test because it is counter-intuitive enough to have been written
// into the interop matrix backwards: the matrix's own
// test_row_authcode_pkce_client_auth[jwt] fixture publishes private_key_jwt with
// neither `jwks` nor `jwks_uri` and expects a code, so it scores the row
// "unsupported" against an implementation that supports it. Refusing is correct
// and is the same rule zeroid#346 applied to registration — a client advertising
// an authentication method it has given us no way to verify can never
// authenticate, so admitting it only defers the failure to a point where the
// client can no longer tell why.
func TestCIMD_PrivateKeyJWTWithoutKeyMaterialIsRefused(t *testing.T) {
	base, docClient := newCIMDDocumentOrigin(t, fmt.Sprintf(`{
		"client_id": "%%CLIENT_ID%%",
		"client_name": "keyless private_key_jwt client",
		"redirect_uris": [%q],
		"grant_types": ["authorization_code"],
		"token_endpoint_auth_method": "private_key_jwt"
	}`, cimdTestRedirectURI))
	srvURL := newCIMDZeroID(t, docClient).URL

	_, challenge := buildPKCEPair(t)
	resp := cimdAuthorize(t, srvURL, url.Values{
		"client_id":              {base + "/keyless.json"},
		"redirect_uri":           {cimdTestRedirectURI},
		"response_type":          {"code"},
		"code_challenge":         {challenge},
		"code_challenge_method":  {"S256"},
		"test_principal_account": {"acct-cimd-keyless"},
	})
	// The specific status and error code, not merely "not a redirect": the
	// harness can fail to produce a 302 for reasons that have nothing to do with
	// key material — an unresolvable origin, a resolver that declines, a 500 —
	// and each of those would satisfy a not-302 assertion while proving nothing.
	// invalid_client_metadata is what document validation specifically emits.
	require.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"a document declaring private_key_jwt with no jwks or jwks_uri must be refused as invalid metadata")
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), "invalid_client_metadata",
		"the refusal must come from document validation, not from some unrelated failure: %s", string(body))
}
