// End-to-end coverage for RFC 7009 §2.1 revocation by a CIMD client
// (zeroid#419).
//
// A public client may identify itself at the revocation endpoint by client_id
// alone. For a REGISTERED public client that always worked; a CIMD client —
// whose registration is the metadata document at its client_id URL — was
// refused, because revocation shared introspection's registry-only gate. These
// tests pin the split:
//
//   - a public CIMD client revokes a token issued to it;
//   - naming a CIMD client_id reaches ONLY that client's tokens: another
//     client's token answers 200 (RFC 7009 §2.2) and stays active;
//   - introspection still refuses an unauthenticated CIMD client_id;
//   - a CIMD client that declares private_key_jwt is confidential: it revokes
//     its own tokens with a valid RFC 7523 §2.2 assertion (same rules as the
//     token endpoint) and is refused without one;
//   - introspection refuses a CIMD client even when it authenticates;
//   - a CIMD client_id whose document does not resolve is still refused.
//
// Run in isolation:
//
//	go test ./tests/integration/ -run 'TestCIMDRevoke' -count=1
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
)

// cimdGonePath is a document path the revoke-test origin answers 404 for, so a
// client_id naming it fails CIMD resolution at the fetch.
const cimdGonePath = "/gone.json"

// newCIMDRevokeOrigin serves a PUBLIC (token_endpoint_auth_method "none")
// self-referencing metadata document at every path except cimdGonePath. One
// origin, many client_ids: each path is a distinct CIMD client.
func newCIMDRevokeOrigin(t *testing.T) (base string, client *http.Client) {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == cimdGonePath {
			http.NotFound(w, r)
			return
		}
		clientID := "https://" + r.Host + r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"client_id": %q,
			"client_name": "cimd public client",
			"redirect_uris": [%q],
			"grant_types": ["authorization_code"],
			"token_endpoint_auth_method": "none"
		}`, clientID, cimdTestRedirectURI)
	}))
	t.Cleanup(ts.Close)
	return ts.URL, ts.Client()
}

// cimdPublicAccessToken runs the public-client authorization_code flow for
// clientID against srvURL and returns the access token.
func cimdPublicAccessToken(t *testing.T, srvURL, clientID string) string {
	t.Helper()
	verifier, challenge := buildPKCEPair(t)
	code := authorizeAndGetCode(t, srvURL, clientID, challenge)
	tok := postFederation(t, srvURL, map[string]any{
		"grant_type":    "authorization_code",
		"client_id":     clientID,
		"code":          code,
		"code_verifier": verifier,
		"redirect_uri":  cimdTestRedirectURI,
	})
	require.Equal(t, http.StatusOK, tok.StatusCode, "public CIMD token exchange: %s", tok.RawBody)
	require.NotEmpty(t, tok.AccessToken)
	// The ownership check compares against this claim; if the fixture's token
	// did not carry it, every "revoked" assertion below would be meaningless.
	require.Equal(t, clientID, decodeIssuedTokenClaims(t, tok.AccessToken)["client_id"],
		"the issued token must carry the CIMD client_id it was issued to")
	return tok.AccessToken
}

// postFormTo posts an application/x-www-form-urlencoded body to baseURL+path
// and returns the status and decoded JSON body.
func postFormTo(t *testing.T, baseURL, path string, form url.Values, headers map[string]string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		baseURL+path, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	body := map[string]any{}
	if len(raw) > 0 {
		require.NoError(t, json.Unmarshal(raw, &body), "body=%s", raw)
	}
	return resp.StatusCode, body
}

// cimdRevokeIntrospector registers a confidential client in the shared
// registry (clients are global, so the CIMD test server sees it) and returns
// a function that introspects a token on srvURL authenticated as it. The
// CIMD test server runs strict token-inspection auth, so introspection needs
// an authenticated caller.
func cimdRevokeIntrospector(t *testing.T, srvURL string) func(token string) map[string]any {
	t.Helper()
	inspector := registerOAuthClient(t, uid("cimd-revoke-inspector"), []string{"data:read"})
	return func(token string) map[string]any {
		t.Helper()
		status, body := postFormTo(t, srvURL, "/oauth2/token/introspect",
			url.Values{"token": {token}}, basicAuthHeader(inspector.ClientID, inspector.ClientSecret))
		require.Equal(t, http.StatusOK, status, "authenticated introspection: %v", body)
		return body
	}
}

func TestCIMDRevoke_PublicClient(t *testing.T) {
	base, docClient := newCIMDRevokeOrigin(t)
	srvURL := newCIMDZeroID(t, docClient).URL
	introspectAs := cimdRevokeIntrospector(t, srvURL)

	// THE ACCEPTANCE CASE. A stock OAuth library revoking its own token sends
	// token + client_id and nothing else (RFC 7009 §2.1).
	t.Run("revokes its own token by client_id alone", func(t *testing.T) {
		clientID := base + "/" + uid("owner") + ".json"
		token := cimdPublicAccessToken(t, srvURL, clientID)
		require.Equal(t, true, introspectAs(token)["active"], "baseline: the token is live")

		status, body := postFormTo(t, srvURL, "/oauth2/token/revoke",
			url.Values{"token": {token}, "client_id": {clientID}}, nil)
		require.Equal(t, http.StatusOK, status,
			"a public CIMD client must be able to revoke its own token: %v", body)

		assert.Equal(t, false, introspectAs(token)["active"],
			"the token must actually be revoked, not just answered with 200")
	})

	// THE CONSTRAINT that makes accepting a self-published identity safe here.
	// Anyone can name any CIMD URL, so naming one must reach only that
	// client's tokens. The response is still 200 — RFC 7009 §2.2, and
	// distinguishing "not yours" would reveal whose token it is.
	t.Run("cannot revoke another client's token", func(t *testing.T) {
		victimID := base + "/" + uid("victim") + ".json"
		attackerID := base + "/" + uid("other") + ".json"
		token := cimdPublicAccessToken(t, srvURL, victimID)

		status, body := postFormTo(t, srvURL, "/oauth2/token/revoke",
			url.Values{"token": {token}, "client_id": {attackerID}}, nil)
		require.Equal(t, http.StatusOK, status, "RFC 7009 §2.2: still 200: %v", body)

		assert.Equal(t, true, introspectAs(token)["active"],
			"a CIMD client_id must not revoke a token issued to a different client")
	})

	// Introspection keeps the registry-only rule: it has no ownership
	// constraint to apply, so an unauthenticated CIMD client_id would make it a
	// token oracle for anyone who can name a URL.
	t.Run("introspection still refuses an unauthenticated CIMD client_id", func(t *testing.T) {
		clientID := base + "/" + uid("introspector") + ".json"
		token := cimdPublicAccessToken(t, srvURL, clientID)

		status, body := postFormTo(t, srvURL, "/oauth2/token/introspect",
			url.Values{"token": {token}, "client_id": {clientID}}, nil)
		require.Equal(t, http.StatusUnauthorized, status,
			"introspection must not accept a CIMD client_id without authentication: %v", body)
		assert.Equal(t, "invalid_client", body["error"])
		assert.NotContains(t, body, "active", "no token information may leak on refusal")
	})

	// Resolution failure is refused exactly as before this path existed — the
	// same resolver, fetch and domain policy as the token endpoint.
	t.Run("a client_id whose document does not resolve is refused", func(t *testing.T) {
		owner := base + "/" + uid("live") + ".json"
		token := cimdPublicAccessToken(t, srvURL, owner)

		status, body := postFormTo(t, srvURL, "/oauth2/token/revoke",
			url.Values{"token": {token}, "client_id": {base + cimdGonePath}}, nil)
		require.Equal(t, http.StatusUnauthorized, status,
			"an unresolvable CIMD client_id must be refused: %v", body)
		assert.Equal(t, "invalid_client", body["error"])
		assert.Equal(t, true, introspectAs(token)["active"])
	})
}

// cimdPrivateKeyJWTAccessToken runs the confidential-client
// authorization_code flow for clientID (a private_key_jwt document published
// with key) and returns the access token.
func cimdPrivateKeyJWTAccessToken(t *testing.T, srvURL, clientID string, key *ecdsa.PrivateKey) string {
	t.Helper()
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
	require.Equal(t, http.StatusOK, tok.StatusCode, "fixture: %s", tok.RawBody)
	require.Equal(t, clientID, decodeIssuedTokenClaims(t, tok.AccessToken)["client_id"],
		"fixture: the token must carry the client_id it was issued to")
	return tok.AccessToken
}

// cimdAssertionWithAud is cimdAssertionFor with an explicit aud.
func cimdAssertionWithAud(t *testing.T, key *ecdsa.PrivateKey, clientID, aud string) string {
	t.Helper()
	now := time.Now()
	tok, err := jwt.NewBuilder().
		Issuer(clientID).
		Subject(clientID).
		Audience([]string{aud}).
		IssuedAt(now).
		Expiration(now.Add(2 * time.Minute)).
		JwtID(uid("cimd-cla")).
		Build()
	require.NoError(t, err)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), key))
	require.NoError(t, err)
	return string(signed)
}

// A document declaring private_key_jwt describes a CONFIDENTIAL client
// (zeroid#348). It revokes by authenticating with an RFC 7523 §2.2 assertion
// signed by a key its document publishes — under the same rules the token
// endpoint applies to it — and, like a public CIMD client, only ever reaches
// tokens issued to it. Its client_id alone proves nothing and is refused.
func TestCIMDRevoke_ConfidentialClient(t *testing.T) {
	key := generateKey(t)
	base, docClient := newCIMDDocumentOrigin(t, privateKeyJWTDoc(t, key))
	srvURL := newCIMDZeroID(t, docClient).URL
	introspectAs := cimdRevokeIntrospector(t, srvURL)
	revoke := func(form url.Values) (int, map[string]any) {
		t.Helper()
		return postFormTo(t, srvURL, "/oauth2/token/revoke", form, nil)
	}

	t.Run("revokes its own token with a valid assertion", func(t *testing.T) {
		clientID := base + "/" + uid("pkjwt") + ".json"
		token := cimdPrivateKeyJWTAccessToken(t, srvURL, clientID, key)

		status, body := revoke(url.Values{
			"token": {token}, "client_id": {clientID},
			"client_assertion": {cimdAssertionFor(t, key, clientID)}, "client_assertion_type": {clientAssertionType},
		})
		require.Equal(t, http.StatusOK, status, "an authenticated CIMD client must revoke its own token: %v", body)
		assert.Equal(t, false, introspectAs(token)["active"])
	})

	// The token endpoint URL is the RFC 7523 §3 conventional aud; the issuer
	// identifier (above) is what most libraries send. Both are accepted, as for
	// a registered private_key_jwt client.
	t.Run("accepts the token endpoint URL as aud", func(t *testing.T) {
		clientID := base + "/" + uid("pkjwt-aud") + ".json"
		token := cimdPrivateKeyJWTAccessToken(t, srvURL, clientID, key)

		status, body := revoke(url.Values{
			"token": {token}, "client_id": {clientID},
			"client_assertion":      {cimdAssertionWithAud(t, key, clientID, cimdTestIssuer+"/oauth2/token")},
			"client_assertion_type": {clientAssertionType},
		})
		require.Equal(t, http.StatusOK, status, "%v", body)
		assert.Equal(t, false, introspectAs(token)["active"])
	})

	// RFC 7523 §3: the assertion's iss identifies the client, so conformant
	// libraries omit client_id.
	t.Run("identifies the client from the assertion when client_id is omitted", func(t *testing.T) {
		clientID := base + "/" + uid("pkjwt-iss") + ".json"
		token := cimdPrivateKeyJWTAccessToken(t, srvURL, clientID, key)

		status, body := revoke(url.Values{
			"token":            {token},
			"client_assertion": {cimdAssertionFor(t, key, clientID)}, "client_assertion_type": {clientAssertionType},
		})
		require.Equal(t, http.StatusOK, status, "%v", body)
		assert.Equal(t, false, introspectAs(token)["active"])
	})

	// Authentication proves only "I am this URL" — anyone can publish a
	// document with their own key — so it buys no more than the public case:
	// only this client's own tokens.
	t.Run("cannot revoke another client's token even when authenticated", func(t *testing.T) {
		victimID := base + "/" + uid("pkjwt-victim") + ".json"
		otherID := base + "/" + uid("pkjwt-other") + ".json"
		token := cimdPrivateKeyJWTAccessToken(t, srvURL, victimID, key)

		status, body := revoke(url.Values{
			"token": {token}, "client_id": {otherID},
			"client_assertion": {cimdAssertionFor(t, key, otherID)}, "client_assertion_type": {clientAssertionType},
		})
		require.Equal(t, http.StatusOK, status, "RFC 7009 §2.2: still 200: %v", body)
		assert.Equal(t, true, introspectAs(token)["active"],
			"an authenticated CIMD client must not revoke a token issued to a different client")
	})

	t.Run("is refused without an assertion", func(t *testing.T) {
		clientID := base + "/" + uid("pkjwt-bare") + ".json"
		token := cimdPrivateKeyJWTAccessToken(t, srvURL, clientID, key)

		status, body := revoke(url.Values{"token": {token}, "client_id": {clientID}})
		require.Equal(t, http.StatusUnauthorized, status,
			"a private_key_jwt CIMD client presenting no assertion must be refused: %v", body)
		assert.Equal(t, "invalid_client", body["error"])
		assert.Contains(t, body["error_description"], "private_key_jwt",
			"the refusal must come from the declared method, not some unrelated failure")
		assert.Equal(t, true, introspectAs(token)["active"])
	})

	t.Run("is refused with an assertion signed by a key the document does not publish", func(t *testing.T) {
		clientID := base + "/" + uid("pkjwt-foreign") + ".json"
		token := cimdPrivateKeyJWTAccessToken(t, srvURL, clientID, key)

		status, body := revoke(url.Values{
			"token": {token}, "client_id": {clientID},
			"client_assertion": {cimdAssertionFor(t, generateKey(t), clientID)}, "client_assertion_type": {clientAssertionType},
		})
		require.Equal(t, http.StatusUnauthorized, status, "%v", body)
		assert.Equal(t, "invalid_client", body["error"])
		assert.Equal(t, true, introspectAs(token)["active"])
	})

	t.Run("is refused when the assertion is replayed", func(t *testing.T) {
		clientID := base + "/" + uid("pkjwt-replay") + ".json"
		first := cimdPrivateKeyJWTAccessToken(t, srvURL, clientID, key)
		second := cimdPrivateKeyJWTAccessToken(t, srvURL, clientID, key)
		assertion := cimdAssertionFor(t, key, clientID)

		status, _ := revoke(url.Values{
			"token": {first}, "client_id": {clientID},
			"client_assertion": {assertion}, "client_assertion_type": {clientAssertionType},
		})
		require.Equal(t, http.StatusOK, status)

		status, body := revoke(url.Values{
			"token": {second}, "client_id": {clientID},
			"client_assertion": {assertion}, "client_assertion_type": {clientAssertionType},
		})
		require.Equal(t, http.StatusUnauthorized, status, "a client assertion is single-use: %v", body)
		assert.Equal(t, true, introspectAs(second)["active"])
	})

	// Introspection stays closed to CIMD clients even when they authenticate.
	// Unlike revocation it has no ownership constraint to apply — it answers
	// about any token presented — and authenticating as a CIMD client proves
	// only control of a URL, which anyone can have. Admitting it would make
	// introspection a token oracle for anyone with a web server.
	t.Run("introspection refuses it even with a valid assertion", func(t *testing.T) {
		clientID := base + "/" + uid("pkjwt-introspect") + ".json"
		token := cimdPrivateKeyJWTAccessToken(t, srvURL, clientID, key)

		status, body := postFormTo(t, srvURL, "/oauth2/token/introspect", url.Values{
			"token": {token}, "client_id": {clientID},
			"client_assertion": {cimdAssertionFor(t, key, clientID)}, "client_assertion_type": {clientAssertionType},
		}, nil)
		require.Equal(t, http.StatusUnauthorized, status,
			"an authenticated CIMD client must still not introspect: %v", body)
		assert.Equal(t, "invalid_client", body["error"])
		assert.NotContains(t, body, "active", "no token information may leak on refusal")
	})
}
