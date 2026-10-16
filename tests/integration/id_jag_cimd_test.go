// ID-JAG redemption by a Client ID Metadata Document client (firehog#701).
//
// MCP Enterprise-Managed Authorization §5: "If the MCP Client is not
// pre-registered with the Resource Authorization Server, then it can use its
// Client ID Metadata Document as its client ID, and optionally authenticate
// using private_key_jwt."
//
// What lands here, and what does not. A CIMD client now RESOLVES on this grant,
// is held to private_key_jwt against its document's key, must not contradict an
// ID-JAG profile claim (draft §8), and is bound to the ID-JAG's client_id claim.
// It need not list jwt-bearer: the grant list is its own unauthenticated claim. It then stops at the tenant:
// ADR 0042 D5 derives the project from the identity the credential maps to
// (D6), and no (issuer, client_id) → identity binding exists yet. So the best
// a CIMD client can reach today is a clean invalid_grant naming the missing
// binding, which is what the acceptance subtest pins. Each refusal below
// carries a distinct message, so the test proves WHICH gate fired.
package integration_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	zeroid "github.com/highflame-ai/zeroid"
	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/pkg/authjwt"
)

// newCIMDDocumentsOrigin serves a different metadata document per path, over
// TLS. Each document's client_id is filled in with its own URL (CIMD §4).
func newCIMDDocumentsOrigin(t *testing.T, docs map[string]string) (base string, client *http.Client) {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc, ok := docs[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, strings.ReplaceAll(doc, "%CLIENT_ID%", "https://"+r.Host+r.URL.Path))
	}))
	t.Cleanup(ts.Close)
	return ts.URL, ts.Client()
}

// newIDJAGCIMDServer is a ZeroID with both an external issuer (for ID-JAGs)
// and CIMD enabled (for the redeeming client), its document fetcher trusting
// the test origin. Its token issuer is cimdTestIssuer, so cimdAssertionFor
// produces client assertions it accepts.
func newIDJAGCIMDServer(t *testing.T, issuer domain.ExternalIssuerConfig, docClient *http.Client, cimdEnabled bool) *httptest.Server {
	t.Helper()
	require.NoError(t, initFederationKeyMaterial(), "init key material")
	cfg := zeroid.Config{
		Server:   zeroid.ServerConfig{Port: "0", Env: "test", ShutdownTimeoutSeconds: 5},
		Database: zeroid.DatabaseConfig{URL: sharedDBURL, MaxOpenConns: 5, MaxIdleConns: 2},
		Keys: zeroid.KeysConfig{
			PrivateKeyPath:    fedKeyPaths.privPath,
			PublicKeyPath:     fedKeyPaths.pubPath,
			KeyID:             "idjag-cimd-key-1",
			RSAPrivateKeyPath: fedKeyPaths.rsaPriv,
			RSAPublicKeyPath:  fedKeyPaths.rsaPub,
			RSAKeyID:          "idjag-cimd-rsa-1",
		},
		Token: zeroid.TokenConfig{
			Issuer:         cimdTestIssuer,
			DefaultTTL:     3600,
			MaxTTL:         90 * 24 * 3600,
			HMACSecret:     testHMACSecret,
			AuthCodeIssuer: cimdTestIssuer,
		},
		CIMD:            zeroid.CIMDConfig{Enabled: cimdEnabled},
		Telemetry:       zeroid.TelemetryConfig{Enabled: false},
		Logging:         zeroid.LoggingConfig{Level: "warn"},
		WIMSEDomain:     testWIMSE,
		ExternalIssuers: []domain.ExternalIssuerConfig{issuer},
	}
	insecure := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // test IdP
	}
	srv, err := zeroid.NewServer(cfg,
		zeroid.WithCIMDHTTPClient(docClient),
		zeroid.WithExternalIssuerJWKSOption(authjwt.WithHTTPClient(insecure)))
	require.NoError(t, err, "build ID-JAG + CIMD server")
	httpSrv := httptest.NewServer(srv.Router())
	t.Cleanup(httpSrv.Close)
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	return httpSrv
}

// idJAGCIMDDoc renders a metadata document. grants and profiles are JSON
// fragments; key is published inline when method is private_key_jwt.
func idJAGCIMDDoc(t *testing.T, method string, key *ecdsa.PrivateKey, grants, profiles []string) string {
	t.Helper()
	g, err := json.Marshal(grants)
	require.NoError(t, err)
	extra := ""
	if key != nil {
		jwks, err := json.Marshal(clientJWKS(t, key))
		require.NoError(t, err)
		extra += fmt.Sprintf(`, "jwks": %s`, jwks)
	}
	if profiles != nil {
		p, err := json.Marshal(profiles)
		require.NoError(t, err)
		extra += fmt.Sprintf(`, "authorization_grant_profiles_supported": %s`, p)
	}
	return fmt.Sprintf(`{
		"client_id": "%%CLIENT_ID%%",
		"client_name": "ID-JAG CIMD client",
		"redirect_uris": [%q],
		"grant_types": %s,
		"token_endpoint_auth_method": %q%s
	}`, cimdTestRedirectURI, g, method, extra)
}

func TestIDJAG_CIMDClient(t *testing.T) {
	const (
		upstreamIss   = "https://corp-idp.idjag-cimd.test"
		federationAud = "https://zeroid.idjag-cimd.test"
		mcpResource   = "https://mcp-server.idjag-cimd.test"
		jwtBearer     = "urn:ietf:params:oauth:grant-type:jwt-bearer"
		tokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
		idJAGProfile  = "urn:ietf:params:oauth:grant-profile:id-jag"
		allowedAcct   = "acct-fed-001"
		allowedProj   = "proj-fed-001"
	)

	upstream := newFakeUpstreamIdP(t)
	defer upstream.Close()
	issuer := domain.ExternalIssuerConfig{
		Issuer:          upstreamIss,
		JWKSURI:         upstream.JWKSURL(),
		Audience:        federationAud,
		ClaimMapping:    map[string]string{"user_id": "sub"},
		AllowedAccounts: []string{allowedAcct},
	}

	key := generateKey(t)
	otherKey := generateKey(t)
	base, docClient := newCIMDDocumentsOrigin(t, map[string]string{
		"/fit.json":    idJAGCIMDDoc(t, "private_key_jwt", key, []string{"authorization_code", jwtBearer}, nil),
		"/public.json": idJAGCIMDDoc(t, "none", nil, []string{"authorization_code", jwtBearer}, nil),
		// WSO2 MCP playground's shape: no jwt-bearer, no profile claim.
		"/no-bearer.json": idJAGCIMDDoc(t, "private_key_jwt", key,
			[]string{"authorization_code", "refresh_token", "client_credentials"}, nil),
		"/profile-ok.json": idJAGCIMDDoc(t, "private_key_jwt", key, []string{"authorization_code", tokenExchange, jwtBearer}, []string{idJAGProfile}),
		"/profile-bad.json": idJAGCIMDDoc(t, "private_key_jwt", key,
			[]string{"authorization_code", jwtBearer}, []string{idJAGProfile}),
	})
	srvURL := newIDJAGCIMDServer(t, issuer, docClient, true).URL

	idjagFor := func(t *testing.T, clientIDClaim string) string {
		t.Helper()
		now := time.Now()
		return upstream.SignTokenWithTyp(t, idJAGTyp, map[string]any{
			"iss":       upstreamIss,
			"aud":       federationAud,
			"sub":       uid("00uCIMD"),
			"client_id": clientIDClaim,
			"jti":       uid("idjag-cimd-jti"),
			"resource":  mcpResource,
			"scope":     "tools:read",
			"iat":       now.Unix(),
			"exp":       now.Add(5 * time.Minute).Unix(),
		})
	}
	// The EMA §5 request shape: grant_type, assertion, client_id, plus the
	// private_key_jwt client assertion. No tenant fields.
	redeem := func(t *testing.T, clientID, idjag string, signer *ecdsa.PrivateKey, extra map[string]any) tokenResponse {
		t.Helper()
		body := map[string]any{
			"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
			"assertion":  idjag,
			"client_id":  clientID,
		}
		if signer != nil {
			body["client_assertion"] = cimdAssertionFor(t, signer, clientID)
			body["client_assertion_type"] = clientAssertionType
		}
		for k, v := range extra {
			body[k] = v
		}
		return postFederation(t, srvURL, body)
	}

	fit := base + "/fit.json"

	t.Run("acceptance today: a fit CIMD client passes every client gate, then stops at the missing D6 binding", func(t *testing.T) {
		resp := redeem(t, fit, idjagFor(t, fit), key, nil)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode, "body=%s", resp.RawBody)
		require.Equal(t, "invalid_grant", resp.Error, "body=%s", resp.RawBody)
		require.Contains(t, resp.RawBody, "no binding maps this client metadata document client",
			"the refusal must come from the tenant gate, i.e. after client auth, the document gates "+
				"and the client_id binding all passed")
		require.Empty(t, resp.AccessToken)
	})

	t.Run("naming an allowed tenant on the request does not supply one", func(t *testing.T) {
		resp := redeem(t, fit, idjagFor(t, fit), key, map[string]any{
			"account_id": allowedAcct, "project_id": allowedProj,
		})
		require.Equal(t, http.StatusBadRequest, resp.StatusCode, "body=%s", resp.RawBody)
		require.Equal(t, "invalid_grant", resp.Error, "body=%s", resp.RawBody)
		require.Contains(t, resp.RawBody, "no binding maps this client metadata document client")
		require.Empty(t, resp.AccessToken)
	})

	t.Run("naming a tenant the issuer does not allow is refused too", func(t *testing.T) {
		resp := redeem(t, fit, idjagFor(t, fit), key, map[string]any{
			"account_id": "acct-not-allowed", "project_id": "proj-x",
		})
		require.Equal(t, http.StatusBadRequest, resp.StatusCode, "body=%s", resp.RawBody)
		require.Equal(t, "invalid_grant", resp.Error, "body=%s", resp.RawBody)
		require.Empty(t, resp.AccessToken)
	})

	t.Run("ID-JAG client_id that is not the document URL is invalid_grant", func(t *testing.T) {
		resp := redeem(t, fit, idjagFor(t, base+"/someone-else.json"), key, nil)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode, "body=%s", resp.RawBody)
		require.Equal(t, "invalid_grant", resp.Error, "body=%s", resp.RawBody)
		require.Contains(t, resp.RawBody, "client_id does not match the authenticated client")
		require.Empty(t, resp.AccessToken)
	})

	t.Run("token_endpoint_auth_method none is refused", func(t *testing.T) {
		pub := base + "/public.json"
		resp := redeem(t, pub, idjagFor(t, pub), nil, nil)
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "body=%s", resp.RawBody)
		require.Equal(t, "invalid_client", resp.Error, "body=%s", resp.RawBody)
		require.Contains(t, resp.RawBody, "requires private_key_jwt")
		require.Empty(t, resp.AccessToken)
	})

	t.Run("private_key_jwt document without a client_assertion is refused", func(t *testing.T) {
		resp := redeem(t, fit, idjagFor(t, fit), nil, nil)
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "body=%s", resp.RawBody)
		require.Equal(t, "invalid_client", resp.Error, "body=%s", resp.RawBody)
		require.Empty(t, resp.AccessToken)
	})

	t.Run("a client_assertion signed by a key the document did not publish is refused", func(t *testing.T) {
		resp := redeem(t, fit, idjagFor(t, fit), otherKey, nil)
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "body=%s", resp.RawBody)
		require.Equal(t, "invalid_client", resp.Error, "body=%s", resp.RawBody)
		require.Empty(t, resp.AccessToken)
	})

	t.Run("a document that does not list jwt-bearer passes the client gates", func(t *testing.T) {
		nb := base + "/no-bearer.json"
		resp := redeem(t, nb, idjagFor(t, nb), key, nil)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode, "body=%s", resp.RawBody)
		require.Equal(t, "invalid_grant", resp.Error, "body=%s", resp.RawBody)
		require.Contains(t, resp.RawBody, "no binding maps this client metadata document client",
			"it must reach the tenant gate, i.e. pass every client gate")
		require.Empty(t, resp.AccessToken)
	})

	t.Run("a document claiming the ID-JAG profile without token-exchange is refused (draft §8)", func(t *testing.T) {
		bad := base + "/profile-bad.json"
		resp := redeem(t, bad, idjagFor(t, bad), key, nil)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode, "body=%s", resp.RawBody)
		require.Equal(t, "unauthorized_client", resp.Error, "body=%s", resp.RawBody)
		require.Empty(t, resp.AccessToken)
	})

	t.Run("a document claiming the profile with both grants reaches the tenant gate", func(t *testing.T) {
		ok := base + "/profile-ok.json"
		resp := redeem(t, ok, idjagFor(t, ok), key, nil)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode, "body=%s", resp.RawBody)
		require.Equal(t, "invalid_grant", resp.Error, "body=%s", resp.RawBody)
		require.Contains(t, resp.RawBody, "no binding maps this client metadata document client")
	})

	// CIMD §7.2 "Pre-Registering Client Identifier URLs": a registry row for the
	// URL wins over its document (resolveClientRegistryOrCIMD), and the row can
	// carry a tenant (#409). This is the path a CIMD-identified client can use
	// TODAY, until the D6 binding exists: the document is never fetched, the
	// key is the registered one, and the tenant comes from the row's identity.
	t.Run("a pre-registered Client Identifier URL with a tenant redeems (registry row wins)", func(t *testing.T) {
		pinned := base + "/pinned.json" // the origin serves no document here
		headers := map[string]string{"X-Account-ID": allowedAcct, "X-Project-ID": allowedProj}
		agent := registerIdentityIn(t, headers, uid("idjag-cimd-pinned"), []string{"tools:read"})
		jwks, err := json.Marshal(clientJWKS(t, key))
		require.NoError(t, err)
		created := post(t, adminPath("/oauth/clients"), map[string]any{
			"client_id":                  pinned,
			"name":                       "pinned CIMD URL",
			"token_endpoint_auth_method": "private_key_jwt",
			"jwks":                       json.RawMessage(jwks),
			"grant_types":                []string{jwtBearer},
			"identity_id":                agent.ID,
		}, headers)
		require.Equal(t, http.StatusCreated, created.StatusCode)
		_ = created.Body.Close()

		resp := redeem(t, pinned, idjagFor(t, pinned), key, nil)
		require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)
		claims := decodeIssuedTokenClaims(t, resp.AccessToken)
		require.Equal(t, allowedAcct, claims["account_id"])
		require.Equal(t, allowedProj, claims["project_id"])
		require.Equal(t, pinned, claims["client_id"])
	})

	t.Run("with CIMD disabled, a document URL is an unknown client, as before", func(t *testing.T) {
		disabled := newIDJAGCIMDServer(t, issuer, docClient, false).URL
		resp := postFederation(t, disabled, map[string]any{
			"grant_type":            "urn:ietf:params:oauth:grant-type:jwt-bearer",
			"assertion":             idjagFor(t, fit),
			"client_id":             fit,
			"client_assertion":      cimdAssertionFor(t, key, fit),
			"client_assertion_type": clientAssertionType,
		})
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "body=%s", resp.RawBody)
		require.Equal(t, "invalid_client", resp.Error, "body=%s", resp.RawBody)
		require.Contains(t, resp.RawBody, "invalid client credentials")
		require.Empty(t, resp.AccessToken)
	})
}
