// Baseline for agents whose identity lives in a customer IdP or a hosting
// platform: what ZeroID supports TODAY on the standard paths that
// highflame-architecture ADR 0042 builds on.
//
// These tests pin CURRENT behaviour, gaps included. Each gap assertion is
// annotated "Flips with ADR 0042 Dx", naming the decision expected to change
// it. When a feature lands and a test here fails, update the assertion to the
// new behaviour in the same PR (and drop the note), rather than deleting the
// test. Assertions with no note are invariants the ADR keeps.
//
// Test names follow the ADR's paths (D3):
//
//   - P1a, interactive person: MCP authorization (authorization code + PKCE,
//     CIMD, RFC 8707) against ZeroID, with sign-in handed to a login surface.
//   - P1b, enterprise-managed person: an ID-JAG redeemed with jwt-bearer
//     (ADR 0010).
//   - P2, agent as itself: client_credentials with private_key_jwt, either
//     with a key the client registered or with a federated client assertion
//     from a trusted workload issuer (Kubernetes, AWS STS, SPIFFE, GitHub).
//
// The id_token exchange is a person path outside ADR 0042; its client binding
// (zeroid#385 D13) is pinned at the end of this file.
package integration_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/domain"
)

// ── self-contained RSA mock IdP ──────────────────────────────────────────────

// probeRSAIdP is a minimal RS256 issuer. It serves its JWKS at every path over
// TLS and counts every request it receives, so a test can show whether ZeroID
// contacted it at all.
type probeRSAIdP struct {
	srv  *httptest.Server
	priv *rsa.PrivateKey
	kid  string
	hits atomic.Int64
}

func newProbeRSAIdP(t *testing.T) *probeRSAIdP {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	idp := &probeRSAIdP{priv: priv, kid: "probe-rsa-1"}

	pub, err := jwk.Import[jwk.Key](&priv.PublicKey)
	require.NoError(t, err)
	require.NoError(t, pub.Set(jwk.KeyIDKey, idp.kid))
	require.NoError(t, pub.Set(jwk.AlgorithmKey, jwa.RS256()))
	set := jwk.NewSet()
	require.NoError(t, set.AddKey(pub))
	body, err := json.Marshal(set)
	require.NoError(t, err)

	idp.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		idp.hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(idp.srv.Close)
	return idp
}

func (i *probeRSAIdP) JWKSURL() string { return i.srv.URL }

func (i *probeRSAIdP) sign(t *testing.T, typ string, claims map[string]any) string {
	t.Helper()
	tok := jwt.New()
	for k, v := range claims {
		require.NoError(t, tok.Set(k, v))
	}
	hdr := jws.NewHeaders()
	require.NoError(t, hdr.Set(jws.KeyIDKey, i.kid))
	require.NoError(t, hdr.Set(jws.TypeKey, typ))
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), i.priv, jws.WithProtectedHeaders(hdr)))
	require.NoError(t, err)
	return string(signed)
}

// k8sSAToken mints a token shaped like a projected Kubernetes ServiceAccount
// token. Only the claims matter here; the issuer is whatever the caller gives.
func (i *probeRSAIdP) k8sSAToken(t *testing.T, iss, aud string) string {
	t.Helper()
	now := time.Now()
	return i.sign(t, "JWT", map[string]any{
		"iss": iss,
		"aud": aud,
		"sub": "system:serviceaccount:agents:invoice-bot",
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
		"kubernetes.io": map[string]any{
			"namespace":      "agents",
			"serviceaccount": map[string]any{"name": "invoice-bot", "uid": "b4c1-uid"},
		},
	})
}

// postSharedToken posts a JSON token request to the shared TestMain server and
// returns the status plus the decoded body.
func postSharedToken(t *testing.T, body map[string]any) (int, map[string]any) {
	t.Helper()
	resp := post(t, "/oauth2/token", body, nil)
	return resp.StatusCode, decode(t, resp)
}

// ── P1a: interactive person (MCP authorization against ZeroID) ──────────────

// TestIdPAgentBaseline_P1a_ASMetadataAdvertisement records what the RFC 8414
// document advertises on the shared server, which has PrincipalResolvers
// registered (so authorization_code is servable) but CIMD disabled.
//
// ZeroID's side of ADR 0042 D2's metadata list is already complete here; what
// D2 still needs is in Firehog, AuthN and Studio, not in this document.
func TestIdPAgentBaseline_P1a_ASMetadataAdvertisement(t *testing.T) {
	resp := get(t, "/.well-known/oauth-authorization-server", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	md := decode(t, resp)

	assert.ElementsMatch(t, []any{
		"authorization_code",
		"refresh_token",
		"client_credentials",
		"urn:ietf:params:oauth:grant-type:jwt-bearer",
		"urn:ietf:params:oauth:grant-type:token-exchange",
		"api_key",
		"urn:openid:params:grant-type:ciba",
	}, md["grant_types_supported"])
	// The shared server is built from a struct literal, so cimd.enabled keeps
	// its Go zero value (false) instead of the koanf default (true). CIMD is
	// therefore NOT advertised here. See the CIMD-enabled server below.
	assert.NotContains(t, md, "client_id_metadata_document_supported")
	assert.Equal(t, []any{"urn:ietf:params:oauth:grant-profile:id-jag"}, md["authorization_grant_profiles_supported"])
	assert.ElementsMatch(t, []any{"client_secret_post", "client_secret_basic", "private_key_jwt", "none"},
		md["token_endpoint_auth_methods_supported"])
	assert.Subset(t, md["token_endpoint_auth_signing_alg_values_supported"], []any{"ES256", "RS256"},
		"private_key_jwt clients learn which algorithms to sign with")
	assert.Equal(t, []any{"code"}, md["response_types_supported"])
	assert.Equal(t, []any{"S256"}, md["code_challenge_methods_supported"])

	// ZeroID is not an OpenID Provider: response_types_supported carries only
	// "code" (asserted above) and there is no scopes_supported naming "openid".
	assert.NotContains(t, md, "scopes_supported")

	t.Run("CIMD-enabled server with a resolver advertises CIMD", func(t *testing.T) {
		_, docClient := newCIMDDocumentOrigin(t, `{}`)
		cimdSrv := newCIMDZeroID(t, docClient)
		r, err := http.Get(cimdSrv.URL + "/.well-known/oauth-authorization-server")
		require.NoError(t, err)
		defer func() { _ = r.Body.Close() }()
		require.Equal(t, http.StatusOK, r.StatusCode)
		var cmd map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&cmd))
		assert.Equal(t, true, cmd["client_id_metadata_document_supported"])
		assert.Contains(t, cmd["grant_types_supported"], "authorization_code")
	})
}

// TestIdPAgentBaseline_P1a_ASMetadataWithoutResolver shows that configuring an
// external (Okta) issuer does not make the authorization_code flow servable.
// That flow depends only on whether a PrincipalResolver is registered.
func TestIdPAgentBaseline_P1a_ASMetadataWithoutResolver(t *testing.T) {
	okta := newProbeRSAIdP(t)
	fedSrv, fedHTTP, _ := newFederationServer(t, domain.ExternalIssuerConfig{
		Issuer:          "https://probe-okta-md.example.test",
		JWKSURI:         okta.JWKSURL(),
		Audience:        "https://zeroid.probe.test",
		ClaimMapping:    map[string]string{"user_id": "sub"},
		AllowedAccounts: []string{"acct-fed-001"},
	})
	defer fedHTTP.Close()
	defer func() { _ = fedSrv.Shutdown(context.Background()) }()

	resp, err := http.Get(fedHTTP.URL + "/.well-known/oauth-authorization-server")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var md map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&md))

	require.Contains(t, md, "grant_types_supported", "the document is populated")
	assert.NotContains(t, md["grant_types_supported"], "authorization_code",
		"with an external issuer configured but no resolver, authorization_code is NOT advertised")
	assert.NotContains(t, md, "client_id_metadata_document_supported",
		"CIMD rides the authorization_code gate")
	assert.NotContains(t, md, "response_types_supported")
	assert.Equal(t, []any{"urn:ietf:params:oauth:grant-profile:id-jag"}, md["authorization_grant_profiles_supported"])
}

// TestIdPAgentBaseline_P1a_AuthorizeDoesNotFederateLogin covers what a standard
// MCP client (a browser GET with no Highflame credential) gets from
// /oauth2/authorize. ZeroID never redirects the browser to an upstream OIDC
// IdP itself. The sign-in hand-off ADR 0042 D2 relies on is a resolver
// returning ErrPrincipalInteractionRequired, which sends the browser to the
// deployer's login surface (SetInteractiveLoginURL); that hand-off is covered
// by oauth_authorize_interactive_test.go.
func TestIdPAgentBaseline_P1a_AuthorizeDoesNotFederateLogin(t *testing.T) {
	t.Run("shared server: credential-less browser GET is refused back to the client", func(t *testing.T) {
		query, _ := authorizeGETQuery(t)
		resp := getAuthorize(t, query, nil)
		defer func() { _ = resp.Body.Close() }()

		require.Equal(t, http.StatusFound, resp.StatusCode)
		loc := resp.Header.Get("Location")
		u, err := url.Parse(loc)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(loc, testRedirectURI+"?"), "redirect goes back to the client only, got %q", loc)
		assert.Equal(t, "access_denied", u.Query().Get("error"))
		assert.Empty(t, u.Query().Get("code"))
	})

	t.Run("federation server: an external issuer configured, no resolver, gives 503 and never contacts the IdP", func(t *testing.T) {
		okta := newProbeRSAIdP(t)
		fedSrv, fedHTTP, _ := newFederationServer(t, domain.ExternalIssuerConfig{
			Issuer:          "https://probe-okta-authz.example.test",
			JWKSURI:         okta.JWKSURL(),
			Audience:        "https://zeroid.probe.test",
			ClaimMapping:    map[string]string{"user_id": "sub"},
			AllowedAccounts: []string{"acct-fed-001"},
		})
		defer fedHTTP.Close()
		defer func() { _ = fedSrv.Shutdown(context.Background()) }()

		// Measured as a delta so a JWKS prefetch at server start (if one is
		// ever added) cannot make this flaky.
		before := okta.hits.Load()
		query, _ := authorizeGETQuery(t)
		noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := noRedirect.Get(fedHTTP.URL + "/oauth2/authorize?" + query.Encode())
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
		assert.Empty(t, resp.Header.Get("Location"), "no redirect to an upstream authorization endpoint")
		assert.Equal(t, before, okta.hits.Load(), "ZeroID did not contact the configured IdP while serving authorize")
	})
}

// ── P2: the agent acts as itself ─────────────────────────────────────────────

// TestIdPAgentBaseline_P2_WorkloadJWTOnUnconfiguredServer presents a
// k8s-SA-shaped JWT through the RFC 7523 and RFC 8693 grant shapes on the
// shared server, which has NO external issuers configured, and records the
// error each returns. None of these grants is where ADR 0042 P2 lands (P2 is
// client_credentials with a federated client assertion), so these refusals
// are invariants, not gaps.
func TestIdPAgentBaseline_P2_WorkloadJWTOnUnconfiguredServer(t *testing.T) {
	k8s := newProbeRSAIdP(t)
	const k8sIss = "https://oidc.eks.us-east-1.amazonaws.com/id/PROBE"
	saTok := k8s.k8sSAToken(t, k8sIss, testIssuer)

	cases := []struct {
		name     string
		body     map[string]any
		wantCode int
		wantErr  string
	}{
		{
			name: "jwt-bearer (RFC 7523 §2.1) with workload JWT",
			body: map[string]any{
				"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
				"assertion":  saTok,
			},
			wantCode: http.StatusBadRequest, wantErr: "invalid_grant", // iss is not a WIMSE URI
		},
		{
			name: "token-exchange subject_token_type=jwt",
			body: map[string]any{
				"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
				"subject_token":      saTok,
				"subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
				"account_id":         testAccountID,
				"project_id":         testProjectID,
			},
			wantCode: http.StatusBadRequest, wantErr: "invalid_grant", // broker arm, caller is not a trusted service
		},
		{
			name: "token-exchange subject_token_type=access_token",
			body: map[string]any{
				"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
				"subject_token":      saTok,
				"subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
				"account_id":         testAccountID,
				"project_id":         testProjectID,
			},
			wantCode: http.StatusBadRequest, wantErr: "invalid_grant", // broker arm, caller is not a trusted service
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body := postSharedToken(t, tc.body)
			t.Logf("status=%d error=%v description=%v", code, body["error"], body["error_description"])
			assert.Equal(t, tc.wantCode, code)
			assert.Equal(t, tc.wantErr, body["error"])
			assert.Empty(t, body["access_token"])
		})
	}
}

// TestIdPAgentBaseline_P2_WorkloadJWTWithIssuerConfigured configures a workload
// platform (Kubernetes) as an external issuer and checks that no grant treats
// its tokens as a workload credential today.
func TestIdPAgentBaseline_P2_WorkloadJWTWithIssuerConfigured(t *testing.T) {
	k8s := newProbeRSAIdP(t)
	const k8sIss = "https://oidc.eks.us-east-1.amazonaws.com/id/PROBEFED"
	const aud = "https://zeroid.probe-wif.test"
	// The federation server's own issuer, which is where an RFC 7523 §2.2
	// client assertion is addressed.
	const fedIssuer = "https://federation.zeroid.test"

	fedSrv, fedHTTP, fedCfg := newFederationServer(t, domain.ExternalIssuerConfig{
		Issuer:          k8sIss,
		JWKSURI:         k8s.JWKSURL(),
		Audience:        aud,
		ClaimMapping:    map[string]string{"user_id": "sub"},
		AllowedAccounts: []string{"acct-fed-001"},
	})
	defer fedHTTP.Close()
	defer func() { _ = fedSrv.Shutdown(context.Background()) }()

	// Flips with ADR 0042 D8 (federated client assertions from a trusted
	// workload issuer, a D4 row, mapped to the agent through a D6 binding on
	// sub). Today a client assertion verifies only against keys a client
	// registered, so a platform-signed one is refused.
	t.Run("client_credentials with the k8s SA token as a federated client assertion is refused", func(t *testing.T) {
		resp := postFederation(t, fedHTTP.URL, map[string]any{
			"grant_type":            "client_credentials",
			"client_assertion":      k8s.k8sSAToken(t, k8sIss, fedIssuer),
			"client_assertion_type": clientAssertionType,
			"account_id":            fedCfg.AccountID,
			"project_id":            fedCfg.ProjectID,
		})
		t.Logf("status=%d body=%s", resp.StatusCode, resp.RawBody)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Equal(t, "invalid_client", resp.Error)
		assert.Empty(t, resp.AccessToken)
	})

	t.Run("jwt-bearer with the k8s SA token is refused (only ID-JAGs take the external-issuer arm)", func(t *testing.T) {
		resp := postFederation(t, fedHTTP.URL, map[string]any{
			"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
			"assertion":  k8s.k8sSAToken(t, k8sIss, aud),
			"account_id": fedCfg.AccountID,
			"project_id": fedCfg.ProjectID,
		})
		t.Logf("status=%d body=%s", resp.StatusCode, resp.RawBody)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Equal(t, "invalid_grant", resp.Error)
		assert.Empty(t, resp.AccessToken)
	})

	t.Run("token-exchange subject_token_type=jwt with the k8s SA token is refused (broker arm)", func(t *testing.T) {
		resp := postFederation(t, fedHTTP.URL, map[string]any{
			"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
			"subject_token":      k8s.k8sSAToken(t, k8sIss, aud),
			"subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
			"account_id":         fedCfg.AccountID,
			"project_id":         fedCfg.ProjectID,
		})
		t.Logf("status=%d body=%s", resp.StatusCode, resp.RawBody)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Equal(t, "invalid_grant", resp.Error)
		assert.Empty(t, resp.AccessToken)
	})
}

// TestIdPAgentBaseline_P2_ClientCredentialsPrivateKeyJWT covers P2 with a key
// the client registered.
func TestIdPAgentBaseline_P2_ClientCredentialsPrivateKeyJWT(t *testing.T) {
	clientID := uid("probe-cc-pkjwt")
	key := generateKey(t)

	// client_credentials resolves the identity by external_id == client_id
	// inside the request's tenant, so the agent identity must exist first.
	ident := registerIdentity(t, clientID, []string{"data:read", "tools:exec"})

	reg := post(t, adminPath("/oauth/clients"), map[string]any{
		"client_id":                  clientID,
		"name":                       clientID + "-client",
		"confidential":               false,
		"token_endpoint_auth_method": "private_key_jwt",
		"jwks":                       clientJWKS(t, key),
		"grant_types":                []string{"client_credentials"},
		"scopes":                     []string{"data:read", "tools:exec"},
	}, nil)
	require.Equal(t, http.StatusCreated, reg.StatusCode)
	regBody := decode(t, reg)
	assert.Empty(t, regBody["client_secret"], "a key-based client gets no secret (ADR 0042 D8: no secrets for agents)")

	const mcpResource = "https://gw.example.test/mcp/github"

	t.Run("registered jwks + client_assertion mints, binds resource", func(t *testing.T) {
		code, body := postSharedToken(t, map[string]any{
			"grant_type":            "client_credentials",
			"client_id":             clientID,
			"client_assertion":      clientAssertionFor(t, key, clientID),
			"client_assertion_type": clientAssertionType,
			"account_id":            testAccountID,
			"project_id":            testProjectID,
			"scope":                 "data:read",
			"resource":              mcpResource,
		})
		require.Equal(t, http.StatusOK, code, "body=%v", body)
		at, _ := body["access_token"].(string)
		c := decodeIssuedTokenClaims(t, at)
		t.Logf("claims=%v", c)

		assert.Equal(t, clientID, c["external_id"])
		assert.Equal(t, ident.WIMSEURI, c["sub"])
		assert.Equal(t, testAccountID, c["account_id"])
		assert.Equal(t, testProjectID, c["project_id"])
		assert.Equal(t, "client_credentials", c["grant_type"])
		assert.ElementsMatch(t, []any{mcpResource}, c["resource"])
		assert.ElementsMatch(t, []any{mcpResource}, c["aud"])
		assert.ElementsMatch(t, []any{"data:read"}, c["scopes"])
	})

	// Flips with ADR 0042 D5: with a registered key, the tenant comes from the
	// client's registration.
	t.Run("account_id/project_id are mandatory request params (tenant is not derived from the client)", func(t *testing.T) {
		code, body := postSharedToken(t, map[string]any{
			"grant_type":            "client_credentials",
			"client_id":             clientID,
			"client_assertion":      clientAssertionFor(t, key, clientID),
			"client_assertion_type": clientAssertionType,
		})
		t.Logf("status=%d body=%v", code, body)
		assert.Equal(t, http.StatusBadRequest, code)
		assert.Equal(t, "invalid_request", body["error"])
	})

	t.Run("client_id omitted: iss of the assertion identifies the client", func(t *testing.T) {
		code, body := postSharedToken(t, map[string]any{
			"grant_type":            "client_credentials",
			"client_assertion":      clientAssertionFor(t, key, clientID),
			"client_assertion_type": clientAssertionType,
			"account_id":            testAccountID,
			"project_id":            testProjectID,
		})
		require.Equal(t, http.StatusOK, code, "body=%v", body)
		at, _ := body["access_token"].(string)
		assert.Equal(t, clientID, decodeIssuedTokenClaims(t, at)["external_id"])
	})

	// Not a gap: D8's federated assertions carry the workload issuer as iss
	// (see TestIdPAgentBaseline_P2_WorkloadJWTWithIssuerConfigured). An
	// assertion claiming to BE the client must verify against the client's
	// own keys, now and after ADR 0042.
	t.Run("a client_assertion signed by a key outside the client's registration is refused", func(t *testing.T) {
		other := newProbeRSAIdP(t)
		now := time.Now()
		assertion := other.sign(t, "JWT", map[string]any{
			"iss": clientID, "sub": clientID, "aud": testIssuer,
			"iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(), "jti": uid("foreign-cla"),
		})
		code, body := postSharedToken(t, map[string]any{
			"grant_type":            "client_credentials",
			"client_id":             clientID,
			"client_assertion":      assertion,
			"client_assertion_type": clientAssertionType,
			"account_id":            testAccountID,
			"project_id":            testProjectID,
		})
		assert.Equal(t, http.StatusUnauthorized, code)
		assert.Equal(t, "invalid_client", body["error"])
		assert.Empty(t, body["access_token"])
	})
}

// TestIdPAgentBaseline_P2_CIMDClientCredentials runs on a CIMD-enabled server
// (on the shared one, with CIMD off, the refusal would say nothing about
// CIMD). The client publishes private_key_jwt keys and declares
// client_credentials in its metadata document. client_credentials
// authenticates registry rows only and never resolves a metadata document, so
// the CIMD URL is an unknown client; CIMD synthesis also drops
// client_credentials from the declared grants. The same document shape
// completes authorization_code (TestCIMD_PrivateKeyJWTClient).
//
// Flips with ADR 0042 D8: CIMD clients gain client_credentials.
func TestIdPAgentBaseline_P2_CIMDClientCredentials(t *testing.T) {
	key := generateKey(t)
	jwks, err := json.Marshal(clientJWKS(t, key))
	require.NoError(t, err)
	doc := fmt.Sprintf(`{
		"client_id": "%%CLIENT_ID%%",
		"client_name": "cimd client_credentials probe",
		"redirect_uris": [%q],
		"grant_types": ["authorization_code", "client_credentials"],
		"token_endpoint_auth_method": "private_key_jwt",
		"jwks": %s
	}`, cimdTestRedirectURI, jwks)
	base, docClient := newCIMDDocumentOrigin(t, doc)
	srvURL := newCIMDZeroID(t, docClient).URL
	clientID := base + "/.well-known/oauth-client"

	resp := postFederation(t, srvURL, map[string]any{
		"grant_type":            "client_credentials",
		"client_id":             clientID,
		"client_assertion":      cimdAssertionFor(t, key, clientID),
		"client_assertion_type": clientAssertionType,
		"account_id":            testAccountID,
		"project_id":            testProjectID,
	})
	t.Logf("status=%d body=%s", resp.StatusCode, resp.RawBody)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, "invalid_client", resp.Error)
	assert.Empty(t, resp.AccessToken)
}

// ── P1b: ID-JAG (ADR 0010) identity and tenant semantics ────────────────────

func TestIdPAgentBaseline_P1b_IDJAGIdentityAndTenantSemantics(t *testing.T) {
	upstreamIss := "https://okta.probe-idjag.test"
	federationAud := "https://zeroid.probe-idjag.test"
	const mcpResource = "https://mcp.probe-idjag.test"

	upstream := newFakeUpstreamIdP(t)
	defer upstream.Close()

	fedSrv, fedHTTP, fedCfg := newFederationServer(t, domain.ExternalIssuerConfig{
		Issuer:          upstreamIss,
		JWKSURI:         upstream.JWKSURL(),
		Audience:        federationAud,
		ClaimMapping:    map[string]string{"user_id": "sub", "email": "email"},
		AllowedAccounts: []string{"acct-fed-001", "acct-fed-002"},
	})
	defer fedHTTP.Close()
	defer func() { _ = fedSrv.Shutdown(context.Background()) }()

	// ADR 0042 D5: the client's registration carries the tenant (it links an
	// identity in acct-fed-001), which is how the grant derives it.
	client := registerTenantBoundClient(t, fedCfg.AccountID, fedCfg.ProjectID, []string{"tools:read"})

	sign := func(t *testing.T, extra map[string]any) string {
		t.Helper()
		now := time.Now()
		claims := map[string]any{
			"iss":       upstreamIss,
			"aud":       federationAud,
			"sub":       "00uAGENTPROBE",
			"client_id": client.ClientID,
			"jti":       uid("probe-idjag-jti"),
			"resource":  mcpResource,
			"scope":     "tools:read",
			"iat":       now.Unix(),
			"exp":       now.Add(5 * time.Minute).Unix(),
		}
		for k, v := range extra {
			claims[k] = v
		}
		return upstream.SignTokenWithTyp(t, idJAGTyp, claims)
	}
	body := func(idjag, acct, proj string) map[string]any {
		return map[string]any{
			"grant_type":    "urn:ietf:params:oauth:grant-type:jwt-bearer",
			"assertion":     idjag,
			"account_id":    acct,
			"project_id":    proj,
			"client_id":     client.ClientID,
			"client_secret": client.ClientSecret,
		}
	}

	// Flips with ADR 0042 D6: the ID-JAG maps through a binding on act.sub to
	// the agent's own identity row, and no binding means invalid_grant rather
	// than a synthetic identity.
	t.Run("no application_id: synthetic identity", func(t *testing.T) {
		resp := postFederation(t, fedHTTP.URL, body(sign(t, map[string]any{"email": "agent@corp.example"}),
			fedCfg.AccountID, fedCfg.ProjectID))
		require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)
		c := decodeIssuedTokenClaims(t, resp.AccessToken)
		t.Logf("claims=%v", c)

		assert.Equal(t, "00uAGENTPROBE", c["sub"], "sub is the IdP subject, not a WIMSE URI")
		assert.Equal(t, "", c["external_id"], "no registered identity: external_id empty")
		assert.Equal(t, "service", c["identity_type"])
		assert.Equal(t, fedCfg.AccountID, c["account_id"])
		assert.Equal(t, fedCfg.ProjectID, c["project_id"])
		assert.Equal(t, "id_jag", c["token_exchange"])
		assert.NotContains(t, c, "identity_id")
		// zeroid#385 D8: the authenticated redeeming client is named on the token.
		assert.Equal(t, client.ClientID, c["client_id"])
		// zeroid#385 D9: RFC 9068 at+jwt typ.
		assertAccessTokenTyp(t, resp.AccessToken)
	})

	t.Run("account_id not in allowed_accounts is refused", func(t *testing.T) {
		resp := postFederation(t, fedHTTP.URL, body(sign(t, nil), "acct-not-allowed", "proj-x"))
		t.Logf("status=%d body=%s", resp.StatusCode, resp.RawBody)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Equal(t, "invalid_grant", resp.Error)
		assert.Empty(t, resp.AccessToken)
	})

	// ADR 0042 D5: with two allowed accounts the request still cannot choose.
	// Naming the OTHER admitted account is a mismatch, not a selection.
	t.Run("naming another allowed account is refused", func(t *testing.T) {
		resp := postFederation(t, fedHTTP.URL, body(sign(t, nil), "acct-fed-002", fedCfg.ProjectID))
		t.Logf("status=%d body=%s", resp.StatusCode, resp.RawBody)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Equal(t, "invalid_grant", resp.Error)
		assert.Empty(t, resp.AccessToken)
	})

	// Two allowed accounts and a client that names no tenant: ambiguous, so
	// refused, whatever the request says.
	t.Run("several allowed accounts and no client tenant is refused", func(t *testing.T) {
		unlinked := registerOAuthClient(t, uid("probe-idjag-unlinked"), []string{"tools:read"})
		resp := postFederation(t, fedHTTP.URL, map[string]any{
			"grant_type":    "urn:ietf:params:oauth:grant-type:jwt-bearer",
			"assertion":     sign(t, map[string]any{"client_id": unlinked.ClientID}),
			"account_id":    fedCfg.AccountID,
			"project_id":    fedCfg.ProjectID,
			"client_id":     unlinked.ClientID,
			"client_secret": unlinked.ClientSecret,
		})
		t.Logf("status=%d body=%s", resp.StatusCode, resp.RawBody)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Equal(t, "invalid_grant", resp.Error)
		assert.Empty(t, resp.AccessToken)
	})

	// ADR 0042 D3 leaves this open: ZeroID MAY accept a sub_profile=service
	// ID-JAG if Okta documents third-party issuance, under D4-D7.
	t.Run("sub_profile=service is accepted (not inspected)", func(t *testing.T) {
		resp := postFederation(t, fedHTTP.URL, body(sign(t, map[string]any{"sub_profile": "service"}),
			fedCfg.AccountID, fedCfg.ProjectID))
		require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)
		c := decodeIssuedTokenClaims(t, resp.AccessToken)
		assert.NotContains(t, c, "sub_profile", "sub_profile is not propagated")
		assert.Equal(t, "service", c["identity_type"], "identity_type is service regardless")
	})

	t.Run("no email claim is accepted", func(t *testing.T) {
		resp := postFederation(t, fedHTTP.URL, body(sign(t, nil), fedCfg.AccountID, fedCfg.ProjectID))
		require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)
		c := decodeIssuedTokenClaims(t, resp.AccessToken)
		assert.NotContains(t, c, "user_email")
	})
}

// ── id_token exchange (a person path, outside ADR 0042) ─────────────────────

// TestIdPAgentBaseline_IDTokenExchange_RejectsForeignAudience pins the
// relying-party rules on the id_token exchange: the redeeming client must
// authenticate, and the ID token must be addressed to ZeroID's configured
// audience and issued to that client (zeroid#385 D13). An Okta ID token minted
// for some other relying party is refused even when a client authenticates.
func TestIdPAgentBaseline_IDTokenExchange_RejectsForeignAudience(t *testing.T) {
	upstreamIss := "https://okta.probe-aud.test"
	federationAud := "https://zeroid.probe-aud.test"

	upstream := newFakeUpstreamIdP(t)
	defer upstream.Close()
	fedSrv, fedHTTP, fedCfg := newFederationServer(t, domain.ExternalIssuerConfig{
		Issuer:          upstreamIss,
		JWKSURI:         upstream.JWKSURL(),
		Audience:        federationAud,
		ClaimMapping:    map[string]string{"user_id": "sub"},
		AllowedAccounts: []string{"acct-fed-001"},
	})
	defer fedHTTP.Close()
	defer func() { _ = fedSrv.Shutdown(context.Background()) }()

	// The relying party: a registered client whose client_id is the audience
	// the IdP issues ID tokens to.
	rp := rpClient(t, federationAud)

	idToken := func(aud string) string {
		now := time.Now()
		return upstream.SignToken(t, map[string]any{
			"iss": upstreamIss, "aud": aud, "sub": "00uAUDPROBE",
			"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		})
	}
	exchange := func(tok string, client *oauthClientResp) tokenResponse {
		body := map[string]any{
			"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
			"subject_token":      tok,
			"subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
			"account_id":         fedCfg.AccountID,
			"project_id":         fedCfg.ProjectID,
		}
		if client != nil {
			body["client_id"] = client.ClientID
			body["client_secret"] = client.ClientSecret
		}
		return postFederation(t, fedHTTP.URL, body)
	}

	t.Run("foreign audience is refused, even with client authentication", func(t *testing.T) {
		foreign := exchange(idToken("0oaSOMEOTHERAPP"), &rp)
		t.Logf("status=%d body=%s", foreign.StatusCode, foreign.RawBody)
		assert.Equal(t, http.StatusBadRequest, foreign.StatusCode)
		assert.Equal(t, "invalid_grant", foreign.Error)
		assert.Empty(t, foreign.AccessToken)
	})

	t.Run("an unauthenticated exchange is refused", func(t *testing.T) {
		anon := exchange(idToken(federationAud), nil)
		t.Logf("status=%d body=%s", anon.StatusCode, anon.RawBody)
		assert.Equal(t, http.StatusUnauthorized, anon.StatusCode)
		assert.Equal(t, "invalid_client", anon.Error)
		assert.Empty(t, anon.AccessToken)
	})

	t.Run("control: addressed to ZeroID, redeemed by the client it was issued to", func(t *testing.T) {
		ok := exchange(idToken(federationAud), &rp)
		require.Equal(t, http.StatusOK, ok.StatusCode, "body=%s", ok.RawBody)
		c := decodeIssuedTokenClaims(t, ok.AccessToken)
		assert.Equal(t, "00uAUDPROBE", c["sub"])
		assert.Equal(t, upstreamIss, c["user_id_iss"])
		assert.Equal(t, "external_id_token", c["token_exchange"])
		assert.Equal(t, rp.ClientID, c["client_id"], "zeroid#385 D8: the relying party is named on the token")
	})
}
