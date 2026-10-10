// Baseline for agents whose identity lives in a customer IdP or a hosting
// platform: what ZeroID supports TODAY on the standard paths that
// highflame-architecture ADR 0042 builds on.
//
// These tests pin CURRENT behaviour, gaps included. Each gap assertion names
// the ADR 0042 decision that is expected to change it. When a feature lands
// and a test here fails, update the assertion to the new behaviour in the
// same PR (and drop the "flips with" note), rather than deleting the test.
//
//   - Path 1: MCP authorization (authorization code + PKCE, CIMD, RFC 8707),
//     where a person logs in at an upstream IdP.
//   - Path 2: the agent acts as itself with a platform-issued workload JWT
//     (Kubernetes, GitHub OIDC, AWS STS).
//   - Path 3: the agent acts as itself with client_credentials and
//     private_key_jwt (the MCP client-credentials extension).
//   - ID-JAG (ADR 0010): redemption identity semantics.
package integration_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
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

// probeRSAIdP is a minimal RS256 issuer. It serves its JWKS at the server root
// over TLS and counts every request it receives, so a probe can prove that
// ZeroID never contacted it for anything other than key material.
type probeRSAIdP struct {
	srv  *httptest.Server
	priv *rsa.PrivateKey
	kid  string
	hits atomic.Int64
	// nonJWKSHits counts requests for any path other than the JWKS root,
	// such as an /authorize a login-federating AS would redirect to.
	nonJWKSHits atomic.Int64
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

	idp.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idp.hits.Add(1)
		if r.URL.Path != "/" && r.URL.Path != "" {
			idp.nonJWKSHits.Add(1)
		}
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

// ── Path 1: standard MCP authorization with an upstream IdP login ───────────

// TestIdPAgentBaseline_Path1_ASMetadataAdvertisement records what the RFC 8414 document
// advertises on the shared server, which has PrincipalResolvers registered and
// CIMD enabled by default.
func TestIdPAgentBaseline_Path1_ASMetadataAdvertisement(t *testing.T) {
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
	assert.Equal(t, []any{"code"}, md["response_types_supported"])
	assert.Equal(t, []any{"S256"}, md["code_challenge_methods_supported"])

	// ZeroID is not an OpenID Provider. Nothing advertises an id_token
	// response type or an "openid" scope.
	assert.NotContains(t, md, "scopes_supported")

	t.Run("CIMD-enabled server with a resolver advertises CIMD", func(t *testing.T) {
		_, docClient := newCIMDDocumentOrigin(t, `{}`)
		cimdSrv := newCIMDZeroID(t, docClient)
		r, err := http.Get(cimdSrv.URL + "/.well-known/oauth-authorization-server")
		require.NoError(t, err)
		defer func() { _ = r.Body.Close() }()
		var cmd map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&cmd))
		assert.Equal(t, true, cmd["client_id_metadata_document_supported"])
		assert.Contains(t, cmd["grant_types_supported"], "authorization_code")
	})
}

// TestIdPAgentBaseline_Path1_ASMetadataWithoutResolver shows that configuring an external
// (Okta) issuer does not make the authorization_code flow servable. That flow
// depends only on whether a PrincipalResolver is registered.
func TestIdPAgentBaseline_Path1_ASMetadataWithoutResolver(t *testing.T) {
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
	var md map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&md))

	assert.NotContains(t, md["grant_types_supported"], "authorization_code",
		"with an external issuer configured but no resolver, authorization_code is NOT advertised")
	assert.NotContains(t, md, "client_id_metadata_document_supported",
		"CIMD rides the authorization_code gate")
	assert.NotContains(t, md, "response_types_supported")
	assert.Equal(t, []any{"urn:ietf:params:oauth:grant-profile:id-jag"}, md["authorization_grant_profiles_supported"])
}

// TestIdPAgentBaseline_Path1_AuthorizeDoesNotFederateLogin covers what a standard MCP
// client (a browser GET with no Highflame credential) gets from
// /oauth2/authorize. No arm redirects the user to the upstream OIDC IdP.
func TestIdPAgentBaseline_Path1_AuthorizeDoesNotFederateLogin(t *testing.T) {
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	t.Run("shared server: credential-less browser GET is refused, not sent to an IdP", func(t *testing.T) {
		query, _ := authorizeGETQuery(t)
		resp := getAuthorize(t, query, nil)
		defer func() { _ = resp.Body.Close() }()

		loc := resp.Header.Get("Location")
		t.Logf("status=%d location=%q", resp.StatusCode, loc)
		if loc != "" {
			u, err := url.Parse(loc)
			require.NoError(t, err)
			// The only redirect possible is back to the client with an error.
			assert.True(t, strings.HasPrefix(loc, testRedirectURI), "redirect goes back to the client only")
			assert.Equal(t, "access_denied", u.Query().Get("error"))
			assert.Empty(t, u.Query().Get("code"))
		} else {
			assert.Contains(t, []int{http.StatusUnauthorized, http.StatusBadRequest}, resp.StatusCode)
		}
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

		query, _ := authorizeGETQuery(t)
		resp, err := noRedirect.Get(fedHTTP.URL + "/oauth2/authorize?" + query.Encode())
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
		assert.Empty(t, resp.Header.Get("Location"), "no redirect to an upstream authorization endpoint")
		assert.Zero(t, okta.nonJWKSHits.Load(), "ZeroID never contacted the IdP's authorize surface")
	})
}

// ── Path 2: workload identity federation at /oauth2/token ───────────────────

// TestIdPAgentBaseline_Path2_WorkloadJWTOnUnconfiguredServer presents a k8s-SA-shaped JWT
// through every RFC 7523 / RFC 8693 shape on the shared server, which has NO
// external issuers configured. It records the error each shape returns.
func TestIdPAgentBaseline_Path2_WorkloadJWTOnUnconfiguredServer(t *testing.T) {
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
			wantCode: http.StatusBadRequest, wantErr: "invalid_grant",
		},
		{
			name: "token-exchange subject_token_type=id_token",
			body: map[string]any{
				"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
				"subject_token":      saTok,
				"subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
				"account_id":         testAccountID,
				"project_id":         testProjectID,
			},
			wantCode: http.StatusBadRequest, wantErr: "invalid_request", // no external issuers configured
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

// TestIdPAgentBaseline_Path2_WorkloadJWTViaIDTokenFederation configures a workload
// platform (Kubernetes) as an external issuer and checks that no grant treats
// its tokens as a workload credential: jwt-bearer and the broker arm refuse
// them, and application_id cannot bind one to an agent in another tenant.
// Flips with ADR 0042 D3/P2, which adds federated client assertions on
// client_credentials.
func TestIdPAgentBaseline_Path2_WorkloadJWTViaIDTokenFederation(t *testing.T) {
	k8s := newProbeRSAIdP(t)
	const k8sIss = "https://oidc.eks.us-east-1.amazonaws.com/id/PROBEFED"
	const aud = "https://zeroid.probe-wif.test"

	fedSrv, fedHTTP, fedCfg := newFederationServer(t, domain.ExternalIssuerConfig{
		Issuer:          k8sIss,
		JWKSURI:         k8s.JWKSURL(),
		Audience:        aud,
		ClaimMapping:    map[string]string{"user_id": "sub"},
		AllowedAccounts: []string{"acct-fed-001"},
	})
	defer fedHTTP.Close()
	defer func() { _ = fedSrv.Shutdown(context.Background()) }()

	t.Run("jwt-bearer with the same k8s SA token is still refused (no external-issuer arm for non-ID-JAG)", func(t *testing.T) {
		resp := postFederation(t, fedHTTP.URL, map[string]any{
			"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
			"assertion":  k8s.k8sSAToken(t, k8sIss, aud),
			"account_id": fedCfg.AccountID,
			"project_id": fedCfg.ProjectID,
		})
		t.Logf("status=%d body=%s", resp.StatusCode, resp.RawBody)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Equal(t, "invalid_grant", resp.Error)
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
	})

	t.Run("application_id cannot bind the workload JWT to a registered agent in another tenant", func(t *testing.T) {
		// application_id resolves against the CALLER-SUPPLIED tenant. A
		// registered agent in the shared test tenant is not found from
		// acct-fed-001, so this is refused.
		ident := registerIdentity(t, uid("probe-wif-agent"), []string{"data:read"})
		resp := postFederation(t, fedHTTP.URL, map[string]any{
			"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
			"subject_token":      k8s.k8sSAToken(t, k8sIss, aud),
			"subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
			"account_id":         fedCfg.AccountID,
			"project_id":         fedCfg.ProjectID,
			"application_id":     ident.ID,
		})
		t.Logf("status=%d body=%s", resp.StatusCode, resp.RawBody)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Equal(t, "invalid_request", resp.Error)
	})
}

// ── Path 3: client_credentials with private_key_jwt ──────────────────────────

func TestIdPAgentBaseline_Path3_ClientCredentialsPrivateKeyJWT(t *testing.T) {
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
	assert.Empty(t, regBody["client_secret"], "a key-based client gets no secret")

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

	// Flips with ADR 0042 D5: the tenant comes from the client registration.
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
		t.Logf("status=%d error=%v desc=%v", code, body["error"], body["error_description"])
		assert.Equal(t, http.StatusOK, code)
	})

	// Flips with ADR 0042 D8: CIMD clients gain client_credentials.
	t.Run("a CIMD URL as client_id cannot use client_credentials", func(t *testing.T) {
		cimdID := "https://agent.example.test/.well-known/client.json"
		code, body := postSharedToken(t, map[string]any{
			"grant_type":            "client_credentials",
			"client_id":             cimdID,
			"client_assertion":      clientAssertionFor(t, key, cimdID),
			"client_assertion_type": clientAssertionType,
			"account_id":            testAccountID,
			"project_id":            testProjectID,
		})
		t.Logf("status=%d error=%v desc=%v", code, body["error"], body["error_description"])
		assert.Equal(t, http.StatusUnauthorized, code)
		assert.Equal(t, "invalid_client", body["error"])
	})

	// Flips with ADR 0042 D8 for trusted workload issuers (federated client assertions).
	t.Run("an Okta-signed client_assertion (external issuer key) is not accepted", func(t *testing.T) {
		// A client_assertion signed by any key outside the client's own
		// registered jwks/jwks_uri fails, even when iss/sub equal the client_id.
		okta := newProbeRSAIdP(t)
		now := time.Now()
		assertion := okta.sign(t, "JWT", map[string]any{
			"iss": clientID, "sub": clientID, "aud": testIssuer,
			"iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(), "jti": uid("okta-cla"),
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
	})
}

// ── ID-JAG (ADR 0010) identity and tenant semantics ─────────────────────────

func TestIdPAgentBaseline_IDJAG_IdentityAndTenantSemantics(t *testing.T) {
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

	client := registerOAuthClient(t, uid("probe-idjag-client"), []string{"tools:read"})

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

	// Flips with ADR 0042 D6: the ID-JAG maps through a binding (act.sub) to the agent row.
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
	})

	t.Run("account_id not in allowed_accounts is refused", func(t *testing.T) {
		resp := postFederation(t, fedHTTP.URL, body(sign(t, nil), "acct-not-allowed", "proj-x"))
		t.Logf("status=%d body=%s", resp.StatusCode, resp.RawBody)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Equal(t, "invalid_grant", resp.Error)
	})

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

// TestIdPAgentBaseline_IDTokenExchange_RejectsForeignAudience confirms that ZeroID only
// accepts ID tokens addressed to its configured audience. An Okta ID token
// minted for some other relying party is refused.
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

	exchange := func(aud string) tokenResponse {
		now := time.Now()
		tok := upstream.SignToken(t, map[string]any{
			"iss": upstreamIss, "aud": aud, "sub": "00uAUDPROBE",
			"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		})
		return postFederation(t, fedHTTP.URL, map[string]any{
			"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
			"subject_token":      tok,
			"subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
			"account_id":         fedCfg.AccountID,
			"project_id":         fedCfg.ProjectID,
		})
	}

	foreign := exchange("0oaSOMEOTHERAPP")
	t.Logf("foreign aud: status=%d body=%s", foreign.StatusCode, foreign.RawBody)
	assert.Equal(t, http.StatusBadRequest, foreign.StatusCode)
	assert.Equal(t, "invalid_grant", foreign.Error)
	assert.Empty(t, foreign.AccessToken)

	// Control: the same token shape addressed to ZeroID is accepted.
	ok := exchange(federationAud)
	assert.Equal(t, http.StatusOK, ok.StatusCode, "body=%s", ok.RawBody)
}
