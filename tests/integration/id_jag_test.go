package integration_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/domain"
)

// idJAGTyp mirrors service.idJAGTyp — the JWS typ header that marks an
// assertion as an MCP ID-JAG. Re-declared here (the const is unexported in the
// service package) so the integration test pins the exact wire value.
const idJAGTyp = "oauth-id-jag+jwt"

// TestIDJAG_EndToEnd exercises the ADR 0010 MCP Authorization Server leg: an
// MCP ID-JAG (typ oauth-id-jag+jwt) presented at POST /oauth2/token via
// grant_type=jwt-bearer is validated against the corporate IdP's JWKS (the #88
// substrate), mapped to a Highflame principal, and minted into a ZeroID access
// token audience-restricted to the ID-JAG's `resource`.
//
// The IdP-facing setup (fake upstream IdP + federation-configured second
// server) reuses the same harness the id_token-exchange federation test uses;
// the only difference on the wire is grant_type=jwt-bearer + subject=<ID-JAG>
// instead of token-exchange + subject_token=<id_token>.
//
// Per ADR 0010 D2a/D2b, redemption now also REQUIRES an authenticated
// confidential client whose client_id equals the ID-JAG's client_id claim, and
// a single-use jti. The harness registers a confidential client (visible to the
// federation server via the shared DB, since OAuth-client lookup is global) and
// every signed ID-JAG carries that client_id + a UNIQUE jti so independent
// subtests don't collide on the replay table.
func TestIDJAG_EndToEnd(t *testing.T) {
	upstreamIss := "https://corp-idp.idjag.test"
	federationAud := "https://zeroid.idjag.test"
	const mcpResource = "https://mcp-server.idjag.test"

	upstream := newFakeUpstreamIdP(t)
	defer upstream.Close()

	fedSrv, fedHTTPSrv, fedCfg := newFederationServer(t, domain.ExternalIssuerConfig{
		Issuer:   upstreamIss,
		JWKSURI:  upstream.JWKSURL(),
		Audience: federationAud,
		ClaimMapping: map[string]string{
			"user_id": "sub",
			"email":   "email",
			// Map an IdP group/role claim into a Highflame Cedar attribute (D3):
			// the upstream emits `roles` → minted token carries a `role` claim.
			"role": "idp_role",
		},
		AllowedAccounts: []string{"acct-fed-001"},
	})
	defer fedHTTPSrv.Close()
	defer func() { _ = fedSrv.Shutdown(context.Background()) }()

	// Confidential client the ID-JAG is bound to (ADR 0010 D2b). Registered on
	// the shared testServer; OAuth-client lookup is global, so the federation
	// server's VerifyClientSecret resolves it from the same DB.
	client := registerOAuthClient(t, uid("idjag-client"), []string{"data:read"})

	// signIDJAG mints a validly-signed ID-JAG against the fake upstream IdP. It
	// auto-fills the bound client_id (D2b) and a UNIQUE jti (D2a) unless the
	// caller already set them, so happy-path subtests don't collide on replay.
	signIDJAG := func(t *testing.T, claims map[string]any) string {
		t.Helper()
		if _, ok := claims["client_id"]; !ok {
			claims["client_id"] = client.ClientID
		}
		if _, ok := claims["jti"]; !ok {
			claims["jti"] = uid("idjag-jti")
		}
		// Force the ID-JAG typ header on the upstream-signed token.
		return upstream.SignTokenWithTyp(t, idJAGTyp, claims)
	}

	// idJAGBody builds the /oauth2/token form with the confidential client auth
	// (D2b) every redemption now requires.
	idJAGBody := func(idjag string) map[string]any {
		return map[string]any{
			"grant_type":    "urn:ietf:params:oauth:grant-type:jwt-bearer",
			"subject":       idjag,
			"account_id":    fedCfg.AccountID,
			"project_id":    fedCfg.ProjectID,
			"client_id":     client.ClientID,
			"client_secret": client.ClientSecret,
		}
	}

	t.Run("happy path: mapped claims and aud==resource", func(t *testing.T) {
		now := time.Now()
		idjag := signIDJAG(t, map[string]any{
			"iss":      upstreamIss,
			"aud":      federationAud,
			"sub":      "00uMCPAGENT01",
			"email":    "agent@corp.example.com",
			"idp_role": "engineering",
			"resource": mcpResource,
			"scope":    "tools:read tools:exec",
			"iat":      now.Unix(),
			"exp":      now.Add(5 * time.Minute).Unix(),
		})

		resp := postFederation(t, fedHTTPSrv.URL, idJAGBody(idjag))
		require.Equal(t, http.StatusOK, resp.StatusCode,
			"ID-JAG jwt-bearer must return 200; body=%s", resp.RawBody)

		claims := decodeIssuedTokenClaims(t, resp.AccessToken)

		// D4 — audience restriction MUST: minted aud == ID-JAG resource.
		require.Equal(t, []any{mcpResource}, claims["aud"],
			"minted token aud must equal the ID-JAG resource claim")

		// D3 — identity mapping: sub mapped from the ID-JAG sub; email mapped;
		// IdP group/role mapped into the `role` Cedar attribute.
		require.Equal(t, "00uMCPAGENT01", claims["sub"])
		require.Equal(t, "agent@corp.example.com", claims["user_email"])
		require.Equal(t, "engineering", claims["role"])

		// IdP provenance + structural fingerprint distinguishing this path.
		require.Equal(t, upstreamIss, claims["user_id_iss"])
		require.Equal(t, "id_jag", claims["token_exchange"])

		// Tenant binding stamped from the request (gated by AllowedAccounts).
		require.Equal(t, fedCfg.AccountID, claims["account_id"])
		require.Equal(t, fedCfg.ProjectID, claims["project_id"])

		// Scopes flow from the ID-JAG `scope` claim (IdP already scoped it).
		require.ElementsMatch(t, []any{"tools:read", "tools:exec"}, claims["scopes"])
	})

	t.Run("resource as RFC 8707 array → aud is the full authorized set", func(t *testing.T) {
		now := time.Now()
		const mcpResource2 = "https://mcp-server-2.idjag.test"
		// RFC 8707 permits `resource` as an array; some IdPs emit even a single
		// resource as a one-element array. Accept it and audience-restrict to
		// every resource the IdP authorized (D4).
		idjag := signIDJAG(t, map[string]any{
			"iss":      upstreamIss,
			"aud":      federationAud,
			"sub":      "00uMULTIRES01",
			"resource": []any{mcpResource, mcpResource2},
			"scope":    "tools:read",
			"iat":      now.Unix(),
			"exp":      now.Add(5 * time.Minute).Unix(),
		})

		resp := postFederation(t, fedHTTPSrv.URL, idJAGBody(idjag))
		require.Equal(t, http.StatusOK, resp.StatusCode,
			"an array-valued resource is valid per RFC 8707; body=%s", resp.RawBody)

		claims := decodeIssuedTokenClaims(t, resp.AccessToken)
		require.ElementsMatch(t, []any{mcpResource, mcpResource2}, claims["aud"],
			"minted aud must contain every resource in the ID-JAG resource array")
	})

	t.Run("missing resource fails closed (invalid_grant)", func(t *testing.T) {
		now := time.Now()
		idjag := signIDJAG(t, map[string]any{
			"iss":   upstreamIss,
			"aud":   federationAud,
			"sub":   "00uNORESOURCE",
			"scope": "tools:read",
			"iat":   now.Unix(),
			"exp":   now.Add(5 * time.Minute).Unix(),
		})

		resp := postFederation(t, fedHTTPSrv.URL, idJAGBody(idjag))
		require.Equal(t, http.StatusBadRequest, resp.StatusCode, "body=%s", resp.RawBody)
		require.Equal(t, "invalid_grant", resp.Error, "body=%s", resp.RawBody)
		require.Empty(t, resp.AccessToken, "no token may be minted without an audience binding")
	})

	t.Run("tenant binding failure fails closed (invalid_grant)", func(t *testing.T) {
		now := time.Now()
		idjag := signIDJAG(t, map[string]any{
			"iss":      upstreamIss,
			"aud":      federationAud,
			"sub":      "00uWRONGTENANT",
			"resource": mcpResource,
			"iat":      now.Unix(),
			"exp":      now.Add(5 * time.Minute).Unix(),
		})

		resp := postFederation(t, fedHTTPSrv.URL, map[string]any{
			"grant_type":    "urn:ietf:params:oauth:grant-type:jwt-bearer",
			"subject":       idjag,
			"account_id":    "acct-not-in-allowlist",
			"project_id":    fedCfg.ProjectID,
			"client_id":     client.ClientID,
			"client_secret": client.ClientSecret,
		})
		require.Equal(t, http.StatusBadRequest, resp.StatusCode, "body=%s", resp.RawBody)
		require.Equal(t, "invalid_grant", resp.Error, "body=%s", resp.RawBody)
		require.Empty(t, resp.AccessToken)
	})

	t.Run("bad signature fails closed (invalid_grant)", func(t *testing.T) {
		now := time.Now()
		// Sign with a foreign key the upstream JWKS does not publish. Inject the
		// bound client_id + a jti so the only failing check is the signature.
		forged := signForeignIDJAG(t, idJAGTyp, map[string]any{
			"iss":       upstreamIss,
			"aud":       federationAud,
			"sub":       "00uFORGED",
			"resource":  mcpResource,
			"client_id": client.ClientID,
			"jti":       uid("idjag-jti"),
			"iat":       now.Unix(),
			"exp":       now.Add(5 * time.Minute).Unix(),
		})

		resp := postFederation(t, fedHTTPSrv.URL, idJAGBody(forged))
		require.Equal(t, http.StatusBadRequest, resp.StatusCode, "body=%s", resp.RawBody)
		require.Equal(t, "invalid_grant", resp.Error, "body=%s", resp.RawBody)
		require.Empty(t, resp.AccessToken)
	})

	t.Run("unknown issuer fails closed (invalid_grant)", func(t *testing.T) {
		now := time.Now()
		// Validly signed by the upstream key, but with an iss the federation
		// server has not configured.
		idjag := signIDJAG(t, map[string]any{
			"iss":      "https://stranger.idjag.test",
			"aud":      federationAud,
			"sub":      "00uSTRANGER",
			"resource": mcpResource,
			"iat":      now.Unix(),
			"exp":      now.Add(5 * time.Minute).Unix(),
		})

		resp := postFederation(t, fedHTTPSrv.URL, idJAGBody(idjag))
		require.Equal(t, http.StatusBadRequest, resp.StatusCode, "body=%s", resp.RawBody)
		require.Equal(t, "invalid_grant", resp.Error, "body=%s", resp.RawBody)
		require.Empty(t, resp.AccessToken)
	})

	// ── ADR 0010 D2a — single-use jti replay rejection ───────────────────────

	t.Run("replay: same jti redeemed twice → 2nd is invalid_grant", func(t *testing.T) {
		now := time.Now()
		// Pin the jti so both redemptions present the SAME single-use grant.
		idjag := signIDJAG(t, map[string]any{
			"iss":      upstreamIss,
			"aud":      federationAud,
			"sub":      "00uREPLAY01",
			"resource": mcpResource,
			"scope":    "tools:read",
			"jti":      uid("idjag-jti-replay"),
			"iat":      now.Unix(),
			"exp":      now.Add(5 * time.Minute).Unix(),
		})

		// First redemption mints normally.
		resp1 := postFederation(t, fedHTTPSrv.URL, idJAGBody(idjag))
		require.Equal(t, http.StatusOK, resp1.StatusCode,
			"first redemption of a fresh ID-JAG must succeed; body=%s", resp1.RawBody)
		require.NotEmpty(t, resp1.AccessToken)

		// Replaying the exact same ID-JAG (same jti) must be rejected.
		resp2 := postFederation(t, fedHTTPSrv.URL, idJAGBody(idjag))
		require.Equal(t, http.StatusBadRequest, resp2.StatusCode, "body=%s", resp2.RawBody)
		require.Equal(t, "invalid_grant", resp2.Error,
			"a replayed single-use ID-JAG must be invalid_grant; body=%s", resp2.RawBody)
		require.Empty(t, resp2.AccessToken, "no token may be minted on replay")
	})

	t.Run("missing jti fails closed (invalid_grant)", func(t *testing.T) {
		now := time.Now()
		// Sign directly (bypassing signIDJAG's jti auto-fill) so the grant
		// carries NO jti at all. client_id is still set so the only failing
		// check is the missing single-use jti.
		idjag := upstream.SignTokenWithTyp(t, idJAGTyp, map[string]any{
			"iss":       upstreamIss,
			"aud":       federationAud,
			"sub":       "00uNOJTI01",
			"resource":  mcpResource,
			"scope":     "tools:read",
			"client_id": client.ClientID,
			"iat":       now.Unix(),
			"exp":       now.Add(5 * time.Minute).Unix(),
		})

		resp := postFederation(t, fedHTTPSrv.URL, idJAGBody(idjag))
		require.Equal(t, http.StatusBadRequest, resp.StatusCode, "body=%s", resp.RawBody)
		require.Equal(t, "invalid_grant", resp.Error,
			"a single-use grant with no jti must be invalid_grant; body=%s", resp.RawBody)
		require.Empty(t, resp.AccessToken)
	})

	// ── ADR 0010 D2b — confidential client auth + client_id binding ──────────

	t.Run("no client auth → invalid_client", func(t *testing.T) {
		now := time.Now()
		idjag := signIDJAG(t, map[string]any{
			"iss":      upstreamIss,
			"aud":      federationAud,
			"sub":      "00uNOCLIENT01",
			"resource": mcpResource,
			"scope":    "tools:read",
			"iat":      now.Unix(),
			"exp":      now.Add(5 * time.Minute).Unix(),
		})

		// No client_id / client_secret presented.
		resp := postFederation(t, fedHTTPSrv.URL, map[string]any{
			"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
			"subject":    idjag,
			"account_id": fedCfg.AccountID,
			"project_id": fedCfg.ProjectID,
		})
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "body=%s", resp.RawBody)
		require.Equal(t, "invalid_client", resp.Error,
			"ID-JAG redemption without confidential client auth must be invalid_client; body=%s", resp.RawBody)
		require.Empty(t, resp.AccessToken)
	})

	t.Run("bad client secret → invalid_client", func(t *testing.T) {
		now := time.Now()
		idjag := signIDJAG(t, map[string]any{
			"iss":      upstreamIss,
			"aud":      federationAud,
			"sub":      "00uBADSECRET01",
			"resource": mcpResource,
			"scope":    "tools:read",
			"iat":      now.Unix(),
			"exp":      now.Add(5 * time.Minute).Unix(),
		})

		resp := postFederation(t, fedHTTPSrv.URL, map[string]any{
			"grant_type":    "urn:ietf:params:oauth:grant-type:jwt-bearer",
			"subject":       idjag,
			"account_id":    fedCfg.AccountID,
			"project_id":    fedCfg.ProjectID,
			"client_id":     client.ClientID,
			"client_secret": "wrong-secret",
		})
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "body=%s", resp.RawBody)
		require.Equal(t, "invalid_client", resp.Error,
			"a wrong client_secret must be invalid_client; body=%s", resp.RawBody)
		require.Empty(t, resp.AccessToken)
	})

	t.Run("client_id mismatch (authed client != ID-JAG client_id) → invalid_grant", func(t *testing.T) {
		now := time.Now()
		// The ID-JAG is bound to a DIFFERENT client than the one redeeming it.
		idjag := signIDJAG(t, map[string]any{
			"iss":       upstreamIss,
			"aud":       federationAud,
			"sub":       "00uMISMATCH01",
			"resource":  mcpResource,
			"scope":     "tools:read",
			"client_id": "some-other-client-id",
			"iat":       now.Unix(),
			"exp":       now.Add(5 * time.Minute).Unix(),
		})

		// Authenticate as our real client — which does NOT match the ID-JAG's
		// client_id claim. The binding (not the signature) must reject this.
		resp := postFederation(t, fedHTTPSrv.URL, idJAGBody(idjag))
		require.Equal(t, http.StatusBadRequest, resp.StatusCode, "body=%s", resp.RawBody)
		require.Equal(t, "invalid_grant", resp.Error,
			"an ID-JAG whose client_id does not match the authenticated client must be invalid_grant; body=%s", resp.RawBody)
		require.Empty(t, resp.AccessToken)
	})
}

// TestIDJAG_NHISelfSignedRegression is the load-bearing regression: a normal
// NHI self-signed jwt-bearer assertion (typ JWT, signed by the identity's
// registered key) MUST still succeed after the typ-branch was added. This runs
// against the SHARED TestMain server — the same path every existing NHI test
// uses — so it proves the ID-JAG branch did not perturb the registered-key path.
func TestIDJAG_NHISelfSignedRegression(t *testing.T) {
	agentKey := generateKey(t)
	ext := uid("idjag-nhi-regress")
	identity := registerIdentity(t, ext, []string{"data:read"}, ecPublicKeyPEM(t, agentKey))

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
		"subject":    buildAssertion(t, agentKey, identity.WIMSEURI),
		"scope":      "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"a self-signed NHI jwt-bearer assertion must still mint a token after the ID-JAG typ-branch")

	body := decode(t, resp)
	accessTok, _ := body["access_token"].(string)
	require.NotEmpty(t, accessTok, "NHI jwt-bearer must return an access token")

	// Structural proof this went through the NHI path, not the ID-JAG path:
	// sub is the agent's WIMSE URI (NHI), and there is NO id_jag fingerprint.
	claims := decodeIssuedTokenClaims(t, accessTok)
	require.Equal(t, identity.WIMSEURI, claims["sub"], "NHI token sub must be the agent WIMSE URI")
	require.NotEqual(t, "id_jag", claims["token_exchange"], "NHI token must not carry the ID-JAG fingerprint")
}

// TestIDJAG_ConfigurableScopeClaim proves the ID-JAG path sources scopes from
// the claim NAME configured in ClaimMapping["scope"] (defaulting to "scope"),
// so IdPs that emit scopes under a non-standard name — e.g. Microsoft Entra's
// `scp` — work without code changes (ADR 0010 D3).
func TestIDJAG_ConfigurableScopeClaim(t *testing.T) {
	upstreamIss := "https://corp-idp-scp.idjag.test"
	federationAud := "https://zeroid.idjag.test"
	const mcpResource = "https://mcp-server.idjag.test"

	upstream := newFakeUpstreamIdP(t)
	defer upstream.Close()

	fedSrv, fedHTTPSrv, fedCfg := newFederationServer(t, domain.ExternalIssuerConfig{
		Issuer:   upstreamIss,
		JWKSURI:  upstream.JWKSURL(),
		Audience: federationAud,
		ClaimMapping: map[string]string{
			"user_id": "sub",
			// Entra emits scopes under `scp`, not the standard `scope`. The
			// claim NAME is configurable; the ID-JAG path must read from it.
			"scope": "scp",
		},
		AllowedAccounts: []string{"acct-fed-001"},
	})
	defer fedHTTPSrv.Close()
	defer func() { _ = fedSrv.Shutdown(context.Background()) }()

	// Confidential client the ID-JAG is bound to (D2b).
	client := registerOAuthClient(t, uid("idjag-scp-client"), []string{"data:read"})

	now := time.Now()
	idjag := upstream.SignTokenWithTyp(t, idJAGTyp, map[string]any{
		"iss":       upstreamIss,
		"aud":       federationAud,
		"sub":       "00uENTRASCP01",
		"resource":  mcpResource,
		"scp":       "tools:read tools:exec", // non-standard scope claim name
		"client_id": client.ClientID,
		"jti":       uid("idjag-scp-jti"),
		"iat":       now.Unix(),
		"exp":       now.Add(5 * time.Minute).Unix(),
	})

	resp := postFederation(t, fedHTTPSrv.URL, map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:jwt-bearer",
		"subject":       idjag,
		"account_id":    fedCfg.AccountID,
		"project_id":    fedCfg.ProjectID,
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
	})
	require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)

	claims := decodeIssuedTokenClaims(t, resp.AccessToken)
	require.ElementsMatch(t, []any{"tools:read", "tools:exec"}, claims["scopes"],
		"scopes must be sourced from the ClaimMapping-configured scope claim (scp)")
}
