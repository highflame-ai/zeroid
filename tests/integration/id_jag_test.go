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

	// signIDJAG mints a validly-signed ID-JAG against the fake upstream IdP.
	signIDJAG := func(t *testing.T, claims map[string]any) string {
		t.Helper()
		// Force the ID-JAG typ header on the upstream-signed token.
		return upstream.SignTokenWithTyp(t, idJAGTyp, claims)
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

		resp := postFederation(t, fedHTTPSrv.URL, map[string]any{
			"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
			"subject":    idjag,
			"account_id": fedCfg.AccountID,
			"project_id": fedCfg.ProjectID,
		})
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

		resp := postFederation(t, fedHTTPSrv.URL, map[string]any{
			"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
			"subject":    idjag,
			"account_id": fedCfg.AccountID,
			"project_id": fedCfg.ProjectID,
		})
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
			"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
			"subject":    idjag,
			"account_id": "acct-not-in-allowlist",
			"project_id": fedCfg.ProjectID,
		})
		require.Equal(t, http.StatusBadRequest, resp.StatusCode, "body=%s", resp.RawBody)
		require.Equal(t, "invalid_grant", resp.Error, "body=%s", resp.RawBody)
		require.Empty(t, resp.AccessToken)
	})

	t.Run("bad signature fails closed (invalid_grant)", func(t *testing.T) {
		now := time.Now()
		// Sign with a foreign key the upstream JWKS does not publish.
		forged := signForeignIDJAG(t, idJAGTyp, map[string]any{
			"iss":      upstreamIss,
			"aud":      federationAud,
			"sub":      "00uFORGED",
			"resource": mcpResource,
			"iat":      now.Unix(),
			"exp":      now.Add(5 * time.Minute).Unix(),
		})

		resp := postFederation(t, fedHTTPSrv.URL, map[string]any{
			"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
			"subject":    forged,
			"account_id": fedCfg.AccountID,
			"project_id": fedCfg.ProjectID,
		})
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

		resp := postFederation(t, fedHTTPSrv.URL, map[string]any{
			"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
			"subject":    idjag,
			"account_id": fedCfg.AccountID,
			"project_id": fedCfg.ProjectID,
		})
		require.Equal(t, http.StatusBadRequest, resp.StatusCode, "body=%s", resp.RawBody)
		require.Equal(t, "invalid_grant", resp.Error, "body=%s", resp.RawBody)
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
