package integration_test

// AAuth Agent Provider (internal/aauth): a workload presents its platform
// token (here a Kubernetes service account token from the mock IdP) in an
// hwk-signed POST /ap/token and gets an AAuth agent token bound to its own
// key, issued through IssueCredential like every other token.
//
// The request signer below is written independently of internal/aauth, from
// RFC 9421 and the AAuth profile, so these tests check ZeroID against the
// spec rather than against itself.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	zeroid "github.com/highflame-ai/zeroid"
	"github.com/highflame-ai/zeroid/internal/mockidp"
	"github.com/highflame-ai/zeroid/pkg/authjwt"
)

// aauthHost is federationIssuer's host: the Agent Provider's authority and
// the domain of every agent identifier it issues.
const aauthHost = "federation.zeroid.test"

// aauthFed is a db-mode ZeroID with the Agent Provider on, and one workload
// agent bound to a mock cluster's service account.
type aauthFed struct {
	*workloadFed
}

func newAAuthFed(t *testing.T, grantTypes ...string) *aauthFed {
	t.Helper()
	if len(grantTypes) == 0 {
		grantTypes = []string{"aauth_agent", "aauth_bridge", "client_credentials"}
	}
	idp, err := mockidp.New("https://placeholder")
	require.NoError(t, err)
	idpSrv := httptest.NewTLSServer(idp.Handler())
	t.Cleanup(idpSrv.Close)
	idp.SetBaseURL(idpSrv.URL)
	f := &dbFederation{idp: idp, idpSrv: idpSrv, members: map[string]string{}}
	f.srv, f.http = newAAuthServer(t)

	w := &workloadFed{f: f, tn: newTITenant(t)}
	w.policy = createRichCredentialPolicy(t, map[string]any{
		"name":                uid("aauth-policy"),
		"allowed_grant_types": grantTypes,
		"allowed_scopes":      []string{"tools:read"},
		"max_ttl_seconds":     3600,
	}, w.tn.headers)
	resp := post(t, adminPath("/identities"), map[string]any{
		"external_id":          uid("aauth-agent"),
		"identity_type":        "agent",
		"trust_level":          "unverified",
		"owner_user_id":        "user-test-owner",
		"credential_policy_id": w.policy,
	}, w.tn.headers)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	got := decode(t, resp)
	_ = resp.Body.Close()
	w.agent, w.wimse = got["id"].(string), got["wimse_uri"].(string)

	status, body := f.call(t, http.MethodPost, "/external-issuers", map[string]any{
		"kind": "workload", "display_name": "Mock cluster", "issuer": idp.K8sIssuer(),
		"audiences": []string{federationIssuer},
	}, w.tn.headers)
	require.Equal(t, http.StatusCreated, status, "create workload row: %v", body)
	w.rowID = body["id"].(string)
	w.sub = "system:serviceaccount:agents:" + uid("sa")
	status, body = f.bind(t, w.tn, w.rowID, w.sub, w.agent, false)
	require.Equal(t, http.StatusCreated, status, "bind: %v", body)
	return &aauthFed{workloadFed: w}
}

// newAAuthServer is newDBFederationServer with the Agent Provider on.
func newAAuthServer(t *testing.T) (*zeroid.Server, *httptest.Server) {
	t.Helper()
	require.NoError(t, initFederationKeyMaterial())
	_, apKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(apKey)
	require.NoError(t, err)
	keyPath := filepath.Join(t.TempDir(), "aauth.pem")
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600))

	cfg := zeroid.Config{
		Server:   zeroid.ServerConfig{Port: "0", Env: "test", ShutdownTimeoutSeconds: 5},
		Database: zeroid.DatabaseConfig{URL: sharedDBURL, MaxOpenConns: 5, MaxIdleConns: 2},
		Keys: zeroid.KeysConfig{
			PrivateKeyPath: fedKeyPaths.privPath, PublicKeyPath: fedKeyPaths.pubPath, KeyID: "fed-test-key-1",
			RSAPrivateKeyPath: fedKeyPaths.rsaPriv, RSAPublicKeyPath: fedKeyPaths.rsaPub, RSAKeyID: "fed-test-rsa-1",
		},
		Token: zeroid.TokenConfig{
			Issuer: federationIssuer, DefaultTTL: 3600, MaxTTL: 90 * 24 * 3600,
			HMACSecret: testHMACSecret, AuthCodeIssuer: federationIssuer,
		},
		Telemetry:   zeroid.TelemetryConfig{Enabled: false},
		Logging:     zeroid.LoggingConfig{Level: "warn"},
		WIMSEDomain: testWIMSE,
		Federation:  zeroid.FederationConfig{IssuerStore: "db", AllowPrivateEndpoints: true},
		AAuth:       zeroid.AAuthConfig{Enabled: true, SigningKeyPath: keyPath, Name: "ZeroID test AP"},
	}
	insecure := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec
	}
	srv, err := zeroid.NewServer(cfg,
		zeroid.WithExternalIssuerHTTPClient(insecure),
		zeroid.WithExternalIssuerJWKSOption(authjwt.WithHTTPClient(insecure)))
	require.NoError(t, err)
	httpSrv := httptest.NewServer(srv.Router())
	t.Cleanup(httpSrv.Close)
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	return srv, httpSrv
}

// agentKey is an agent's Ed25519 signing key and its public JWK.
type agentKey struct {
	priv ed25519.PrivateKey
	x    string
}

func newAgentKey(t *testing.T) agentKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return agentKey{priv: priv, x: base64.RawURLEncoding.EncodeToString(pub)}
}

// thumbprint is the key's RFC 7638 thumbprint.
func (k agentKey) thumbprint() string {
	sum := sha256.Sum256([]byte(`{"crv":"Ed25519","kty":"OKP","x":"` + k.x + `"}`))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// signedBootstrap builds POST /ap/token with body, signed with k under hwk
// for authority (RFC 9421, AAuth profile), created at created.
func (a *aauthFed) signedBootstrap(t *testing.T, k agentKey, body, authority string, created time.Time) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, a.f.http.URL+"/ap/token", strings.NewReader(body))
	require.NoError(t, err)
	req.Host = authority
	req.Header.Set("Content-Type", "application/json")
	sum := sha256.Sum256([]byte(body))
	digest := "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
	req.Header.Set("Content-Digest", digest)
	sigKey := fmt.Sprintf(`sig=hwk;kty="OKP";crv="Ed25519";x="%s";alg="Ed25519"`, k.x)
	req.Header.Set("Signature-Key", sigKey)
	params := fmt.Sprintf(`("@method" "@authority" "@path" "signature-key" "content-digest" "content-type");created=%d`, created.Unix())
	base := strings.Join([]string{
		`"@method": POST`,
		`"@authority": ` + authority,
		`"@path": /ap/token`,
		`"signature-key": ` + sigKey,
		`"content-digest": ` + digest,
		`"content-type": application/json`,
		`"@signature-params": ` + params,
	}, "\n")
	req.Header.Set("Signature-Input", "sig="+params)
	req.Header.Set("Signature", "sig=:"+base64.StdEncoding.EncodeToString(ed25519.Sign(k.priv, []byte(base)))+":")
	return req
}

type apResponse struct {
	status  int
	headers http.Header
	body    map[string]any
}

func (a *aauthFed) do(t *testing.T, req *http.Request) apResponse {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := apResponse{status: resp.StatusCode, headers: resp.Header, body: map[string]any{}}
	_ = json.Unmarshal(raw, &out.body)
	return out
}

func (a *aauthFed) bootstrap(t *testing.T, k agentKey, platformToken string) apResponse {
	t.Helper()
	body := `{"attestation":"` + platformToken + `"}`
	return a.do(t, a.signedBootstrap(t, k, body, aauthHost, time.Now()))
}

func TestAAuthAgentProvider(t *testing.T) {
	a := newAAuthFed(t)

	t.Run("a platform token and an hwk-signed request get an agent token bound to the key", func(t *testing.T) {
		k := newAgentKey(t)
		res := a.bootstrap(t, k, a.assertion(t, nil))
		require.Equal(t, http.StatusOK, res.status, "body=%v", res.body)
		assert.Equal(t, "no-store", res.headers.Get("Cache-Control"))
		assert.EqualValues(t, 900, res.body["expires_in"], "15 minutes, inside the policy's hour")

		token := res.body["agent_token"].(string)
		header := decodeJWTHeader(t, token)
		assert.Equal(t, "aa-agent+jwt", header["typ"])
		assert.Equal(t, "Ed25519", header["alg"])
		claims := decodeJWTPayload(t, token)
		assert.Equal(t, federationIssuer, claims["iss"])
		assert.Equal(t, "aauth-agent.json", claims["dwk"])
		assert.Equal(t, "aauth:"+a.agent+"@"+aauthHost, claims["sub"], "the identity's UUID at the AP's domain")
		cnf := claims["cnf"].(map[string]any)["jwk"].(map[string]any)
		assert.Equal(t, k.x, cnf["x"])
		assert.Equal(t, "Ed25519", cnf["alg"])
		assert.EqualValues(t, 900, claims["exp"].(float64)-claims["iat"].(float64))
		for _, absent := range []string{"aud", "scope", "scopes", "account_id", "wimse_id"} {
			assert.NotContains(t, claims, absent, "an agent token carries no %s", absent)
		}
	})

	t.Run("the token verifies against the published metadata and JWKS", func(t *testing.T) {
		res := a.bootstrap(t, newAgentKey(t), a.assertion(t, nil))
		require.Equal(t, http.StatusOK, res.status, "body=%v", res.body)

		meta := a.getJSON(t, "/.well-known/aauth-agent.json")
		assert.Equal(t, federationIssuer, meta["issuer"], "issuer byte-matches the URL it is served from")
		assert.Equal(t, federationIssuer+"/ap/jwks.json", meta["jwks_uri"])

		set, err := jwk.Parse(a.getRaw(t, "/ap/jwks.json"))
		require.NoError(t, err)
		key, ok := set.Key(0)
		require.True(t, ok)
		alg, _ := key.Algorithm()
		assert.Equal(t, "Ed25519", alg.String(), "every published key carries a fully specified alg")
		_, err = jwt.Parse([]byte(res.body["agent_token"].(string)), jwt.WithKey(jwa.EdDSAEd25519(), key))
		require.NoError(t, err, "the agent token verifies under the published key")
	})

	t.Run("the agent token is an ordinary credential of the identity", func(t *testing.T) {
		k := newAgentKey(t)
		res := a.bootstrap(t, k, a.assertion(t, nil))
		require.Equal(t, http.StatusOK, res.status, "body=%v", res.body)
		jti := decodeJWTPayload(t, res.body["agent_token"].(string))["jti"].(string)
		cred := a.credential(t, jti)
		require.NotNil(t, cred, "an issued_credentials row exists")
		assert.Equal(t, "aauth_agent", cred["grant_type"])
		assert.Equal(t, k.thumbprint(), cred["dpop_key_thumbprint"], "the row records the key the token is bound to")
		assert.Equal(t, a.wimse, cred["subject"], "the row's subject is the WIMSE URI, as for every credential")

		status, body := a.f.call(t, http.MethodPost, "/credentials/"+cred["id"].(string)+"/rotate", map[string]any{}, a.tn.headers)
		assert.Equal(t, http.StatusConflict, status, "an agent token is re-issued by bootstrap, never rotated: %v", body)
		assert.Equal(t, false, a.credential(t, jti)["is_revoked"], "a refused rotation leaves the token alive")
	})

	t.Run("the same key may redeem the same platform token again; another key may not", func(t *testing.T) {
		platform := a.assertion(t, nil)
		k := newAgentKey(t)
		first := a.bootstrap(t, k, platform)
		require.Equal(t, http.StatusOK, first.status, "body=%v", first.body)
		again := a.bootstrap(t, k, platform)
		require.Equal(t, http.StatusOK, again.status, "a worker or restarted container sharing the pod key: %v", again.body)
		assert.NotEqual(t, first.body["agent_token"], again.body["agent_token"])

		thief := a.bootstrap(t, newAgentKey(t), platform)
		assert.Equal(t, http.StatusForbidden, thief.status)
		assert.Equal(t, "invalid_grant", thief.body["error"])
		assert.Empty(t, thief.headers.Get("Signature-Error"), "403 after the signature verified carries no Signature-Error")
	})

	t.Run("one platform token is redeemed at one endpoint only", func(t *testing.T) {
		atAP := a.assertion(t, nil)
		require.Equal(t, http.StatusOK, a.bootstrap(t, newAgentKey(t), atAP).status)
		requireRefused(t, a.clientCredentials(t, atAP, nil), "invalid_client")

		atToken := a.assertion(t, nil)
		resp := a.clientCredentials(t, atToken, nil)
		require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", resp.RawBody)
		res := a.bootstrap(t, newAgentKey(t), atToken)
		assert.Equal(t, http.StatusForbidden, res.status)
		assert.Equal(t, "invalid_grant", res.body["error"])
	})

	t.Run("refusals before the attestation verifies are indistinguishable", func(t *testing.T) {
		other, err := mockidp.New("https://placeholder")
		require.NoError(t, err)
		otherSrv := httptest.NewTLSServer(other.Handler())
		t.Cleanup(otherSrv.Close)
		other.SetBaseURL(otherSrv.URL)
		untrusted, _, err := other.Mint(mockidp.MintRequest{Profile: mockidp.ProfileK8sServiceAccount,
			Claims: map[string]any{"sub": a.sub, "aud": federationIssuer, "jti": uid("jti")}})
		require.NoError(t, err)

		for name, platform := range map[string]string{
			"an untrusted issuer":     untrusted,
			"a token for another aud": a.assertion(t, map[string]any{"aud": "https://elsewhere.example"}),
			"a token with no jti":     a.assertion(t, map[string]any{"jti": nil}),
			"not a JWT":               "not-a-jwt",
			"a tampered signature":    a.assertion(t, nil) + "x",
		} {
			res := a.bootstrap(t, newAgentKey(t), platform)
			assert.Equal(t, http.StatusForbidden, res.status, name)
			assert.Equal(t, "access_denied", res.body["error"], name)
			assert.Equal(t, "the attestation was not accepted", res.body["error_description"], name)
		}
	})

	t.Run("a bound subject the tenant has not adopted, or an unbound one, is refused", func(t *testing.T) {
		res := a.bootstrap(t, newAgentKey(t), a.assertion(t, map[string]any{"sub": "system:serviceaccount:agents:" + uid("nobody")}))
		assert.Equal(t, http.StatusForbidden, res.status)
		assert.Equal(t, "invalid_grant", res.body["error"])
	})

	t.Run("signature failures are 401 with Signature-Error", func(t *testing.T) {
		platform := a.assertion(t, nil)
		body := `{"attestation":"` + platform + `"}`

		unsigned, _ := http.NewRequest(http.MethodPost, a.f.http.URL+"/ap/token", strings.NewReader(body))
		unsigned.Host = aauthHost
		unsigned.Header.Set("Content-Type", "application/json")
		res := a.do(t, unsigned)
		assert.Equal(t, http.StatusUnauthorized, res.status)
		assert.Equal(t, "error=invalid_signature", res.headers.Get("Signature-Error"))

		stale := a.do(t, a.signedBootstrap(t, newAgentKey(t), body, aauthHost, time.Now().Add(-2*time.Minute)))
		assert.Equal(t, http.StatusUnauthorized, stale.status)
		assert.Equal(t, "error=invalid_signature", stale.headers.Get("Signature-Error"))

		elsewhere := a.do(t, a.signedBootstrap(t, newAgentKey(t), body, "other.example", time.Now()))
		assert.Equal(t, http.StatusUnauthorized, elsewhere.status, "a request signed for, and sent to, another authority")
	})

	t.Run("a tenant whose policy does not list aauth_agent is not opted in", func(t *testing.T) {
		off := newAAuthFed(t, "client_credentials")
		k := newAgentKey(t)
		platform := off.assertion(t, nil)
		res := off.bootstrap(t, k, platform)
		assert.Equal(t, http.StatusForbidden, res.status)
		assert.Equal(t, "access_denied", res.body["error"])

		// The same key retrying is told the truth at once: its earlier
		// redemption was refused. Not "another key", not "retry".
		retry := off.bootstrap(t, k, platform)
		assert.Equal(t, http.StatusForbidden, retry.status, "body=%v", retry.body)
		assert.Equal(t, "invalid_grant", retry.body["error"])
		assert.Contains(t, retry.body["error_description"], "was refused")
		assert.Empty(t, retry.headers.Get("Retry-After"))
	})

	t.Run("a policy too short for the refresh margin is refused, not looped on", func(t *testing.T) {
		short := newAAuthFed(t)
		status, body := short.f.call(t, http.MethodPatch, "/credential-policies/"+short.policy,
			map[string]any{"max_ttl_seconds": 300}, short.tn.headers)
		require.Equal(t, http.StatusOK, status, "shorten the policy: %v", body)
		res := short.bootstrap(t, newAgentKey(t), short.assertion(t, nil))
		assert.Equal(t, http.StatusForbidden, res.status)
		assert.Equal(t, "access_denied", res.body["error"])
		assert.Contains(t, res.body["error_description"], "over 300s")
	})
}

func (a *aauthFed) getRaw(t *testing.T, path string) []byte {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, a.f.http.URL+path, nil)
	req.Host = aauthHost
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return raw
}

func (a *aauthFed) getJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	var out map[string]any
	require.NoError(t, json.Unmarshal(a.getRaw(t, path), &out))
	return out
}

// credential returns the identity's credential row with jti, or nil.
func (a *aauthFed) credential(t *testing.T, jti string) map[string]any {
	t.Helper()
	status, body := a.f.call(t, http.MethodGet, "/credentials?identity_id="+a.agent, nil, a.tn.headers)
	require.Equal(t, http.StatusOK, status, "list credentials: %v", body)
	items, _ := body["credentials"].([]any)
	for _, it := range items {
		c := it.(map[string]any)
		if c["jti"] == jti {
			return c
		}
	}
	return nil
}

func decodeJWTHeader(t *testing.T, token string) map[string]any {
	t.Helper()
	part := strings.SplitN(token, ".", 2)[0]
	raw, err := base64.RawURLEncoding.DecodeString(part)
	require.NoError(t, err)
	var out map[string]any
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

// dpopProof is an RFC 9449 proof signed by k for POST htu. Ed25519 DPoP uses
// the JOSE name EdDSA, which pkg/dpop requires; AAuth itself names the same
// key Ed25519.
func (k agentKey) dpopProof(t *testing.T, htu string) string {
	t.Helper()
	enc := func(v any) string {
		b, err := json.Marshal(v)
		require.NoError(t, err)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	head := enc(map[string]any{"typ": "dpop+jwt", "alg": "EdDSA", "jwk": map[string]string{"kty": "OKP", "crv": "Ed25519", "x": k.x}})
	body := enc(map[string]any{"jti": uid("dpop"), "htm": "POST", "htu": htu, "iat": time.Now().Unix()})
	return head + "." + body + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(k.priv, []byte(head+"."+body)))
}

// bridge exchanges agentToken at the token endpoint. proofKey, when set,
// signs the DPoP proof.
func (a *aauthFed) bridge(t *testing.T, agentToken string, proofKey *agentKey, extra map[string]any) apResponse {
	t.Helper()
	body := map[string]any{
		"grant_type":    "urn:highflame:params:oauth:grant-type:aauth-agent-token",
		"subject_token": agentToken,
		"resource":      "https://mcp.example/tools",
		"scope":         "tools:read",
	}
	for k, v := range extra {
		if v == nil {
			delete(body, k)
			continue
		}
		body[k] = v
	}
	b, err := json.Marshal(body)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, a.f.http.URL+"/oauth2/token", strings.NewReader(string(b)))
	require.NoError(t, err)
	req.Host = aauthHost
	req.Header.Set("Content-Type", "application/json")
	if proofKey != nil {
		// No TLS in the test, and forwarded headers aren't trusted, so the
		// token endpoint sees http://<host>/oauth2/token.
		req.Header.Set("DPoP", proofKey.dpopProof(t, "http://"+aauthHost+"/oauth2/token"))
	}
	return a.do(t, req)
}

func TestAAuthBridge(t *testing.T) {
	a := newAAuthFed(t)
	newAgentToken := func(t *testing.T) (agentKey, string) {
		k := newAgentKey(t)
		res := a.bootstrap(t, k, a.assertion(t, nil))
		require.Equal(t, http.StatusOK, res.status, "bootstrap: %v", res.body)
		return k, res.body["agent_token"].(string)
	}

	t.Run("an agent token and a DPoP proof by its key get a DPoP-bound OAuth token", func(t *testing.T) {
		k, agentToken := newAgentToken(t)
		agentClaims := decodeJWTPayload(t, agentToken)
		res := a.bridge(t, agentToken, &k, nil)
		require.Equal(t, http.StatusOK, res.status, "body=%v", res.body)
		assert.Equal(t, "DPoP", res.body["token_type"])

		claims := decodeJWTPayload(t, res.body["access_token"].(string))
		assert.Equal(t, a.wimse, claims["sub"], "an ordinary token of the identity")
		assert.Equal(t, "aauth_bridge", claims["grant_type"])
		assert.Equal(t, agentClaims["sub"], claims["aauth_agent"], "names the agent it was exchanged for")
		assert.Equal(t, k.thumbprint(), claims["cnf"].(map[string]any)["jkt"], "bound to the agent's own key")
		assert.Contains(t, fmt.Sprint(claims["aud"]), "https://mcp.example/tools")
		assert.Contains(t, fmt.Sprint(claims["resource"]), "https://mcp.example/tools")
		assert.LessOrEqual(t, claims["exp"].(float64), agentClaims["exp"].(float64), "never outlives the agent token")

		row := a.credential(t, claims["jti"].(string))
		require.NotNil(t, row)
		assert.Equal(t, agentClaims["jti"], row["parent_jti"], "the child of the agent token")
	})

	t.Run("revoking the agent token revokes what was bridged from it", func(t *testing.T) {
		k, agentToken := newAgentToken(t)
		res := a.bridge(t, agentToken, &k, nil)
		require.Equal(t, http.StatusOK, res.status, "body=%v", res.body)
		bridgedJTI := decodeJWTPayload(t, res.body["access_token"].(string))["jti"].(string)
		agentRow := a.credential(t, decodeJWTPayload(t, agentToken)["jti"].(string))
		require.NotNil(t, agentRow)

		status, body := a.f.call(t, http.MethodPost, "/credentials/"+agentRow["id"].(string)+"/revoke",
			map[string]any{"reason": "test"}, a.tn.headers)
		require.Contains(t, []int{http.StatusOK, http.StatusNoContent}, status, "revoke: %v", body)
		assert.Equal(t, true, a.credential(t, bridgedJTI)["is_revoked"], "cascade through parent_jti")

		again := a.bridge(t, agentToken, &k, nil)
		assert.Equal(t, http.StatusBadRequest, again.status)
		assert.Equal(t, "invalid_grant", again.body["error"], "a revoked agent token can't be exchanged")
	})

	t.Run("possession of the agent key is required", func(t *testing.T) {
		_, agentToken := newAgentToken(t)
		none := a.bridge(t, agentToken, nil, nil)
		assert.Equal(t, http.StatusBadRequest, none.status)
		assert.Equal(t, "invalid_request", none.body["error"])

		other := newAgentKey(t)
		wrong := a.bridge(t, agentToken, &other, nil)
		assert.Equal(t, http.StatusBadRequest, wrong.status)
		assert.Equal(t, "invalid_grant", wrong.body["error"], "a DPoP proof by another key")
	})

	t.Run("only agent tokens from this Agent Provider are exchanged", func(t *testing.T) {
		k := newAgentKey(t)
		oauth := a.clientCredentials(t, a.assertion(t, nil), nil)
		require.Equal(t, http.StatusOK, oauth.StatusCode, "body=%s", oauth.RawBody)
		res := a.bridge(t, oauth.AccessToken, &k, nil)
		assert.Equal(t, http.StatusBadRequest, res.status)
		assert.Equal(t, "invalid_grant", res.body["error"], "an OAuth access token is not an agent token")
	})

	t.Run("a scope outside the ceiling is invalid_scope, not a bad agent token", func(t *testing.T) {
		k, agentToken := newAgentToken(t)
		res := a.bridge(t, agentToken, &k, map[string]any{"scope": "nhi:manage"})
		assert.Equal(t, http.StatusBadRequest, res.status, "body=%v", res.body)
		assert.Equal(t, "invalid_scope", res.body["error"])
	})

	t.Run("the token is for exactly one resource", func(t *testing.T) {
		k, agentToken := newAgentToken(t)
		res := a.bridge(t, agentToken, &k, map[string]any{"resource": nil})
		assert.Equal(t, http.StatusBadRequest, res.status)
		assert.Equal(t, "invalid_target", res.body["error"])
	})

	t.Run("a tenant whose policy does not list aauth_bridge can't bridge", func(t *testing.T) {
		off := newAAuthFed(t, "aauth_agent")
		k := newAgentKey(t)
		boot := off.bootstrap(t, k, off.assertion(t, nil))
		require.Equal(t, http.StatusOK, boot.status, "body=%v", boot.body)
		res := off.bridge(t, boot.body["agent_token"].(string), &k, nil)
		assert.Equal(t, http.StatusBadRequest, res.status, "body=%v", res.body)
		assert.Equal(t, "invalid_grant", res.body["error"])
	})
}
