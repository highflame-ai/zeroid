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
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	zeroid "github.com/highflame-ai/zeroid"
	aauthpkg "github.com/highflame-ai/zeroid/internal/aauth"
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
	return newAAuthFedWith(t, nil, grantTypes...)
}

// newAAuthFedWith is newAAuthFed with mutate applied to the server config.
func newAAuthFedWith(t *testing.T, mutate func(*zeroid.Config), grantTypes ...string) *aauthFed {
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
	f.srv, f.http = newAAuthServer(t, mutate)

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

// aauthDialOverrides routes host:port to a local listener address for the
// Agent Provider's outbound requests (person servers).
var aauthDialOverrides sync.Map

// newAAuthServer is newDBFederationServer with the Agent Provider on.
func newAAuthServer(t *testing.T, mutate func(*zeroid.Config)) (*zeroid.Server, *httptest.Server) {
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
			// The confusion tests introspect without client credentials.
			AllowUnauthenticatedTokenInspection: true,
		},
		Telemetry:   zeroid.TelemetryConfig{Enabled: false},
		Logging:     zeroid.LoggingConfig{Level: "warn"},
		WIMSEDomain: testWIMSE,
		Federation:  zeroid.FederationConfig{IssuerStore: "db", AllowPrivateEndpoints: true},
		AAuth:       zeroid.AAuthConfig{Enabled: true, SigningKeyPath: keyPath, Name: "ZeroID test AP", LogoURI: "https://zeroid.test/logo.svg"},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	insecure := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			// A person server is a host without a port; tests serve one on a
			// local listener and route its host there.
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if to, ok := aauthDialOverrides.Load(addr); ok {
					addr = to.(string)
				}
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
		},
	}
	srv, err := zeroid.NewServer(cfg,
		zeroid.WithExternalIssuerHTTPClient(insecure),
		zeroid.WithExternalIssuerJWKSOption(authjwt.WithHTTPClient(insecure)),
		zeroid.WithAAuthPersonServerHTTPClient(insecure))
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
	sigKey := fmt.Sprintf(`sig=hwk;kty="OKP";crv="Ed25519";x="%s";alg="Ed25519"`, k.x)
	return a.signedAP(t, k, "/ap/token", sigKey, body, authority, created)
}

// signedSubagent builds POST /ap/subagent with body, signed with k under the
// jwt scheme presenting agentToken.
func (a *aauthFed) signedSubagent(t *testing.T, k agentKey, agentToken, body string) *http.Request {
	t.Helper()
	return a.signedAP(t, k, "/ap/subagent", `sig=jwt;jwt="`+agentToken+`"`, body, aauthHost, time.Now())
}

// signedAP builds a POST to path with body, signed with k under sigKey for
// authority (RFC 9421, AAuth profile), created at created.
func (a *aauthFed) signedAP(t *testing.T, k agentKey, path, sigKey, body, authority string, created time.Time) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, a.f.http.URL+path, strings.NewReader(body))
	require.NoError(t, err)
	req.Host = authority
	req.Header.Set("Content-Type", "application/json")
	sum := sha256.Sum256([]byte(body))
	digest := "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
	req.Header.Set("Content-Digest", digest)
	req.Header.Set("Signature-Key", sigKey)
	params := fmt.Sprintf(`("@method" "@authority" "@path" "signature-key" "content-digest" "content-type");created=%d`, created.Unix())
	base := strings.Join([]string{
		`"@method": POST`,
		`"@authority": ` + authority,
		`"@path": ` + path,
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
		assert.Equal(t, "ZeroID test AP", meta["name"])
		assert.Equal(t, "https://zeroid.test/logo.svg", meta["logo_uri"])
		assert.NotContains(t, meta, "tos_uri", "unset display members are left out")

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
			assert.Equal(t, "the attestation was not accepted", res.body["detail"], name)
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
		assert.Equal(t, "application/problem+json", res.headers.Get("Content-Type"))
		assert.Equal(t, "invalid_signature", res.body["error"], "the AAuth error body repeats the code")

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
		assert.Contains(t, retry.body["detail"], "was refused")
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
		assert.Contains(t, res.body["detail"], "over 300s")
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

	t.Run("a request naming another tenant is refused", func(t *testing.T) {
		k, agentToken := newAgentToken(t)
		res := a.bridge(t, agentToken, &k, map[string]any{"account_id": "someone-else", "project_id": a.tn.project})
		assert.Equal(t, http.StatusBadRequest, res.status, "body=%v", res.body)
		assert.Equal(t, "invalid_grant", res.body["error"])
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

// TestAAuthTokenConfusion pins that neither AAuth token can pass for
// something it isn't anywhere else in ZeroID.
func TestAAuthTokenConfusion(t *testing.T) {
	a := newAAuthFed(t)
	k := newAgentKey(t)
	boot := a.bootstrap(t, k, a.assertion(t, nil))
	require.Equal(t, http.StatusOK, boot.status, "body=%v", boot.body)
	agentToken := boot.body["agent_token"].(string)
	bridged := a.bridge(t, agentToken, &k, nil)
	require.Equal(t, http.StatusOK, bridged.status, "body=%v", bridged.body)
	bridgedToken := bridged.body["access_token"].(string)

	form := func(path string, values map[string]string) apResponse {
		v := url.Values{}
		for key, val := range values {
			v.Set(key, val)
		}
		req, err := http.NewRequest(http.MethodPost, a.f.http.URL+path, strings.NewReader(v.Encode()))
		require.NoError(t, err)
		req.Host = aauthHost
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return a.do(t, req)
	}

	t.Run("an agent token is never active at introspection", func(t *testing.T) {
		res := form("/oauth2/token/introspect", map[string]string{"token": agentToken})
		require.Equal(t, http.StatusOK, res.status, "body=%v", res.body)
		assert.Equal(t, false, res.body["active"], "its row carries a key thumbprint, but it is not an OAuth access token")
	})

	t.Run("an agent token is not a subject or actor token for RFC 8693 exchange", func(t *testing.T) {
		asSubject := form("/oauth2/token", map[string]string{
			"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
			"subject_token":      agentToken,
			"subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
		})
		assert.NotEqual(t, http.StatusOK, asSubject.status, "body=%v", asSubject.body)
		asActor := form("/oauth2/token", map[string]string{
			"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
			"subject_token":      bridgedToken,
			"subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
			"actor_token":        agentToken,
			"actor_token_type":   "urn:ietf:params:oauth:token-type:jwt",
		})
		assert.NotEqual(t, http.StatusOK, asActor.status, "body=%v", asActor.body)
	})

	t.Run("neither token can enroll a durable key at agent self-service", func(t *testing.T) {
		for name, tok := range map[string]string{"agent token": agentToken, "bridged token": bridgedToken} {
			req, err := http.NewRequest(http.MethodPost, a.f.http.URL+"/agents/self/public-key",
				strings.NewReader(`{"new_public_key_pem":"x","new_key_proof":"x"}`))
			require.NoError(t, err)
			req.Host = aauthHost
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+tok)
			res := a.do(t, req)
			if name == "bridged token" {
				// It verifies as a ZeroID access token; enrollment's own
				// grant-type rule refuses it.
				assert.Equal(t, http.StatusForbidden, res.status, "%s: %v", name, res.body)
				assert.Contains(t, fmt.Sprint(res.body["detail"]), "agent's own token")
				continue
			}
			assert.Equal(t, http.StatusUnauthorized, res.status, "an agent token is not a ZeroID access token: %v", res.body)
		}
	})
}

// newAAuthFirstContactFed is a db-mode ZeroID with the Agent Provider on and
// a mock cluster row whose first_contact is settings(tn), with no binding.
// The mapped project's default policy, which first contact's identities
// take, lists defaultGrants.
func newAAuthFirstContactFed(t *testing.T, settings func(fcTenant) map[string]any, defaultGrants ...string) (*aauthFed, fcTenant) {
	t.Helper()
	idp, err := mockidp.New("https://placeholder")
	require.NoError(t, err)
	idpSrv := httptest.NewTLSServer(idp.Handler())
	t.Cleanup(idpSrv.Close)
	idp.SetBaseURL(idpSrv.URL)
	f := &dbFederation{idp: idp, idpSrv: idpSrv, members: map[string]string{}}
	f.srv, f.http = newAAuthServer(t, nil)

	tn := newFCTenant(t)
	createRichCredentialPolicy(t, map[string]any{
		"name":                "default",
		"allowed_grant_types": defaultGrants,
		"allowed_scopes":      []string{"tools:read"},
		"max_ttl_seconds":     3600,
	}, tn.mappedHeaders)
	body := map[string]any{
		"kind": "workload", "display_name": "Mock cluster", "issuer": idp.K8sIssuer(),
		"audiences": []string{federationIssuer},
	}
	for k, v := range settings(tn) {
		body[k] = v
	}
	status, got := f.call(t, http.MethodPost, "/external-issuers", body, tn.headers)
	require.Equal(t, http.StatusCreated, status, "create workload row: %v", got)
	w := &workloadFed{f: f, tn: tn.tiTenant, rowID: got["id"].(string), sub: newSA()}
	return &aauthFed{workloadFed: w}, tn
}

// First contact applies at /ap/token as at the federated client_credentials
// grant: a platform token means the same thing at both endpoints. The
// credential policy's aauth_agent opt-in still applies to the agent it
// registers.
func TestAAuthFirstContact(t *testing.T) {
	t.Run("discover registers the agent unadopted and refuses it", func(t *testing.T) {
		a, tn := newAAuthFirstContactFed(t, discoverSettings, "aauth_agent")
		res := a.bootstrap(t, newAgentKey(t), a.assertion(t, nil))
		assert.Equal(t, http.StatusForbidden, res.status, "body=%v", res.body)
		assert.Equal(t, "invalid_grant", res.body["error"])

		ids := tn.firstContactIdentities(t)
		require.Len(t, ids, 1, "registered for an admin to adopt")
		assert.Equal(t, "discovered", ids[0]["status"])
	})

	t.Run("adopt registers the agent and serves it when its policy lists aauth_agent", func(t *testing.T) {
		a, tn := newAAuthFirstContactFed(t, adoptSettings, "aauth_agent")
		k := newAgentKey(t)
		res := a.bootstrap(t, k, a.assertion(t, nil))
		require.Equal(t, http.StatusOK, res.status, "body=%v", res.body)

		ids := tn.firstContactIdentities(t)
		require.Len(t, ids, 1)
		claims := decodeJWTPayload(t, res.body["agent_token"].(string))
		assert.Equal(t, "aauth:"+ids[0]["id"].(string)+"@"+aauthHost, claims["sub"])
		assert.Equal(t, k.x, claims["cnf"].(map[string]any)["jwk"].(map[string]any)["x"])
	})

	t.Run("adopt does not opt the agent in to AAuth: its policy must list aauth_agent", func(t *testing.T) {
		a, tn := newAAuthFirstContactFed(t, adoptSettings, "client_credentials")
		res := a.bootstrap(t, newAgentKey(t), a.assertion(t, nil))
		assert.Equal(t, http.StatusForbidden, res.status, "body=%v", res.body)
		assert.Equal(t, "access_denied", res.body["error"])
		assert.Len(t, tn.firstContactIdentities(t), 1, "registered, but issued nothing")
	})
}

// subagent asks for a sub-agent token for child, signed by parentKey with
// parentToken; disc may be empty.
func (a *aauthFed) subagent(t *testing.T, parentKey agentKey, parentToken string, child agentKey, disc string) apResponse {
	t.Helper()
	body := map[string]any{"jwk": map[string]string{"kty": "OKP", "crv": "Ed25519", "x": child.x, "alg": "Ed25519"}}
	if disc != "" {
		body["discriminator"] = disc
	}
	b, err := json.Marshal(body)
	require.NoError(t, err)
	return a.do(t, a.signedSubagent(t, parentKey, parentToken, string(b)))
}

func TestAAuthSubagents(t *testing.T) {
	a := newAAuthFed(t, "aauth_agent", "aauth_subagent", "aauth_bridge")
	enroll := func(t *testing.T) (agentKey, string) {
		t.Helper()
		k := newAgentKey(t)
		res := a.bootstrap(t, k, a.assertion(t, nil))
		require.Equal(t, http.StatusOK, res.status, "body=%v", res.body)
		return k, res.body["agent_token"].(string)
	}

	t.Run("a parent gets a sub-agent token for the sub-agent's own key", func(t *testing.T) {
		pk, parent := enroll(t)
		child := newAgentKey(t)
		res := a.subagent(t, pk, parent, child, "search1")
		require.Equal(t, http.StatusOK, res.status, "body=%v", res.body)

		pc := decodeJWTPayload(t, parent)
		sc := decodeJWTPayload(t, res.body["agent_token"].(string))
		assert.Equal(t, "aa-agent+jwt", decodeJWTHeader(t, res.body["agent_token"].(string))["typ"])
		assert.Equal(t, pc["iss"], sc["iss"], "a sub-agent's iss is its parent's")
		assert.Equal(t, "aauth:"+a.agent+"+search1@"+aauthHost, sc["sub"])
		assert.Equal(t, pc["sub"], sc["parent_agent"])
		assert.Equal(t, child.x, sc["cnf"].(map[string]any)["jwk"].(map[string]any)["x"])
		assert.LessOrEqual(t, sc["exp"].(float64), pc["exp"].(float64), "never outlives its parent")

		row := a.credential(t, sc["jti"].(string))
		require.NotNil(t, row)
		assert.Equal(t, "aauth_subagent", row["grant_type"])
	})

	t.Run("without a discriminator, the Agent Provider picks one", func(t *testing.T) {
		pk, parent := enroll(t)
		res := a.subagent(t, pk, parent, newAgentKey(t), "")
		require.Equal(t, http.StatusOK, res.status, "body=%v", res.body)
		sub := decodeJWTPayload(t, res.body["agent_token"].(string))["sub"].(string)
		assert.Regexp(t, `^aauth:`+a.agent+`\+[A-Za-z0-9_-]{8}@`+regexp.QuoteMeta(aauthHost)+`$`, sub)
	})

	t.Run("a sub-agent may not have sub-agents", func(t *testing.T) {
		pk, parent := enroll(t)
		child := newAgentKey(t)
		res := a.subagent(t, pk, parent, child, "c1")
		require.Equal(t, http.StatusOK, res.status)
		grand := a.subagent(t, child, res.body["agent_token"].(string), newAgentKey(t), "c2")
		assert.Equal(t, http.StatusForbidden, grand.status, "body=%v", grand.body)
		assert.Equal(t, "denied", grand.body["error"])
	})

	t.Run("bad requests are refused", func(t *testing.T) {
		pk, parent := enroll(t)
		same := a.subagent(t, pk, parent, pk, "self")
		assert.Equal(t, http.StatusBadRequest, same.status, "a sub-agent never holds its parent's key")
		plus := a.subagent(t, pk, parent, newAgentKey(t), "a+b")
		assert.Equal(t, http.StatusBadRequest, plus.status, "+ delimits the discriminator")
		assert.Equal(t, "application/problem+json", plus.headers.Get("Content-Type"))
		assert.Equal(t, "invalid_request", plus.body["error"])
	})

	t.Run("only the parent's own key, under the jwt scheme, may ask", func(t *testing.T) {
		pk, parent := enroll(t)
		_ = pk
		thief := newAgentKey(t)
		res := a.subagent(t, thief, parent, newAgentKey(t), "x")
		assert.Equal(t, http.StatusUnauthorized, res.status, "signed by a key the token does not bind")
		assert.NotEmpty(t, res.headers.Get("Signature-Error"))

		hwk := a.do(t, a.signedAP(t, pk, "/ap/subagent",
			fmt.Sprintf(`sig=hwk;kty="OKP";crv="Ed25519";x="%s";alg="Ed25519"`, pk.x), `{}`, aauthHost, time.Now()))
		assert.Equal(t, http.StatusUnauthorized, hwk.status)
		assert.Contains(t, hwk.headers.Get("Signature-Error"), "unsupported_scheme")
	})

	t.Run("revoking the parent revokes its sub-agents, and it can spawn no more", func(t *testing.T) {
		pk, parent := enroll(t)
		res := a.subagent(t, pk, parent, newAgentKey(t), "r1")
		require.Equal(t, http.StatusOK, res.status)
		childJTI := decodeJWTPayload(t, res.body["agent_token"].(string))["jti"].(string)
		parentRow := a.credential(t, decodeJWTPayload(t, parent)["jti"].(string))
		status, body := a.f.call(t, http.MethodPost, "/credentials/"+parentRow["id"].(string)+"/revoke",
			map[string]any{"reason": "test"}, a.tn.headers)
		require.Contains(t, []int{http.StatusOK, http.StatusNoContent}, status, "revoke: %v", body)
		assert.Equal(t, true, a.credential(t, childJTI)["is_revoked"], "cascade through parent_jti")

		again := a.subagent(t, pk, parent, newAgentKey(t), "r2")
		assert.Equal(t, http.StatusUnauthorized, again.status)
		assert.Contains(t, again.headers.Get("Signature-Error"), "revoked_jwt")
	})

	t.Run("a sub-agent token cannot be bridged to OAuth", func(t *testing.T) {
		pk, parent := enroll(t)
		child := newAgentKey(t)
		res := a.subagent(t, pk, parent, child, "b1")
		require.Equal(t, http.StatusOK, res.status)
		bridged := a.bridge(t, res.body["agent_token"].(string), &child, nil)
		assert.Equal(t, http.StatusBadRequest, bridged.status)
		assert.Equal(t, "invalid_grant", bridged.body["error"])
	})

	t.Run("one parent's live sub-agents are bounded", func(t *testing.T) {
		pk, parent := enroll(t)
		for i := 0; i < 16; i++ {
			res := a.subagent(t, pk, parent, newAgentKey(t), fmt.Sprintf("n%d", i))
			require.Equal(t, http.StatusOK, res.status, "sub-agent %d: %v", i, res.body)
		}
		over := a.subagent(t, pk, parent, newAgentKey(t), "n16")
		assert.Equal(t, http.StatusForbidden, over.status)
		assert.Equal(t, "denied", over.body["error"])
	})

	t.Run("a policy that does not list aauth_subagent is not opted in", func(t *testing.T) {
		off := newAAuthFed(t, "aauth_agent")
		k := newAgentKey(t)
		res := off.bootstrap(t, k, off.assertion(t, nil))
		require.Equal(t, http.StatusOK, res.status)
		sub := off.subagent(t, k, res.body["agent_token"].(string), newAgentKey(t), "x")
		assert.Equal(t, http.StatusForbidden, sub.status, "body=%v", sub.body)
		assert.Equal(t, "denied", sub.body["error"])
	})
}

// fakePS is a person server at https://ps.zeroid.test that verifies every
// revocation's signature against the Agent Provider's published key and
// records what it was asked to revoke.
type fakePS struct {
	mode      atomic.Value // "ok", "defer", "fail", "none" (no revocation_endpoint), "unsupported"
	mu        sync.Mutex
	revoked   map[string]int64 // jti -> exp
	polled    int
	sigErrors []string
	apJWKS    func() []byte
	apIssuer  string
	posts     int
}

const fakePSHost = "ps.zeroid.test"

func newFakePS(t *testing.T, a *aauthFed) *fakePS {
	t.Helper()
	ps := &fakePS{revoked: map[string]int64{}, apIssuer: federationIssuer,
		apJWKS: func() []byte { return a.getRaw(t, "/ap/jwks.json") }}
	ps.mode.Store("ok")
	srv := httptest.NewTLSServer(http.HandlerFunc(ps.serve))
	t.Cleanup(srv.Close)
	aauthDialOverrides.Store(fakePSHost+":443", srv.Listener.Addr().String())
	t.Cleanup(func() { aauthDialOverrides.Delete(fakePSHost + ":443") })
	return ps
}

func (ps *fakePS) verify(r *http.Request, body []byte) error {
	_, err := aauthpkg.VerifyRequest(r, body, aauthpkg.VerifyOptions{
		Now: time.Now(), Authority: fakePSHost, RequireBodyCoverage: true, Schemes: []string{"jwks_uri"},
		ResolveKey: func(_ string, params map[string]any) (aauthpkg.JWK, error) {
			if params["id"] != ps.apIssuer || params["dwk"] != "aauth-agent.json" {
				return aauthpkg.JWK{}, fmt.Errorf("unexpected signer %v", params)
			}
			var set struct{ Keys []aauthpkg.JWK }
			if err := json.Unmarshal(ps.apJWKS(), &set); err != nil {
				return aauthpkg.JWK{}, err
			}
			for _, k := range set.Keys {
				if k.Kid == params["kid"] {
					return k, nil
				}
			}
			return aauthpkg.JWK{}, errors.New("no such kid")
		},
	})
	return err
}

func (ps *fakePS) serve(w http.ResponseWriter, r *http.Request) {
	mode := ps.mode.Load().(string)
	body, _ := io.ReadAll(r.Body)
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/.well-known/aauth-person.json":
		md := map[string]any{"issuer": "https://" + fakePSHost, "jwks_uri": "https://" + fakePSHost + "/jwks.json"}
		if mode != "none" {
			md["revocation_endpoint"] = "https://" + fakePSHost + "/revoke"
		}
		_ = json.NewEncoder(w).Encode(md)
	case r.Method == http.MethodPost && r.URL.Path == "/revoke":
		ps.mu.Lock()
		defer ps.mu.Unlock()
		ps.posts++
		if err := ps.verify(r, body); err != nil {
			ps.sigErrors = append(ps.sigErrors, err.Error())
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var req struct {
			JTI string `json:"jti"`
			Exp int64  `json:"exp"`
		}
		_ = json.Unmarshal(body, &req)
		switch mode {
		case "fail":
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		case "unsupported":
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"unsupported_iss"}`))
			return
		}
		ps.revoked[req.JTI] = req.Exp
		if mode == "foreign" {
			w.Header().Set("Location", "https://elsewhere.zeroid.test/pending/"+req.JTI)
			w.WriteHeader(http.StatusAccepted)
			return
		}
		if mode == "defer" {
			w.Header().Set("Location", "/pending/"+req.JTI)
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/pending/"):
		ps.mu.Lock()
		defer ps.mu.Unlock()
		if err := ps.verify(r, nil); err != nil {
			ps.sigErrors = append(ps.sigErrors, "poll: "+err.Error())
			w.WriteHeader(http.StatusNotFound) // another identity polling
			return
		}
		ps.polled++
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (ps *fakePS) state() (map[string]int64, int, []string, int) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	out := map[string]int64{}
	for k, v := range ps.revoked {
		out[k] = v
	}
	return out, ps.polled, append([]string(nil), ps.sigErrors...), ps.posts
}

func TestAAuthPersonServer(t *testing.T) {
	a := newAAuthFed(t, "aauth_agent", "aauth_subagent")
	ps := newFakePS(t, a)
	status, body := a.f.call(t, http.MethodPatch, "/credential-policies/"+a.policy,
		map[string]any{"aauth_person_server": "https://" + fakePSHost}, a.tn.headers)
	require.Equal(t, http.StatusOK, status, "set the policy's person server: %v", body)

	enroll := func(t *testing.T) (agentKey, string) {
		t.Helper()
		k := newAgentKey(t)
		res := a.bootstrap(t, k, a.assertion(t, nil))
		require.Equal(t, http.StatusOK, res.status, "body=%v", res.body)
		return k, res.body["agent_token"].(string)
	}
	revoke := func(t *testing.T, token string) {
		t.Helper()
		row := a.credential(t, decodeJWTPayload(t, token)["jti"].(string))
		require.NotNil(t, row)
		status, body := a.f.call(t, http.MethodPost, "/credentials/"+row["id"].(string)+"/revoke",
			map[string]any{"reason": "test"}, a.tn.headers)
		require.Contains(t, []int{http.StatusOK, http.StatusNoContent}, status, "revoke: %v", body)
	}
	pass := func(t *testing.T) int {
		t.Helper()
		n, err := a.f.srv.RunAAuthPersonServerRevocationsOnce(context.Background())
		require.NoError(t, err)
		return n
	}

	t.Run("policy validation refuses a person server that is not a server identifier", func(t *testing.T) {
		for _, bad := range []string{"http://ps.example", "https://ps.example/", "https://ps.example:8443", "https://PS.example"} {
			status, _ := a.f.call(t, http.MethodPatch, "/credential-policies/"+a.policy,
				map[string]any{"aauth_person_server": bad}, a.tn.headers)
			assert.Equal(t, http.StatusBadRequest, status, bad)
		}
	})

	t.Run("agent and sub-agent tokens carry ps; nothing is sent while they are live", func(t *testing.T) {
		pk, token := enroll(t)
		assert.Equal(t, "https://"+fakePSHost, decodeJWTPayload(t, token)["ps"])
		sub := a.subagent(t, pk, token, newAgentKey(t), "w1")
		require.Equal(t, http.StatusOK, sub.status, "body=%v", sub.body)
		assert.Equal(t, "https://"+fakePSHost, decodeJWTPayload(t, sub.body["agent_token"].(string))["ps"], "copied from the parent")
		pass(t)
		revoked, _, _, _ := ps.state()
		assert.NotContains(t, revoked, decodeJWTPayload(t, token)["jti"])
	})

	t.Run("revoking an agent token revokes it, and its sub-agents, at the person server", func(t *testing.T) {
		pk, token := enroll(t)
		sub := a.subagent(t, pk, token, newAgentKey(t), "w2")
		require.Equal(t, http.StatusOK, sub.status)
		parentJTI := decodeJWTPayload(t, token)["jti"].(string)
		childClaims := decodeJWTPayload(t, sub.body["agent_token"].(string))

		revoke(t, token)
		assert.GreaterOrEqual(t, pass(t), 2)
		revoked, _, sigErrs, _ := ps.state()
		assert.Empty(t, sigErrs, "every revocation verifies as signed by the Agent Provider")
		assert.EqualValues(t, decodeJWTPayload(t, token)["exp"], revoked[parentJTI], "exp is the token's own")
		assert.EqualValues(t, childClaims["exp"], revoked[childClaims["jti"].(string)], "the cascade reaches the person server too")

		_, _, _, posts := ps.state()
		pass(t)
		_, _, _, again := ps.state()
		assert.Equal(t, posts, again, "a delivered revocation is not sent again")
	})

	t.Run("a deferred revocation is polled with signed requests", func(t *testing.T) {
		ps.mode.Store("defer")
		defer ps.mode.Store("ok")
		_, token := enroll(t)
		revoke(t, token)
		pass(t)
		revoked, polled, sigErrs, _ := ps.state()
		assert.Contains(t, revoked, decodeJWTPayload(t, token)["jti"])
		assert.GreaterOrEqual(t, polled, 1)
		assert.Empty(t, sigErrs)
	})

	t.Run("a 202 pointing at another host is not polled", func(t *testing.T) {
		ps.mode.Store("foreign")
		defer ps.mode.Store("ok")
		_, token := enroll(t)
		revoke(t, token)
		_, polledBefore, _, _ := ps.state()
		assert.Equal(t, 0, pass(t), "no terminal outcome: left to retry")
		_, polled, _, _ := ps.state()
		assert.Equal(t, polledBefore, polled)
	})

	t.Run("an unavailable person server is retried later; one that takes none is not", func(t *testing.T) {
		ps.mode.Store("fail")
		_, token := enroll(t)
		jti := decodeJWTPayload(t, token)["jti"].(string)
		revoke(t, token)
		assert.Equal(t, 0, pass(t), "no terminal outcome")
		_, _, _, posts := ps.state()
		pass(t)
		_, _, _, again := ps.state()
		assert.Equal(t, posts, again, "backed off: not sent again at once")

		ps.mode.Store("unsupported")
		_, token2 := enroll(t)
		revoke(t, token2)
		assert.Equal(t, 1, pass(t), "unsupported_iss is terminal")
		revoked, _, _, _ := ps.state()
		assert.NotContains(t, revoked, jti)
		ps.mode.Store("ok")
	})

	t.Run("suspending an identity above the agent revokes its tokens at the person server", func(t *testing.T) {
		c := newAAuthFed(t, "aauth_agent")
		psC := newFakePS(t, c)
		status, body := c.f.call(t, http.MethodPatch, "/credential-policies/"+c.policy,
			map[string]any{"aauth_person_server": "https://" + fakePSHost}, c.tn.headers)
		require.Equal(t, http.StatusOK, status, "%v", body)
		resp := post(t, adminPath("/identities"), map[string]any{
			"external_id": uid("parent"), "identity_type": "agent", "trust_level": "unverified", "owner_user_id": "user-test-owner",
		}, c.tn.headers)
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		parent := decode(t, resp)["id"].(string)
		_ = resp.Body.Close()
		_, err := testDB.NewUpdate().TableExpr("identities").Set("parent_identity_id = ?", parent).
			Where("id = ?", c.agent).Exec(context.Background())
		require.NoError(t, err)

		res := c.bootstrap(t, newAgentKey(t), c.assertion(t, nil))
		require.Equal(t, http.StatusOK, res.status, "body=%v", res.body)
		jti := decodeJWTPayload(t, res.body["agent_token"].(string))["jti"].(string)
		_, err = c.f.srv.RunAAuthPersonServerRevocationsOnce(context.Background())
		require.NoError(t, err)
		revoked, _, _, _ := psC.state()
		require.NotContains(t, revoked, jti, "nothing is sent while the chain is live")

		status, body = c.f.call(t, http.MethodPatch, "/identities/"+parent, map[string]any{"status": "suspended"}, c.tn.headers)
		require.Equal(t, http.StatusOK, status, "suspend the parent: %v", body)
		assert.Equal(t, false, c.credential(t, jti)["is_revoked"], "suspending an ancestor revokes nothing")
		// The chain is re-checked at most once a minute; make this one due.
		_, err = testDB.NewUpdate().TableExpr("aauth_ps_revocations").Set("next_check_at = NOW()").
			Where("jti = ?", jti).Exec(context.Background())
		require.NoError(t, err)
		_, err = c.f.srv.RunAAuthPersonServerRevocationsOnce(context.Background())
		require.NoError(t, err)
		revoked, _, _, _ = psC.state()
		assert.Contains(t, revoked, jti, "an agent whose ancestor stopped is revoked at its person server")
	})

	t.Run("deactivating the identity revokes its tokens at the person server", func(t *testing.T) {
		b := newAAuthFed(t, "aauth_agent")
		psB := newFakePS(t, b)
		status, body := b.f.call(t, http.MethodPatch, "/credential-policies/"+b.policy,
			map[string]any{"aauth_person_server": "https://" + fakePSHost}, b.tn.headers)
		require.Equal(t, http.StatusOK, status, "%v", body)
		k := newAgentKey(t)
		res := b.bootstrap(t, k, b.assertion(t, nil))
		require.Equal(t, http.StatusOK, res.status)
		status, body = b.f.call(t, http.MethodDelete, "/identities/"+b.agent, nil, b.tn.headers)
		require.Equal(t, http.StatusOK, status, "deactivate: %v", body)
		_, err := b.f.srv.RunAAuthPersonServerRevocationsOnce(context.Background())
		require.NoError(t, err)
		revoked, _, _, _ := psB.state()
		assert.Contains(t, revoked, decodeJWTPayload(t, res.body["agent_token"].(string))["jti"])
	})
}

func TestAAuthRateLimits(t *testing.T) {
	a := newAAuthFedWith(t, func(c *zeroid.Config) { c.AAuth.RequestsPerMinute = 3 }, "aauth_agent", "aauth_subagent")

	t.Run("one workload subject's enrollments are limited", func(t *testing.T) {
		var last apResponse
		for i := 0; i < 4; i++ {
			last = a.bootstrap(t, newAgentKey(t), a.assertion(t, nil))
		}
		assert.Equal(t, http.StatusTooManyRequests, last.status, "body=%v", last.body)
		assert.Equal(t, "rate_limited", last.body["error"])
		assert.NotEmpty(t, last.headers.Get("Retry-After"))
		assert.Empty(t, last.headers.Get("Signature-Error"), "the signature verified; this is not a signature failure")

		// Another workload subject has its own limit.
		other := "system:serviceaccount:agents:" + uid("other")
		status, body := a.f.bind(t, a.tn, a.rowID, other, a.agent, false)
		require.Equal(t, http.StatusCreated, status, "bind: %v", body)
		res := a.bootstrap(t, newAgentKey(t), a.assertion(t, map[string]any{"sub": other}))
		assert.Equal(t, http.StatusOK, res.status, "body=%v", res.body)
	})
}

// namingJWT is a jkt-jwt naming JWT: durable delegates to ephemeral until
// exp (bootstrap draft, two-key refresh).
func namingJWT(t *testing.T, durable, ephemeral agentKey, exp time.Time) string {
	t.Helper()
	enc := func(v any) string {
		b, err := json.Marshal(v)
		require.NoError(t, err)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	jwkOf := func(k agentKey) map[string]string {
		return map[string]string{"kty": "OKP", "crv": "Ed25519", "x": k.x, "alg": "Ed25519"}
	}
	signing := enc(map[string]any{"typ": "jkt-s256+jwt", "alg": "Ed25519", "jwk": jwkOf(durable)}) + "." +
		enc(map[string]any{"iss": "urn:jkt:sha-256:" + durable.thumbprint(), "iat": time.Now().Unix(), "exp": exp.Unix(),
			"jti": uid("naming"), "cnf": map[string]any{"jwk": jwkOf(ephemeral)}})
	return signing + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(durable.priv, []byte(signing)))
}

// refresh posts to /ap/refresh signed by ephemeral under jkt-jwt with naming.
func (a *aauthFed) refresh(t *testing.T, ephemeral agentKey, naming string) apResponse {
	t.Helper()
	return a.do(t, a.signedAP(t, ephemeral, "/ap/refresh", `sig=jkt-jwt;jwt="`+naming+`"`, `{}`, aauthHost, time.Now()))
}

func TestAAuthRefresh(t *testing.T) {
	a := newAAuthFed(t, "aauth_agent", "aauth_refresh", "aauth_bridge")
	enroll := func(t *testing.T, a *aauthFed, sub string) (agentKey, string) {
		t.Helper()
		durable := newAgentKey(t)
		var extra map[string]any
		if sub != "" {
			extra = map[string]any{"sub": sub}
		}
		res := a.bootstrap(t, durable, a.assertion(t, extra))
		require.Equal(t, http.StatusOK, res.status, "body=%v", res.body)
		return durable, res.body["agent_token"].(string)
	}

	t.Run("an enrolled key refreshes to a token bound to a fresh ephemeral key", func(t *testing.T) {
		durable, root := enroll(t, a, "")
		eph := newAgentKey(t)
		res := a.refresh(t, eph, namingJWT(t, durable, eph, time.Now().Add(5*time.Minute)))
		require.Equal(t, http.StatusOK, res.status, "body=%v", res.body)
		claims := decodeJWTPayload(t, res.body["agent_token"].(string))
		assert.Equal(t, decodeJWTPayload(t, root)["sub"], claims["sub"], "the agent identifier is stable across refreshes")
		assert.Equal(t, eph.x, claims["cnf"].(map[string]any)["jwk"].(map[string]any)["x"])
		refreshedRow := a.credential(t, claims["jti"].(string))
		assert.Equal(t, "aauth_agent", refreshedRow["grant_type"])
		rootRow := a.credential(t, decodeJWTPayload(t, root)["jti"].(string))
		require.NotEmpty(t, rootRow["mission_id"])
		assert.Equal(t, rootRow["mission_id"], refreshedRow["mission_id"], "a refresh stays in the enrollment's delegation tree")

		// The refreshed token is a full agent token: it bridges, with the
		// ephemeral key as its DPoP key.
		bridged := a.bridge(t, res.body["agent_token"].(string), &eph, nil)
		assert.Equal(t, http.StatusOK, bridged.status, "body=%v", bridged.body)

		// And the durable key refreshes again to another ephemeral key.
		eph2 := newAgentKey(t)
		again := a.refresh(t, eph2, namingJWT(t, durable, eph2, time.Now().Add(5*time.Minute)))
		assert.Equal(t, http.StatusOK, again.status, "body=%v", again.body)
	})

	t.Run("a naming JWT is single use", func(t *testing.T) {
		durable, _ := enroll(t, a, "")
		eph := newAgentKey(t)
		naming := namingJWT(t, durable, eph, time.Now().Add(5*time.Minute))
		require.Equal(t, http.StatusOK, a.refresh(t, eph, naming).status)
		replay := a.refresh(t, eph, naming)
		assert.Equal(t, http.StatusUnauthorized, replay.status)
		assert.Contains(t, replay.headers.Get("Signature-Error"), "invalid_jwt")
	})

	t.Run("bad naming JWTs and unenrolled keys are refused", func(t *testing.T) {
		durable, _ := enroll(t, a, "")
		eph := newAgentKey(t)
		long := a.refresh(t, eph, namingJWT(t, durable, eph, time.Now().Add(time.Hour)))
		assert.Equal(t, http.StatusUnauthorized, long.status, "a naming JWT living an hour")

		thief := newAgentKey(t)
		wrongSigner := a.refresh(t, thief, namingJWT(t, durable, eph, time.Now().Add(5*time.Minute)))
		assert.Equal(t, http.StatusUnauthorized, wrongSigner.status, "signed by a key the naming JWT does not name")

		stranger := newAgentKey(t)
		eph2 := newAgentKey(t)
		unknown := a.refresh(t, eph2, namingJWT(t, stranger, eph2, time.Now().Add(5*time.Minute)))
		assert.Equal(t, http.StatusForbidden, unknown.status)
		assert.Equal(t, "denied", unknown.body["error"])
	})

	t.Run("revoking the enrollment's first token stops refresh and revokes every refreshed token", func(t *testing.T) {
		durable, root := enroll(t, a, "")
		eph := newAgentKey(t)
		res := a.refresh(t, eph, namingJWT(t, durable, eph, time.Now().Add(5*time.Minute)))
		require.Equal(t, http.StatusOK, res.status)
		refreshedJTI := decodeJWTPayload(t, res.body["agent_token"].(string))["jti"].(string)

		rootRow := a.credential(t, decodeJWTPayload(t, root)["jti"].(string))
		status, body := a.f.call(t, http.MethodPost, "/credentials/"+rootRow["id"].(string)+"/revoke",
			map[string]any{"reason": "test"}, a.tn.headers)
		require.Contains(t, []int{http.StatusOK, http.StatusNoContent}, status, "revoke: %v", body)
		assert.Equal(t, true, a.credential(t, refreshedJTI)["is_revoked"], "cascade from the root")

		eph2 := newAgentKey(t)
		again := a.refresh(t, eph2, namingJWT(t, durable, eph2, time.Now().Add(5*time.Minute)))
		assert.Equal(t, http.StatusForbidden, again.status)
	})

	t.Run("revoking the agent's current token stops refresh, whatever became of the first", func(t *testing.T) {
		durable, _ := enroll(t, a, "")
		eph := newAgentKey(t)
		res := a.refresh(t, eph, namingJWT(t, durable, eph, time.Now().Add(5*time.Minute)))
		require.Equal(t, http.StatusOK, res.status)
		current := a.credential(t, decodeJWTPayload(t, res.body["agent_token"].(string))["jti"].(string))
		status, body := a.f.call(t, http.MethodPost, "/credentials/"+current["id"].(string)+"/revoke",
			map[string]any{"reason": "key compromised"}, a.tn.headers)
		require.Contains(t, []int{http.StatusOK, http.StatusNoContent}, status, "revoke: %v", body)

		eph2 := newAgentKey(t)
		again := a.refresh(t, eph2, namingJWT(t, durable, eph2, time.Now().Add(5*time.Minute)))
		assert.Equal(t, http.StatusForbidden, again.status, "the durable key is cut off")
		// A fresh platform token enrolls the key again.
		res = a.bootstrap(t, durable, a.assertion(t, nil))
		require.Equal(t, http.StatusOK, res.status, "body=%v", res.body)
		eph3 := newAgentKey(t)
		assert.Equal(t, http.StatusOK, a.refresh(t, eph3, namingJWT(t, durable, eph3, time.Now().Add(5*time.Minute))).status)
	})

	t.Run("ZeroID's own fail-closed revocations do not cut off the durable key", func(t *testing.T) {
		durable, _ := enroll(t, a, "")
		eph := newAgentKey(t)
		res := a.refresh(t, eph, namingJWT(t, durable, eph, time.Now().Add(5*time.Minute)))
		require.Equal(t, http.StatusOK, res.status)
		// As when a re-check after issuance hit a database error.
		row := a.credential(t, decodeJWTPayload(t, res.body["agent_token"].(string))["jti"].(string))
		status, body := a.f.call(t, http.MethodPost, "/credentials/"+row["id"].(string)+"/revoke",
			map[string]any{"reason": "aauth-internal: enrollment not confirmed live after refresh"}, a.tn.headers)
		require.Contains(t, []int{http.StatusOK, http.StatusNoContent}, status, "revoke: %v", body)

		eph2 := newAgentKey(t)
		again := a.refresh(t, eph2, namingJWT(t, durable, eph2, time.Now().Add(5*time.Minute)))
		assert.Equal(t, http.StatusOK, again.status, "body=%v", again.body)
	})

	t.Run("disabling the binding stops refresh", func(t *testing.T) {
		sub := "system:serviceaccount:agents:" + uid("sa")
		status, b := a.f.bind(t, a.tn, a.rowID, sub, a.agent, false)
		require.Equal(t, http.StatusCreated, status, "%v", b)
		durable, _ := enroll(t, a, sub)
		first := newAgentKey(t)
		require.Equal(t, http.StatusOK, a.refresh(t, first, namingJWT(t, durable, first, time.Now().Add(5*time.Minute))).status,
			"refresh works while the binding is enabled")
		status, body := a.f.call(t, http.MethodPatch, "/external-issuers/"+a.rowID+"/bindings/"+b["id"].(string),
			map[string]any{"enabled": false}, a.tn.headers)
		require.Equal(t, http.StatusOK, status, "%v", body)
		eph := newAgentKey(t)
		res := a.refresh(t, eph, namingJWT(t, durable, eph, time.Now().Add(5*time.Minute)))
		assert.Equal(t, http.StatusForbidden, res.status, "a refresh re-checks what the platform token proved")
	})

	t.Run("a policy that does not list aauth_refresh enrolls no key", func(t *testing.T) {
		off := newAAuthFed(t, "aauth_agent")
		durable, _ := enroll(t, off, "")
		eph := newAgentKey(t)
		res := off.refresh(t, eph, namingJWT(t, durable, eph, time.Now().Add(5*time.Minute)))
		assert.Equal(t, http.StatusForbidden, res.status)
		assert.Equal(t, "denied", res.body["error"])
	})
}

// TestAAuthKeyRotation: ZeroID restarted with a new signing key, the old one
// retired, still honours agent tokens the old key signed, publishes both, and
// signs new tokens with the new key.
func TestAAuthKeyRotation(t *testing.T) {
	var oldPath string
	a := newAAuthFedWith(t, func(c *zeroid.Config) { oldPath = c.AAuth.SigningKeyPath }, "aauth_agent", "aauth_bridge")
	k := newAgentKey(t)
	res := a.bootstrap(t, k, a.assertion(t, nil))
	require.Equal(t, http.StatusOK, res.status, "body=%v", res.body)
	oldToken := res.body["agent_token"].(string)
	oldKid := decodeJWTHeader(t, oldToken)["kid"]

	// The same database, a new key, the old one retired.
	f := &dbFederation{idp: a.f.idp, idpSrv: a.f.idpSrv, idpURL: a.f.idpURL, members: map[string]string{}}
	f.srv, f.http = newAAuthServer(t, func(c *zeroid.Config) { c.AAuth.RetiredSigningKeyPaths = []string{oldPath} })
	wf := *a.workloadFed
	wf.f = f
	b := &aauthFed{workloadFed: &wf}

	var set struct{ Keys []map[string]any }
	require.NoError(t, json.Unmarshal(b.getRaw(t, "/ap/jwks.json"), &set))
	require.Len(t, set.Keys, 2)
	assert.Equal(t, oldKid, set.Keys[1]["kid"], "the retired key is still published")

	bridged := b.bridge(t, oldToken, &k, nil)
	assert.Equal(t, http.StatusOK, bridged.status, "an agent token signed before the rotation is still honoured: %v", bridged.body)

	k2 := newAgentKey(t)
	res = b.bootstrap(t, k2, b.assertion(t, nil))
	require.Equal(t, http.StatusOK, res.status, "body=%v", res.body)
	assert.Equal(t, set.Keys[0]["kid"], decodeJWTHeader(t, res.body["agent_token"].(string))["kid"], "new tokens use the new key")
	assert.NotEqual(t, oldKid, set.Keys[0]["kid"])
}

// TestAAuthPersonServerReplicas: two ZeroID instances on one database run a
// revocation pass at the same moment; each revocation reaches the person
// server once.
func TestAAuthPersonServerReplicas(t *testing.T) {
	var keyPath string
	a := newAAuthFedWith(t, func(c *zeroid.Config) { keyPath = c.AAuth.SigningKeyPath }, "aauth_agent")
	ps := newFakePS(t, a)
	status, body := a.f.call(t, http.MethodPatch, "/credential-policies/"+a.policy,
		map[string]any{"aauth_person_server": "https://" + fakePSHost}, a.tn.headers)
	require.Equal(t, http.StatusOK, status, "%v", body)

	const n = 6
	for i := 0; i < n; i++ {
		res := a.bootstrap(t, newAgentKey(t), a.assertion(t, nil))
		require.Equal(t, http.StatusOK, res.status, "body=%v", res.body)
		row := a.credential(t, decodeJWTPayload(t, res.body["agent_token"].(string))["jti"].(string))
		status, body := a.f.call(t, http.MethodPost, "/credentials/"+row["id"].(string)+"/revoke",
			map[string]any{"reason": "test"}, a.tn.headers)
		require.Contains(t, []int{http.StatusOK, http.StatusNoContent}, status, "revoke: %v", body)
	}

	// A second instance: the same database and signing key.
	replica, _ := newAAuthServer(t, func(c *zeroid.Config) { c.AAuth.SigningKeyPath = keyPath })
	var wg sync.WaitGroup
	done := make([]int, 2)
	for i, srv := range []*zeroid.Server{a.f.srv, replica} {
		wg.Add(1)
		go func(i int, srv *zeroid.Server) {
			defer wg.Done()
			got, err := srv.RunAAuthPersonServerRevocationsOnce(context.Background())
			assert.NoError(t, err)
			done[i] = got
		}(i, srv)
	}
	wg.Wait()
	revoked, _, sigErrs, posts := ps.state()
	assert.Empty(t, sigErrs)
	assert.Len(t, revoked, n)
	assert.Equal(t, n, posts, "each revocation was sent once, not once per instance")
	assert.Equal(t, n, done[0]+done[1])
}

// TestAAuthConcurrency: parallel enrollments and sub-agent requests all
// succeed, with no server errors.
func TestAAuthConcurrency(t *testing.T) {
	a := newAAuthFedWith(t, func(c *zeroid.Config) { c.AAuth.RequestsPerMinute = 1000; c.AAuth.MaxLiveSubagents = 1000 },
		"aauth_agent", "aauth_subagent")
	const n = 40
	statuses := make([]int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			statuses[i] = a.bootstrap(t, newAgentKey(t), a.assertion(t, nil)).status
		}(i)
	}
	wg.Wait()
	for i, s := range statuses {
		assert.Equal(t, http.StatusOK, s, "enrollment %d", i)
	}

	pk := newAgentKey(t)
	res := a.bootstrap(t, pk, a.assertion(t, nil))
	require.Equal(t, http.StatusOK, res.status)
	parent := res.body["agent_token"].(string)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			statuses[i] = a.subagent(t, pk, parent, newAgentKey(t), fmt.Sprintf("p%d", i)).status
		}(i)
	}
	wg.Wait()
	for i, s := range statuses {
		assert.Equal(t, http.StatusOK, s, "sub-agent %d", i)
	}
}
