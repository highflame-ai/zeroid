// Package interop checks ZeroID's AAuth Agent Provider against aauth-go, the
// reference implementation, in-process and with nothing leaving the machine:
//
//   - aauth-go's agentprovider client enrolls at ZeroID's POST /ap/token,
//     signing with aauth-go's own RFC 9421 signer;
//   - aauth-go's agent transport presents the ZeroID-issued agent token to a
//     resource guarded by aauth-go's ResourceGuard, which verifies it by
//     discovering ZeroID's metadata and JWKS itself;
//   - the bridged, DPoP-bound OAuth token reaches an OAuth-only resource,
//     and stops working when the agent token is revoked.
//
// Run with GOWORK=off from examples/aauth. Needs Docker (Postgres).
package interop

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	aauth "github.com/aauth-dev/aauth-go"
	"github.com/aauth-dev/aauth-go/agentprovider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	zeroid "github.com/highflame-ai/zeroid"
	"github.com/highflame-ai/zeroid/examples/aauth/demo"
	"github.com/highflame-ai/zeroid/internal/mockidp"
)

const (
	zeroidHost   = "zeroid.test"
	resourceHost = "resource.test"
	issuer       = "https://" + zeroidHost
	resource     = "https://" + resourceHost
)

// env is ZeroID, the mock cluster and the demo resource, each over TLS
// under its own host name, reached through one client that maps the names
// to the in-process servers.
type env struct {
	zeroidURL string // ZeroID by name; the client maps it to the in-process server
	client    *http.Client
	idp       *mockidp.IdP
	headers   map[string]string
	sub       string
	agentID   string
}

func TestAAuthInterop(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	key, err := demo.LoadOrCreateKey(filepath.Join(t.TempDir(), "pod", "agent.key"))
	require.NoError(t, err)
	platform := e.platformToken(t)

	// 1. aauth-go's agent-provider client enrolls at ZeroID.
	ap := &agentprovider.Client{BaseURL: issuer, HTTPClient: e.client}
	issued, err := ap.Issue(ctx, key, map[string]string{"attestation": platform})
	require.NoError(t, err, "aauth-go's client enrolls at ZeroID's /ap/token")
	assert.EqualValues(t, 900, issued.ExpiresIn)

	agent, err := ap.Enroll(ctx, key, map[string]string{"attestation": platform})
	require.NoError(t, err, "the same key redeems the pod's platform token again")
	assert.Equal(t, "aauth:"+e.agentID+"@"+zeroidHost, agent.ID.String())

	// 2. aauth-go's transport presents the agent token to an aauth-go guard,
	// which verifies it from ZeroID's published metadata and JWKS.
	transport := aauth.NewTransport(agent, nil)
	transport.Base = e.client.Transport
	agentClient := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	resp, err := agentClient.Get(resource + "/whoami")
	require.NoError(t, err)
	body := readJSON(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode, "body=%v", body)
	assert.Equal(t, "aauth:"+e.agentID+"@"+zeroidHost, body["agent"])
	assert.Equal(t, issuer, body["agent_issuer"])
	assert.Equal(t, aauth.TypAgent, body["token_type"])

	// 3. The bridge: the agent token for a DPoP-bound OAuth token, accepted
	// by the OAuth-only resource.
	agentToken, err := agent.MintToken()
	require.NoError(t, err)
	access, err := demo.Bridge(ctx, e.client, issuer, agentToken, key, resource, "tools:read")
	require.NoError(t, err)
	out, err := demo.CallMCP(ctx, e.client, resource+"/mcp", access, key, "search")
	require.NoError(t, err, "the bridged token works at the OAuth resource")
	assert.Contains(t, fmt.Sprint(out["result"]), "ran search")

	// A stolen bridged token without the key is useless.
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	_, err = demo.CallMCP(ctx, e.client, resource+"/mcp", access, otherKey, "search")
	requireStatus(t, err, http.StatusUnauthorized, "a DPoP proof by another key")

	// 4. Revoking the agent token stops the bridged token at once.
	e.revokeAgentToken(t, agentToken)
	_, err = demo.CallMCP(ctx, e.client, resource+"/mcp", access, key, "search")
	requireStatus(t, err, http.StatusUnauthorized, "the bridged token died with its agent token")
}

func TestAAuthInteropRefusesAStolenPlatformToken(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	platform := e.platformToken(t)

	_, owner, _ := ed25519.GenerateKey(rand.Reader)
	_, thief, _ := ed25519.GenerateKey(rand.Reader)
	ap := &agentprovider.Client{BaseURL: issuer, HTTPClient: e.client}
	_, err := ap.Issue(ctx, owner, map[string]string{"attestation": platform})
	require.NoError(t, err)
	_, err = ap.Issue(ctx, thief, map[string]string{"attestation": platform})
	require.Error(t, err, "the pod's platform token is bound to the pod's key")
	assert.Contains(t, err.Error(), "403")
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()

	pg, err := tcpostgres.Run(ctx, "postgres:14-alpine",
		tcpostgres.WithDatabase("zeroid"), tcpostgres.WithUsername("zeroid"), tcpostgres.WithPassword("zeroid"),
		testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).WithStartupTimeout(60*time.Second)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = pg.Terminate(ctx) })
	dbURL, err := pg.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	ca := newCA(t)
	idp, err := mockidp.New("https://placeholder")
	require.NoError(t, err)
	idpSrv := httptest.NewTLSServer(idp.Handler())
	t.Cleanup(idpSrv.Close)
	idp.SetBaseURL(idpSrv.URL)

	cfg := zeroid.Config{
		Server:   zeroid.ServerConfig{Port: "0", Env: "test", ShutdownTimeoutSeconds: 5},
		Database: zeroid.DatabaseConfig{URL: dbURL, MaxOpenConns: 5, MaxIdleConns: 2},
		Keys:     writeServerKeys(t, dir),
		Token: zeroid.TokenConfig{
			Issuer: issuer, DefaultTTL: 3600, MaxTTL: 86400, HMACSecret: strings.Repeat("s", 32), AuthCodeIssuer: issuer,
			// The demo resource introspects without client credentials.
			AllowUnauthenticatedTokenInspection: true,
		},
		Telemetry:   zeroid.TelemetryConfig{Enabled: false},
		Logging:     zeroid.LoggingConfig{Level: "warn"},
		WIMSEDomain: "zeroid.test",
		Federation:  zeroid.FederationConfig{IssuerStore: "db", AllowPrivateEndpoints: true},
		AAuth:       zeroid.AAuthConfig{Enabled: true, SigningKeyPath: writeEd25519Key(t, dir), Name: "ZeroID interop"},
	}
	idpClient := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: certPool(idpSrv.Certificate())}}}
	srv, err := zeroid.NewServer(cfg, zeroid.WithExternalIssuerHTTPClient(idpClient))
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Shutdown(ctx) })
	zeroidSrv := ca.serve(t, zeroidHost, srv.Router())

	// One client that reaches every host by name over verified TLS.
	addrs := map[string]string{}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: ca.pool},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if mapped, ok := addrs[addr]; ok {
				addr = mapped
			}
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}}
	addrs[zeroidHost+":443"] = zeroidSrv.Listener.Addr().String()

	res, err := demo.NewResource(demo.ResourceConfig{Resource: resource, AgentProviders: []string{issuer}, ZeroIDIssuer: issuer, HTTPClient: client})
	require.NoError(t, err)
	resourceSrv := ca.serve(t, resourceHost, res)
	addrs[resourceHost+":443"] = resourceSrv.Listener.Addr().String()

	e := &env{zeroidURL: issuer, client: client, idp: idp,
		headers: map[string]string{"X-Account-ID": "acct-interop", "X-Project-ID": "proj-interop"},
		sub:     "system:serviceaccount:agents:planner"}
	e.seed(t)
	return e
}

// seed creates what an admin sets up once: a policy that opts into AAuth, an
// identity, the cluster's issuer row and the service account's binding.
func (e *env) seed(t *testing.T) {
	t.Helper()
	policy := e.admin(t, http.MethodPost, "/credential-policies", map[string]any{
		"name": "aauth", "allowed_grant_types": []string{"aauth_agent", "aauth_bridge"},
		"allowed_scopes": []string{"tools:read"}, "max_ttl_seconds": 3600,
	}, http.StatusCreated)
	identity := e.admin(t, http.MethodPost, "/identities", map[string]any{
		"external_id": "planner", "identity_type": "agent", "trust_level": "unverified",
		"owner_user_id": "user-1", "credential_policy_id": policy["id"],
	}, http.StatusCreated)
	e.agentID = identity["id"].(string)
	row := e.admin(t, http.MethodPost, "/external-issuers", map[string]any{
		"kind": "workload", "display_name": "Mock cluster", "issuer": e.idp.K8sIssuer(), "audiences": []string{issuer},
	}, http.StatusCreated)
	e.admin(t, http.MethodPost, "/external-issuers/"+row["id"].(string)+"/bindings", map[string]any{
		"subject_key": e.sub, "identity_id": e.agentID,
	}, http.StatusCreated)
}

func (e *env) platformToken(t *testing.T) string {
	t.Helper()
	tok, _, err := e.idp.Mint(mockidp.MintRequest{Profile: mockidp.ProfileK8sServiceAccount,
		Claims: map[string]any{"sub": e.sub, "aud": issuer, "jti": fmt.Sprint(time.Now().UnixNano())}})
	require.NoError(t, err)
	return tok
}

func (e *env) revokeAgentToken(t *testing.T, agentToken string) {
	t.Helper()
	claims := decodePayload(t, agentToken)
	list := e.admin(t, http.MethodGet, "/credentials?identity_id="+e.agentID, nil, http.StatusOK)
	for _, c := range list["credentials"].([]any) {
		cred := c.(map[string]any)
		if cred["jti"] == claims["jti"] {
			e.admin(t, http.MethodPost, "/credentials/"+cred["id"].(string)+"/revoke", map[string]any{"reason": "interop"}, 0)
			return
		}
	}
	t.Fatalf("no credential row for agent token jti %v", claims["jti"])
}

func (e *env) admin(t *testing.T, method, path string, body any, want int) map[string]any {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, e.zeroidURL+path, r)
	require.NoError(t, err)
	req.Host = zeroidHost
	req.Header.Set("Content-Type", "application/json")
	for k, v := range e.headers {
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	require.NoError(t, err)
	out := readJSON(t, resp)
	if want != 0 {
		require.Equal(t, want, resp.StatusCode, "%s %s: %v", method, path, out)
	} else {
		require.Less(t, resp.StatusCode, 300, "%s %s: %v", method, path, out)
	}
	return out
}

func readJSON(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return out
}

func requireStatus(t *testing.T, err error, status int, msg string) {
	t.Helper()
	var se *demo.StatusError
	require.ErrorAs(t, err, &se, msg)
	assert.Equal(t, status, se.Status, "%s: %s", msg, se.Body)
}

func decodePayload(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	raw, err := base64URLDecode(parts[1])
	require.NoError(t, err)
	out := map[string]any{}
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

// testCA issues TLS certificates for the test host names.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "interop CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &testCA{cert: cert, key: key, pool: certPool(cert)}
}

func (c *testCA) serve(t *testing.T, host string, h http.Handler) *httptest.Server {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: host},
		DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	require.NoError(t, err)
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func certPool(certs ...*x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range certs {
		p.AddCert(c)
	}
	return p
}

func writeServerKeys(t *testing.T, dir string) zeroid.KeysConfig {
	t.Helper()
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecDER, err := x509.MarshalECPrivateKey(ec)
	require.NoError(t, err)
	ecPub, err := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	require.NoError(t, err)
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaPub, err := x509.MarshalPKIXPublicKey(&rk.PublicKey)
	require.NoError(t, err)
	write := func(name, typ string, der []byte) string {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600))
		return p
	}
	return zeroid.KeysConfig{
		PrivateKeyPath: write("ec.pem", "EC PRIVATE KEY", ecDER), PublicKeyPath: write("ec.pub", "PUBLIC KEY", ecPub), KeyID: "ec-1",
		RSAPrivateKeyPath: write("rsa.pem", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rk)),
		RSAPublicKeyPath:  write("rsa.pub", "PUBLIC KEY", rsaPub), RSAKeyID: "rsa-1",
	}
}

func writeEd25519Key(t *testing.T, dir string) string {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(k)
	require.NoError(t, err)
	p := filepath.Join(dir, "aauth.pem")
	require.NoError(t, os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600))
	return p
}

func base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
