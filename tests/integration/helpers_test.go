// Package integration_test contains end-to-end integration tests for the
// ZeroID service. Tests spin up a real PostgreSQL container via testcontainers,
// wire the full service stack through zeroid.NewServer, and exercise every
// supported OAuth2 flow through an httptest.Server.
package integration_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"strings"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	zeroid "github.com/highflame-ai/zeroid"
)

const (
	testIssuer    = "https://auth.test.zeroid.dev"
	testKeyID     = "test-key-1"
	testAccountID = "acct-test-001"
	testProjectID = "proj-test-001"
	testWIMSE     = "zeroid.dev"

	// authorization_code / refresh_token test constants.
	testHMACSecret  = "test-hmac-secret-zeroid-32bytes!!"
	testCLIClientID = "zeroid-cli-test"
	testMCPClientID = "zeroid-mcp-test"
	testRedirectURI = "http://localhost:9999/callback"
)

// testServer is the shared httptest.Server for all tests in this package.
var testServer *httptest.Server

// testZeroIDServer is the zeroid.Server instance, exposed for tests that need
// direct access to server methods (e.g., IdentityExists).
var testZeroIDServer *zeroid.Server

// testServerPrivKey is the server's ECDSA signing key, accessible so tests can
// build valid assertions without going through disk files.
var testServerPrivKey *ecdsa.PrivateKey

func TestMain(m *testing.M) {
	os.Exit(runTests(m))
}

func runTests(m *testing.M) int {
	ctx := context.Background()

	// Start a real PostgreSQL container.
	pgContainer, err := tcpostgres.Run(ctx,
		"postgres:14-alpine",
		tcpostgres.WithDatabase("zeroid_test"),
		tcpostgres.WithUsername("zeroid"),
		tcpostgres.WithPassword("zeroid"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "start postgres: %v\n", err)
		return 1
	}
	defer pgContainer.Terminate(ctx) //nolint:errcheck

	dbURL, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		fmt.Fprintf(os.Stderr, "get connection string: %v\n", err)
		return 1
	}

	// Generate the server's ECDSA P-256 key pair and write to temp files.
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate key pair: %v\n", err)
		return 1
	}
	testServerPrivKey = privKey

	privPath, pubPath, cleanKeys, err := writeKeyFiles(privKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "write key files: %v\n", err)
		return 1
	}
	defer cleanKeys()

	// Generate RSA 2048 key pair for RS256 signing (api_key grant).
	rsaPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate RSA key pair: %v\n", err)
		return 1
	}
	rsaPrivPath, rsaPubPath, cleanRSA, err := writeRSAKeyFiles(rsaPrivKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "write RSA key files: %v\n", err)
		return 1
	}
	defer cleanRSA()

	// Build zeroid.Config for the test server.
	cfg := zeroid.Config{
		Server: zeroid.ServerConfig{
			Port:                   "0", // not used — httptest picks a port
			Env:                    "test",
			ShutdownTimeoutSeconds: 5,
		},
		Database: zeroid.DatabaseConfig{
			URL:          dbURL,
			MaxOpenConns: 5,
			MaxIdleConns: 2,
		},
		Keys: zeroid.KeysConfig{
			PrivateKeyPath:    privPath,
			PublicKeyPath:     pubPath,
			KeyID:             testKeyID,
			RSAPrivateKeyPath: rsaPrivPath,
			RSAPublicKeyPath:  rsaPubPath,
			RSAKeyID:          "test-rsa-1",
		},
		Token: zeroid.TokenConfig{
			Issuer:         testIssuer,
			BaseURL:        testIssuer,
			DefaultTTL:     3600,
			MaxTTL:         90 * 24 * 3600, // 90 days — needed for authorization_code CLI tokens
			HMACSecret:     testHMACSecret,
			AuthCodeIssuer: testIssuer,
		},
		Telemetry: zeroid.TelemetryConfig{
			Enabled: false,
		},
		Logging: zeroid.LoggingConfig{
			Level: "warn",
		},
		WIMSEDomain: testWIMSE,
	}

	// Create the server — handles DB connection, migrations, and wiring.
	srv, err := zeroid.NewServer(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create server: %v\n", err)
		return 1
	}

	testZeroIDServer = srv
	testServer = httptest.NewServer(srv.Router())
	defer testServer.Close()

	// Register the CLI and MCP test clients in the oauth_clients table.
	// These are public PKCE clients — no client_secret, no linked identity.
	registerTestOAuthClient(testCLIClientID, []string{"authorization_code"})
	registerTestOAuthClient(testMCPClientID, []string{"authorization_code", "refresh_token"})

	return m.Run()
}

// writeKeyFiles serialises privKey to temp PEM files and returns their paths
// plus a cleanup function. Uses formats expected by JWKSService:
// "EC PRIVATE KEY" (SEC 1) and "PUBLIC KEY" (PKIX).
func writeKeyFiles(privKey *ecdsa.PrivateKey) (privPath, pubPath string, cleanup func(), err error) {
	privDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return "", "", nil, fmt.Errorf("marshal private key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return "", "", nil, fmt.Errorf("marshal public key: %w", err)
	}

	privFile, err := os.CreateTemp("", "zeroid-test-priv-*.pem")
	if err != nil {
		return "", "", nil, err
	}
	if err := pem.Encode(privFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER}); err != nil {
		privFile.Close()
		os.Remove(privFile.Name())
		return "", "", nil, err
	}
	privFile.Close()

	pubFile, err := os.CreateTemp("", "zeroid-test-pub-*.pem")
	if err != nil {
		os.Remove(privFile.Name())
		return "", "", nil, err
	}
	if err := pem.Encode(pubFile, &pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}); err != nil {
		pubFile.Close()
		os.Remove(privFile.Name())
		os.Remove(pubFile.Name())
		return "", "", nil, err
	}
	pubFile.Close()

	return privFile.Name(), pubFile.Name(), func() {
		os.Remove(privFile.Name())
		os.Remove(pubFile.Name())
	}, nil
}

// ── HTTP helpers ─────────────────────────────────────────────────────────────

// post sends a JSON POST to path and returns the response.
func post(t *testing.T, path string, body any, headers map[string]string) *http.Response {
	t.Helper()
	return doRequest(t, http.MethodPost, path, body, headers)
}

// get sends a GET to path and returns the response.
func get(t *testing.T, path string, headers map[string]string) *http.Response {
	t.Helper()
	return doRequest(t, http.MethodGet, path, nil, headers)
}

func doRequest(t *testing.T, method, path string, body any, headers map[string]string) *http.Response {
	t.Helper()
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		bodyReader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, testServer.URL+path, bodyReader)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

// decode reads and JSON-decodes a response body, closing it after.
func decode(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer resp.Body.Close()
	var m map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&m))
	return m
}

// adminHeaders returns headers required for admin /api/v1 endpoints.
// ZeroID admin routes have no built-in auth — only tenant context headers.
func adminHeaders() map[string]string {
	return map[string]string{
		"X-Account-ID": testAccountID,
		"X-Project-ID": testProjectID,
	}
}

// uid returns a unique agent ID for each test to avoid conflicts.
func uid(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

// ── Platform setup helpers ────────────────────────────────────────────────────

type identityResp struct {
	ID            string   `json:"id"`
	ExternalID    string   `json:"external_id"`
	WIMSEURI      string   `json:"wimse_uri"`
	AllowedScopes []string `json:"allowed_scopes"`
}

type oauthClientResp struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// registerIdentity calls POST /api/v1/identities and returns the created identity.
func registerIdentity(t *testing.T, externalID string, scopes []string, publicKeyPEM ...string) identityResp {
	t.Helper()
	body := map[string]any{
		"external_id":    externalID,
		"trust_level":    "unverified",
		"owner_user_id":  "user-test-owner",
		"allowed_scopes": scopes,
	}
	if len(publicKeyPEM) > 0 && publicKeyPEM[0] != "" {
		body["public_key_pem"] = publicKeyPEM[0]
	}
	resp := post(t, "/api/v1/identities", body, adminHeaders())
	require.Equal(t, http.StatusCreated, resp.StatusCode, "registerIdentity: expected 201")
	raw := decode(t, resp)
	return identityResp{
		ID:         raw["id"].(string),
		ExternalID: raw["external_id"].(string),
		WIMSEURI:   raw["wimse_uri"].(string),
	}
}

// registerOAuthClient creates a confidential M2M OAuth client via POST /api/v1/oauth/clients.
// Returns client_id + client_secret. Identity link happens at token issuance, not registration.
func registerOAuthClient(t *testing.T, clientID string, scopes []string) oauthClientResp {
	t.Helper()
	resp := post(t, "/api/v1/oauth/clients", map[string]any{
		"client_id":    clientID,
		"name":         clientID + "-client",
		"confidential": true,
		"grant_types":  []string{"client_credentials"},
		"scopes":       scopes,
	}, nil)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "registerOAuthClient: expected 201")
	raw := decode(t, resp)
	client := raw["client"].(map[string]any)
	return oauthClientResp{
		ClientID:     client["client_id"].(string),
		ClientSecret: raw["client_secret"].(string),
	}
}

// ecPublicKeyPEM encodes an ECDSA public key to PKIX PEM string.
func ecPublicKeyPEM(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, pem.Encode(&buf, &pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	return buf.String()
}

// buildAssertion creates a self-signed ES256 JWT assertion for jwt_bearer and token_exchange flows.
// issuerWIMSE is the agent's WIMSE URI used as the iss claim.
func buildAssertion(t *testing.T, privKey *ecdsa.PrivateKey, issuerWIMSE string) string {
	t.Helper()
	now := time.Now()
	tok, err := jwt.NewBuilder().
		Issuer(issuerWIMSE).
		Audience([]string{testIssuer}).
		IssuedAt(now).
		Expiration(now.Add(5 * time.Minute)).
		Build()
	require.NoError(t, err)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, privKey))
	require.NoError(t, err)
	return string(signed)
}

// newRequest builds an *http.Request for use with doRaw.
func newRequest(t *testing.T, method, path string, body any, headers map[string]string) *http.Request {
	t.Helper()
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		bodyReader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, testServer.URL+path, bodyReader)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

// introspect calls POST /oauth2/token/introspect and returns the decoded response.
func introspect(t *testing.T, tokenStr string) map[string]any {
	t.Helper()
	resp := post(t, "/oauth2/token/introspect", map[string]string{"token": tokenStr}, adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	return decode(t, resp)
}

// writeRSAKeyFiles serialises an RSA private key to temp PEM files (PKCS1 private, PKIX public)
// and returns their paths plus a cleanup function.
func writeRSAKeyFiles(privKey *rsa.PrivateKey) (privPath, pubPath string, cleanup func(), err error) {
	privDER := x509.MarshalPKCS1PrivateKey(privKey)
	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return "", "", nil, fmt.Errorf("marshal RSA public key: %w", err)
	}

	privFile, err := os.CreateTemp("", "zeroid-test-rsa-priv-*.pem")
	if err != nil {
		return "", "", nil, err
	}
	if err := pem.Encode(privFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privDER}); err != nil {
		privFile.Close()
		os.Remove(privFile.Name())
		return "", "", nil, err
	}
	privFile.Close()

	pubFile, err := os.CreateTemp("", "zeroid-test-rsa-pub-*.pem")
	if err != nil {
		os.Remove(privFile.Name())
		return "", "", nil, err
	}
	if err := pem.Encode(pubFile, &pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}); err != nil {
		pubFile.Close()
		os.Remove(privFile.Name())
		os.Remove(pubFile.Name())
		return "", "", nil, err
	}
	pubFile.Close()

	return privFile.Name(), pubFile.Name(), func() {
		os.Remove(privFile.Name())
		os.Remove(pubFile.Name())
	}, nil
}

// registerTestOAuthClient registers a global public PKCE client via Server.EnsureClient.
// Called once in TestMain before any tests run.
// grantTypes controls token behaviour: include "refresh_token" for MCP-style
// short-lived tokens with refresh rotation.
func registerTestOAuthClient(clientID string, grantTypes []string) {
	err := testZeroIDServer.EnsureClient(context.Background(), zeroid.OAuthClientConfig{
		ClientID:     clientID,
		Name:         clientID + "-test-client",
		GrantTypes:   grantTypes,
		RedirectURIs: []string{testRedirectURI},
	})
	if err != nil {
		panic(fmt.Sprintf("registerTestOAuthClient(%s): %v", clientID, err))
	}
}

// agentRegistration holds the response from POST /api/v1/agents/register.
type agentRegistration struct {
	AgentID string // identity UUID
	APIKey  string // plaintext zid_sk_* key
}

// buildPKCEPair generates a random PKCE code verifier and its S256 challenge.
func buildPKCEPair(t *testing.T) (verifier, challenge string) {
	t.Helper()
	b := make([]byte, 32)
	_, err := rand.Read(b)
	require.NoError(t, err)
	verifier = base64.RawURLEncoding.EncodeToString(b)
	hash := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(hash[:])
	return
}

// buildAuthCode mints an HS256 auth code JWT that the server accepts for the
// authorization_code grant. The JWT mirrors what a real authorization endpoint
// would issue after user authentication.
func buildAuthCode(t *testing.T, clientID, userID, redirectURI, codeChallenge string, scopes []string) string {
	t.Helper()
	now := time.Now()
	tok, err := jwt.NewBuilder().
		Issuer(testIssuer).
		Subject("auth-code").
		IssuedAt(now).
		Expiration(now.Add(5*time.Minute)).
		Claim("cid", clientID).
		Claim("uid", userID).
		Claim("aid", testAccountID).
		Claim("pid", testProjectID).
		Claim("cc", codeChallenge).
		Claim("ruri", redirectURI).
		Claim("scp", scopes).
		Build()
	require.NoError(t, err)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256, []byte(testHMACSecret)))
	require.NoError(t, err)
	return string(signed)
}

// generateKey generates a fresh ECDSA P-256 key pair for use in token_exchange tests.
func generateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

// identityIDFromToken introspects a token and returns the identity_id claim.
func identityIDFromToken(t *testing.T, token string) string {
	t.Helper()
	result := introspect(t, token)

	if id, ok := result["identity_id"].(string); ok && id != "" {
		return id
	}

	// Fall back: look up by external_id parsed from the sub claim.
	sub, ok := result["sub"].(string)
	require.True(t, ok, "introspect response must have sub claim")

	externalID, err := extractExternalIDFromWIMSE(sub)
	require.NoError(t, err)

	listResp := get(t, "/api/v1/identities", adminHeaders())
	require.Equal(t, http.StatusOK, listResp.StatusCode)
	body := decode(t, listResp)
	items, ok := body["identities"].([]any)
	require.True(t, ok)
	for _, item := range items {
		identity := item.(map[string]any)
		if identity["external_id"].(string) == externalID {
			return identity["id"].(string)
		}
	}
	t.Fatalf("could not find identity for external_id=%s", externalID)
	return ""
}

// extractExternalIDFromWIMSE parses spiffe://{domain}/{acct}/{proj}/{identity_type}/{external_id}.
func extractExternalIDFromWIMSE(wimseURI string) (string, error) {
	const prefix = "spiffe://" + testWIMSE + "/"
	if len(wimseURI) <= len(prefix) {
		return "", fmt.Errorf("invalid WIMSE URI: %s", wimseURI)
	}
	parts := strings.Split(wimseURI[len(prefix):], "/")
	if len(parts) != 4 {
		return "", fmt.Errorf("unexpected WIMSE URI format: %s (got %d parts)", wimseURI, len(parts))
	}
	return parts[3], nil
}

// registerAgent calls POST /api/v1/agents/register and returns the identity ID and API key.
func registerAgent(t *testing.T, externalID string) agentRegistration {
	t.Helper()
	resp := post(t, "/api/v1/agents/register", map[string]any{
		"name":        externalID,
		"external_id": externalID,
		"sub_type":    "orchestrator",
		"trust_level": "first_party",
		"created_by":  "test-user",
	}, adminHeaders())
	require.Equal(t, http.StatusCreated, resp.StatusCode, "registerAgent: expected 201")
	raw := decode(t, resp)
	agent := raw["identity"].(map[string]any)
	return agentRegistration{
		AgentID: agent["id"].(string),
		APIKey:  raw["api_key"].(string),
	}
}
