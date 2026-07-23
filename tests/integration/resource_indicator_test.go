package integration_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	zeroid "github.com/highflame-ai/zeroid"
)

// newRFC8707Server spins up a second zeroid server with RFC 8707 config
// overrides. Both AllowedResources and DefaultAudience can be set independently;
// the server shares the same Postgres as the shared TestMain server.
func newRFC8707Server(t *testing.T, allowedResources []string, defaultAudience string) *httptest.Server {
	t.Helper()
	require.NoError(t, initFederationKeyMaterial(), "init key material")
	cfg := zeroid.Config{
		Server:   zeroid.ServerConfig{Port: "0", Env: "test", ShutdownTimeoutSeconds: 5},
		Database: zeroid.DatabaseConfig{URL: sharedDBURL, MaxOpenConns: 5, MaxIdleConns: 2},
		Keys: zeroid.KeysConfig{
			PrivateKeyPath:    fedKeyPaths.privPath,
			PublicKeyPath:     fedKeyPaths.pubPath,
			KeyID:             "ri-test-key-1",
			RSAPrivateKeyPath: fedKeyPaths.rsaPriv,
			RSAPublicKeyPath:  fedKeyPaths.rsaPub,
			RSAKeyID:          "ri-test-rsa-1",
		},
		Token: zeroid.TokenConfig{
			Issuer:                              "https://restricted.zeroid.test",
			DefaultTTL:                          3600,
			MaxTTL:                              90 * 24 * 3600,
			HMACSecret:                          testHMACSecret,
			AllowUnauthenticatedTokenInspection: true,
		},
		Telemetry:        zeroid.TelemetryConfig{Enabled: false},
		Logging:          zeroid.LoggingConfig{Level: "warn"},
		WIMSEDomain:      testWIMSE,
		AllowedResources: allowedResources,
		DefaultAudience:  defaultAudience,
		Backchannel:      zeroid.BackchannelConfig{AllowPrivateNotificationEndpoints: true},
		Attestation:      zeroid.AttestationConfig{AllowPrivateIssuerEndpoints: true},
	}
	srv, err := zeroid.NewServer(cfg)
	require.NoError(t, err, "newRFC8707Server: NewServer failed")
	httpSrv := httptest.NewServer(srv.Router())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

// newRestrictedServer is a convenience wrapper for tests that only need
// AllowedResources set (no DefaultAudience override).
func newRestrictedServer(t *testing.T, allowedResources []string) *httptest.Server {
	return newRFC8707Server(t, allowedResources, "")
}

// postJSON posts a JSON body to an arbitrary URL and returns the response.
func postJSON(t *testing.T, url string, body map[string]any) *http.Response {
	t.Helper()
	b, err := json.Marshal(body)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

// decodeBody decodes a JSON response body into a map.
func decodeBody(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer resp.Body.Close() //nolint:errcheck
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	return m
}

// TestResourceIndicator covers the RFC 8707 resource indicator end-to-end.
// Open-mode sub-tests (no AllowedResources) run against the shared testServer.
// Restricted-mode sub-tests spin up a dedicated server.
func TestResourceIndicator(t *testing.T) {
	scopes := []string{"data:read"}

	// ── Open-mode tests (shared testServer, no AllowedResources) ──────────────

	t.Run("valid_resource_open_mode_sets_aud", func(t *testing.T) {
		agentID := uid("ri-open-cc")
		registerIdentity(t, agentID, scopes)
		client := registerOAuthClient(t, agentID, scopes)

		resp := post(t, "/oauth2/token", map[string]any{
			"grant_type":    "client_credentials",
			"account_id":    testAccountID,
			"project_id":    testProjectID,
			"client_id":     client.ClientID,
			"client_secret": client.ClientSecret,
			"scope":         "data:read",
			"resource":      "https://rs.example.com",
		}, nil)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		claims := decodeJWTPayload(t, decode(t, resp)["access_token"].(string))
		assert.Equal(t, []string{"https://rs.example.com"}, audienceOf(t, claims),
			"resource URI must be stamped as aud")
	})

	t.Run("malformed_resource_uri_returns_invalid_target", func(t *testing.T) {
		agentID := uid("ri-malformed")
		registerIdentity(t, agentID, scopes)
		client := registerOAuthClient(t, agentID, scopes)

		resp := post(t, "/oauth2/token", map[string]any{
			"grant_type":    "client_credentials",
			"account_id":    testAccountID,
			"project_id":    testProjectID,
			"client_id":     client.ClientID,
			"client_secret": client.ClientSecret,
			"scope":         "data:read",
			"resource":      "not-a-uri",
		}, nil)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		body := decode(t, resp)
		assert.Equal(t, "invalid_target", body["error"])
	})

	t.Run("resource_with_fragment_returns_invalid_target", func(t *testing.T) {
		agentID := uid("ri-fragment")
		registerIdentity(t, agentID, scopes)
		client := registerOAuthClient(t, agentID, scopes)

		resp := post(t, "/oauth2/token", map[string]any{
			"grant_type":    "client_credentials",
			"account_id":    testAccountID,
			"project_id":    testProjectID,
			"client_id":     client.ClientID,
			"client_secret": client.ClientSecret,
			"scope":         "data:read",
			"resource":      "https://rs.example.com#fragment",
		}, nil)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		body := decode(t, resp)
		assert.Equal(t, "invalid_target", body["error"])
	})

	t.Run("no_resource_no_default_falls_back_to_issuer", func(t *testing.T) {
		agentID := uid("ri-no-resource")
		registerIdentity(t, agentID, scopes)
		client := registerOAuthClient(t, agentID, scopes)

		resp := post(t, "/oauth2/token", map[string]any{
			"grant_type":    "client_credentials",
			"account_id":    testAccountID,
			"project_id":    testProjectID,
			"client_id":     client.ClientID,
			"client_secret": client.ClientSecret,
			"scope":         "data:read",
		}, nil)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		claims := decodeJWTPayload(t, decode(t, resp)["access_token"].(string))
		assert.Equal(t, []string{testIssuer}, audienceOf(t, claims),
			"no resource + no DefaultAudience must keep aud == issuer (regression guard)")
	})

	t.Run("jwt_bearer_resource_sets_aud", func(t *testing.T) {
		agentID := uid("ri-jwt-bearer")
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		identity := registerIdentity(t, agentID, scopes, ecPublicKeyPEM(t, privKey))
		assertion := buildAssertion(t, privKey, identity.WIMSEURI)

		resp := post(t, "/oauth2/token", map[string]any{
			"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
			"subject":    assertion,
			"scope":      "data:read",
			"resource":   "https://rs-jwt.example.com",
		}, nil)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		claims := decodeJWTPayload(t, decode(t, resp)["access_token"].(string))
		assert.Equal(t, []string{"https://rs-jwt.example.com"}, audienceOf(t, claims),
			"jwt_bearer resource must be stamped as aud")
	})

	t.Run("no_resource_uses_default_audience", func(t *testing.T) {
		const defaultAud = "https://default-rs.example.com"
		srv := newRFC8707Server(t, nil, defaultAud)

		agentID := uid("ri-default-aud")
		registerIdentity(t, agentID, scopes)
		client := registerOAuthClient(t, agentID, scopes)

		resp := postJSON(t, srv.URL+"/oauth2/token", map[string]any{
			"grant_type":    "client_credentials",
			"account_id":    testAccountID,
			"project_id":    testProjectID,
			"client_id":     client.ClientID,
			"client_secret": client.ClientSecret,
			"scope":         "data:read",
		})
		require.Equal(t, http.StatusOK, resp.StatusCode)
		body := decodeBody(t, resp)
		claims := decodeJWTPayload(t, body["access_token"].(string))
		assert.Equal(t, []string{defaultAud}, audienceOf(t, claims),
			"no resource + DefaultAudience configured must stamp aud = defaultAudience")
	})

	// ── Restricted-mode tests (dedicated server with AllowedResources set) ────

	t.Run("valid_resource_restricted_mode_sets_aud", func(t *testing.T) {
		allowed := "https://allowed-rs.example.com"
		srv := newRestrictedServer(t, []string{allowed})

		agentID := uid("ri-restricted-ok")
		registerIdentity(t, agentID, scopes)
		client := registerOAuthClient(t, agentID, scopes)

		resp := postJSON(t, srv.URL+"/oauth2/token", map[string]any{
			"grant_type":    "client_credentials",
			"account_id":    testAccountID,
			"project_id":    testProjectID,
			"client_id":     client.ClientID,
			"client_secret": client.ClientSecret,
			"scope":         "data:read",
			"resource":      allowed,
		})
		require.Equal(t, http.StatusOK, resp.StatusCode)
		body := decodeBody(t, resp)
		claims := decodeJWTPayload(t, body["access_token"].(string))
		assert.Equal(t, []string{allowed}, audienceOf(t, claims))
	})

	t.Run("blocked_resource_returns_invalid_target", func(t *testing.T) {
		srv := newRestrictedServer(t, []string{"https://allowed-rs.example.com"})

		agentID := uid("ri-restricted-blocked")
		registerIdentity(t, agentID, scopes)
		client := registerOAuthClient(t, agentID, scopes)

		resp := postJSON(t, srv.URL+"/oauth2/token", map[string]any{
			"grant_type":    "client_credentials",
			"account_id":    testAccountID,
			"project_id":    testProjectID,
			"client_id":     client.ClientID,
			"client_secret": client.ClientSecret,
			"scope":         "data:read",
			"resource":      "https://blocked.example.com",
		})
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		body := decodeBody(t, resp)
		assert.Equal(t, "invalid_target", body["error"])
	})
}
