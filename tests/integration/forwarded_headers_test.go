package integration_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid"
)

// DPoP behind a TLS-terminating edge, end to end, per forwarded-header mode.
//
// Each request is shaped exactly as an AWS ALB delivers one: plain http to the
// service, the real public Host, X-Forwarded-Proto set by the edge — and an
// X-Forwarded-Host the CLIENT chose, because an ALB never sets that header and
// so passes a client-supplied one through untouched.
//
// Asserts real issuance (200 and token_type DPoP), not merely that the proof
// was not the error.

const (
	edgePublicHost  = "auth.edge.zeroid.test"
	edgeSpoofedHost = "attacker.example"
	edgeTokenPath   = "/oauth2/token"
	edgePublicHTU   = "https://" + edgePublicHost + edgeTokenPath
	edgeSpoofedHTU  = "https://" + edgeSpoofedHost + edgeTokenPath
)

// newForwardedServer builds a server on the shared database with the given
// forwarded-header mode. Clients registered through the shared server are
// visible to it, so a real client_credentials redemption can complete.
func newForwardedServer(t *testing.T, mode string) *httptest.Server {
	t.Helper()
	require.NoError(t, initFederationKeyMaterial(), "init key material")

	srv, err := zeroid.NewServer(zeroid.Config{
		Server: zeroid.ServerConfig{Port: "0", Env: "test", ShutdownTimeoutSeconds: 5,
			ForwardedHeaders: mode},
		Database: zeroid.DatabaseConfig{URL: sharedDBURL, MaxOpenConns: 5, MaxIdleConns: 2},
		Keys: zeroid.KeysConfig{
			PrivateKeyPath: fedKeyPaths.privPath, PublicKeyPath: fedKeyPaths.pubPath, KeyID: "fwd-test-key-1",
			RSAPrivateKeyPath: fedKeyPaths.rsaPriv, RSAPublicKeyPath: fedKeyPaths.rsaPub, RSAKeyID: "fwd-test-rsa-1",
		},
		Token: zeroid.TokenConfig{
			Issuer: "https://" + edgePublicHost, DefaultTTL: 3600, MaxTTL: 86400,
			HMACSecret: testHMACSecret, AuthCodeIssuer: "https://" + edgePublicHost,
		},
		Telemetry:   zeroid.TelemetryConfig{Enabled: false},
		Logging:     zeroid.LoggingConfig{Level: "warn"},
		WIMSEDomain: testWIMSE,
	})
	require.NoError(t, err, "build server with forwarded_headers=%q", mode)

	hs := httptest.NewServer(srv.Router())
	t.Cleanup(func() {
		hs.Close()
		_ = srv.Shutdown(context.Background())
	})
	return hs
}

// redeemViaEdge sends a client_credentials request with a DPoP proof for
// proofHTU, shaped as an ALB forwards it.
func redeemViaEdge(t *testing.T, hs *httptest.Server, proofHTU string) (int, map[string]any) {
	t.Helper()

	agentID := uid("fwd-edge")
	registerIdentity(t, agentID, []string{"billing:read"})
	client := registerOAuthClient(t, agentID, []string{"billing:read"})

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {client.ClientID},
		"client_secret": {client.ClientSecret},
		"account_id":    {testAccountID},
		"project_id":    {testProjectID},
		"scope":         {"billing:read"},
	}
	req, err := http.NewRequest(http.MethodPost, hs.URL+edgeTokenPath, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Host = edgePublicHost
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", edgeSpoofedHost)
	req.Header.Set("DPoP", buildDPoPProof(t, key, http.MethodPost, proofHTU, uuid.NewString()))

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode, decode(t, resp)
}

func TestForwardedHeaders_DPoPBehindALB(t *testing.T) {
	t.Run("none: a correct https proof fails htu — the bug", func(t *testing.T) {
		// What every deployment behind a TLS-terminating edge got before this
		// mode existed, unless it trusted X-Forwarded-Host too.
		status, body := redeemViaEdge(t, newForwardedServer(t, zeroid.ForwardedHeadersNone), edgePublicHTU)
		require.Equal(t, http.StatusBadRequest, status, "body=%v", body)
		assert.Equal(t, "invalid_dpop_proof", body["error"])
		assert.Contains(t, body["error_description"], "htu")
	})

	t.Run("proto: the correct https proof mints a DPoP-bound token — the fix", func(t *testing.T) {
		status, body := redeemViaEdge(t, newForwardedServer(t, zeroid.ForwardedHeadersProto), edgePublicHTU)
		require.Equal(t, http.StatusOK, status, "body=%v", body)
		assert.Equal(t, "DPoP", body["token_type"])
	})

	t.Run("proto: a proof for the SPOOFED host is refused", func(t *testing.T) {
		// The security property. The client's X-Forwarded-Host is ignored, so
		// a proof signed for another server cannot be replayed here.
		status, body := redeemViaEdge(t, newForwardedServer(t, zeroid.ForwardedHeadersProto), edgeSpoofedHTU)
		require.Equal(t, http.StatusBadRequest, status, "body=%v", body)
		assert.Equal(t, "invalid_dpop_proof", body["error"])
	})

	t.Run("proto_host: the spoofed host is believed — why it is wrong behind an ALB", func(t *testing.T) {
		// Pinned so the difference between the two modes is a tested fact,
		// not a comment: behind an edge that does not overwrite
		// X-Forwarded-Host, proto_host lets the client pick the htu host.
		status, body := redeemViaEdge(t, newForwardedServer(t, zeroid.ForwardedHeadersProtoHost), edgeSpoofedHTU)
		require.Equal(t, http.StatusOK, status, "body=%v", body)
	})
}
