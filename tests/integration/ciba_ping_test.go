package integration_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	zeroid "github.com/highflame-ai/zeroid"
)

// TestCIBA_PingMode_HappyPath exercises the OpenID CIBA Core §10.2 ping
// callback end-to-end:
//
//  1. Register a client with a registered client_notification_endpoint (HTTPS).
//  2. Client posts bc-authorize *with* client_notification_token.
//  3. Admin approves.
//  4. Server fires an outbound POST to client_notification_endpoint carrying
//     Authorization: Bearer <client_notification_token> and a body of
//     {"auth_req_id": "..."}.
//  5. Client polls /oauth2/token and receives the access token.
//
// The outbound POST is captured via a RoundTripper override installed on
// Server.SetBackchannelPingTransport — no real httptest listener is needed.
// Ping dispatch is forced synchronous so the test can assert deterministically.
func TestCIBA_PingMode_HappyPath(t *testing.T) {
	clientID := uid("ciba-ping-client")
	const pingEndpoint = "https://ping.example.test/callback"

	// Register the client *with* the notification endpoint — without it,
	// bc-authorize must reject ping mode (defence-in-depth check below).
	require.NoError(t, testZeroIDServer.EnsureClient(context.Background(), zeroid.OAuthClientConfig{
		ClientID:                   clientID,
		Name:                       clientID + "-ping",
		GrantTypes:                 []string{"client_credentials"},
		RedirectURIs:               []string{testRedirectURI},
		ClientNotificationEndpoint: pingEndpoint,
	}))

	capt := newCapturingRoundTripper()
	testZeroIDServer.SetBackchannelPingTransport(capt)
	testZeroIDServer.SetBackchannelPingDispatchSync(true)
	t.Cleanup(func() {
		testZeroIDServer.SetBackchannelPingDispatchSync(false)
		testZeroIDServer.SetBackchannelPingTransport(nil)
	})

	const notificationToken = "ping-bearer-from-client-xyz"

	// ── bc-authorize with ping ──────────────────────────────────────────────
	bcResp := post(t, "/oauth2/bc-authorize", map[string]any{
		"client_id":                 clientID,
		"account_id":                testAccountID,
		"project_id":                testProjectID,
		"login_hint":                "bob@example.com",
		"scope":                     "openid",
		"client_notification_token": notificationToken,
	}, nil)
	require.Equal(t, http.StatusOK, bcResp.StatusCode)
	bcBody := decode(t, bcResp)
	authReqID, _ := bcBody["auth_req_id"].(string)
	require.NotEmpty(t, authReqID)

	// No ping yet — the row is still pending.
	require.Empty(t, capt.requests(), "ping must not fire before approval")

	// ── Approve ─────────────────────────────────────────────────────────────
	approveResp := post(t,
		adminPath("/oauth2/bc-authorize/"+authReqID+"/approve"),
		map[string]any{"subject_id": "user-bob-001", "subject_email": "bob@example.com"},
		adminHeaders(),
	)
	require.Equal(t, http.StatusOK, approveResp.StatusCode)
	_ = decode(t, approveResp)

	// ── Ping fired ──────────────────────────────────────────────────────────
	captured := capt.requests()
	require.Len(t, captured, 1, "approve must fire exactly one ping")
	pingReq := captured[0]
	require.Equal(t, http.MethodPost, pingReq.Method)
	require.Equal(t, pingEndpoint, pingReq.URL)
	require.Equal(t, "Bearer "+notificationToken, pingReq.Headers.Get("Authorization"))
	require.Equal(t, "application/json", pingReq.Headers.Get("Content-Type"))

	var pingPayload map[string]string
	require.NoError(t, json.Unmarshal([]byte(pingReq.Body), &pingPayload))
	require.Equal(t, authReqID, pingPayload["auth_req_id"], "ping body must echo auth_req_id")
	require.NotContains(t, pingPayload, "access_token", "ping callback must NOT include the token (that's push mode, PR 3)")

	// ── Poll → token ────────────────────────────────────────────────────────
	tokenResp := post(t, "/oauth2/token", map[string]any{
		"grant_type":  "urn:openid:params:grant-type:ciba",
		"auth_req_id": authReqID,
		"client_id":   clientID,
	}, nil)
	require.Equal(t, http.StatusOK, tokenResp.StatusCode)
	require.NotEmpty(t, decode(t, tokenResp)["access_token"])
}

// TestCIBA_PingMode_RequiresRegisteredEndpoint guards the allowlist invariant:
// a client that supplies client_notification_token but has NO registered
// client_notification_endpoint must be rejected at bc-authorize. This is the
// allowlist's whole point — a compromised client_notification_token cannot
// redirect the server's outbound POSTs.
func TestCIBA_PingMode_RequiresRegisteredEndpoint(t *testing.T) {
	clientID := uid("ciba-ping-noendpoint")
	registerTestOAuthClient(clientID, []string{"client_credentials"}) // no notification endpoint

	resp := post(t, "/oauth2/bc-authorize", map[string]any{
		"client_id":                 clientID,
		"account_id":                testAccountID,
		"project_id":                testProjectID,
		"login_hint":                "carol@example.com",
		"client_notification_token": "any-token",
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body := decode(t, resp)
	require.Equal(t, "invalid_request", body["error"])
	require.Contains(t, body["error_description"], "client_notification_endpoint",
		"error must point at the missing registration field")
}

// TestCIBA_RegisterClient_RejectsHTTPNotificationEndpoint guards CIBA Core §4:
// HTTPS-only. A plain http:// endpoint must be rejected at client registration
// so the server can never POST credentials over plaintext.
func TestCIBA_RegisterClient_RejectsHTTPNotificationEndpoint(t *testing.T) {
	err := testZeroIDServer.EnsureClient(context.Background(), zeroid.OAuthClientConfig{
		ClientID:                   uid("ciba-http-bad"),
		Name:                       "ciba-http-bad",
		GrantTypes:                 []string{"client_credentials"},
		ClientNotificationEndpoint: "http://insecure.example.test/cb",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "https", "rejection message must explain the scheme requirement")
}

// ── helpers ─────────────────────────────────────────────────────────────────

// capturedRequest is a minimal record of an outbound HTTP request — just the
// pieces the test needs to assert on. Avoids holding live *http.Request
// pointers (whose Body is single-read).
type capturedRequest struct {
	Method  string
	URL     string
	Headers http.Header
	Body    string
}

// capturingRoundTripper records every request it sees and returns 204 No
// Content so the dispatcher's success path runs.
type capturingRoundTripper struct {
	mu       sync.Mutex
	captured []capturedRequest
	// failOnce, when set, makes the first call return an error so tests can
	// exercise the retry path. PR 2 leaves this unused; reserved for a
	// follow-up retry test if reviewers want one.
	failOnce error
}

func newCapturingRoundTripper() *capturingRoundTripper { return &capturingRoundTripper{} }

func (c *capturingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	bodyBytes, _ := io.ReadAll(req.Body)
	_ = req.Body.Close()
	c.captured = append(c.captured, capturedRequest{
		Method:  req.Method,
		URL:     req.URL.String(),
		Headers: req.Header.Clone(),
		Body:    string(bodyBytes),
	})
	if c.failOnce != nil {
		err := c.failOnce
		c.failOnce = nil
		return nil, err
	}
	return &http.Response{
		StatusCode: http.StatusNoContent,
		Status:     "204 No Content",
		Body:       io.NopCloser(strings.NewReader("")),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func (c *capturingRoundTripper) requests() []capturedRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]capturedRequest, len(c.captured))
	copy(out, c.captured)
	return out
}
