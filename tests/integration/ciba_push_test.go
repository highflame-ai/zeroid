package integration_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	zeroid "github.com/highflame-ai/zeroid"
)

// TestCIBA_PushMode_HappyPath exercises OpenID CIBA Core §10.3.1 push delivery:
//
//  1. Register a client with backchannel_token_delivery_mode=push and an
//     HTTPS notification endpoint.
//  2. bc-authorize with client_notification_token.
//  3. Approve.
//  4. Server POSTs the full token response (access_token + token_type +
//     expires_in + auth_req_id) to the callback with Authorization: Bearer
//     <client_notification_token>.
//  5. Polling /oauth2/token with grant_type=ciba and the same auth_req_id is
//     refused (access_denied) — push delivers exactly once.
func TestCIBA_PushMode_HappyPath(t *testing.T) {
	clientID := uid("ciba-push-client")
	const pushEndpoint = "https://push.example.test/cb"

	require.NoError(t, testZeroIDServer.EnsureClient(context.Background(), zeroid.OAuthClientConfig{
		ClientID:                     clientID,
		Name:                         clientID + "-push",
		GrantTypes:                   []string{"client_credentials"},
		RedirectURIs:                 []string{testRedirectURI},
		ClientNotificationEndpoint:   pushEndpoint,
		BackchannelTokenDeliveryMode: "push",
	}))

	capt := newCapturingRoundTripper()
	testZeroIDServer.SetBackchannelPingTransport(capt)
	testZeroIDServer.SetBackchannelPingDispatchSync(true)
	t.Cleanup(func() {
		testZeroIDServer.SetBackchannelPingDispatchSync(false)
		testZeroIDServer.SetBackchannelPingTransport(nil)
	})

	const notificationToken = "push-bearer-secret"

	// bc-authorize ─────────────────────────────────────────────────────────
	bcResp := post(t, "/oauth2/bc-authorize", map[string]any{
		"client_id":                 clientID,
		"account_id":                testAccountID,
		"project_id":                testProjectID,
		"login_hint":                "dave@example.com",
		"scope":                     "openid",
		"client_notification_token": notificationToken,
	}, nil)
	require.Equal(t, http.StatusOK, bcResp.StatusCode)
	authReqID, _ := decode(t, bcResp)["auth_req_id"].(string)
	require.NotEmpty(t, authReqID)

	// Approve ──────────────────────────────────────────────────────────────
	approveResp := post(t,
		adminPath("/oauth2/bc-authorize/"+authReqID+"/approve"),
		map[string]any{"subject_id": "user-dave-001", "subject_email": "dave@example.com"},
		adminHeaders(),
	)
	require.Equal(t, http.StatusOK, approveResp.StatusCode)
	_ = decode(t, approveResp)

	// Push fired ───────────────────────────────────────────────────────────
	captured := capt.requests()
	require.Len(t, captured, 1, "approve must fire exactly one push callback")
	cb := captured[0]
	require.Equal(t, http.MethodPost, cb.Method)
	require.Equal(t, pushEndpoint, cb.URL)
	require.Equal(t, "Bearer "+notificationToken, cb.Headers.Get("Authorization"))
	require.Equal(t, "application/json", cb.Headers.Get("Content-Type"))

	var payload map[string]any
	require.NoError(t, json.Unmarshal([]byte(cb.Body), &payload))
	require.Equal(t, authReqID, payload["auth_req_id"])
	require.NotEmpty(t, payload["access_token"], "push callback MUST include access_token")
	require.Equal(t, "Bearer", payload["token_type"])
	require.Greater(t, intField(payload, "expires_in"), 0)

	// Polling is forbidden for push-mode rows ──────────────────────────────
	pollResp := post(t, "/oauth2/token", map[string]any{
		"grant_type":  "urn:openid:params:grant-type:ciba",
		"auth_req_id": authReqID,
		"client_id":   clientID,
	}, nil)
	require.Equal(t, http.StatusBadRequest, pollResp.StatusCode)
	require.Equal(t, "access_denied", decode(t, pollResp)["error"])
}

// TestCIBA_PushMode_Denial delivers an OAuth error body via the callback when
// the user denies a push-mode request. No token is minted.
func TestCIBA_PushMode_Denial(t *testing.T) {
	clientID := uid("ciba-push-deny")
	const pushEndpoint = "https://push.example.test/cb-deny"

	require.NoError(t, testZeroIDServer.EnsureClient(context.Background(), zeroid.OAuthClientConfig{
		ClientID:                     clientID,
		Name:                         clientID + "-push-deny",
		GrantTypes:                   []string{"client_credentials"},
		RedirectURIs:                 []string{testRedirectURI},
		ClientNotificationEndpoint:   pushEndpoint,
		BackchannelTokenDeliveryMode: "push",
	}))

	capt := newCapturingRoundTripper()
	testZeroIDServer.SetBackchannelPingTransport(capt)
	testZeroIDServer.SetBackchannelPingDispatchSync(true)
	t.Cleanup(func() {
		testZeroIDServer.SetBackchannelPingDispatchSync(false)
		testZeroIDServer.SetBackchannelPingTransport(nil)
	})

	bcResp := post(t, "/oauth2/bc-authorize", map[string]any{
		"client_id":                 clientID,
		"account_id":                testAccountID,
		"project_id":                testProjectID,
		"login_hint":                "eve@example.com",
		"client_notification_token": "deny-bearer",
	}, nil)
	require.Equal(t, http.StatusOK, bcResp.StatusCode)
	authReqID, _ := decode(t, bcResp)["auth_req_id"].(string)

	denyResp := post(t,
		adminPath("/oauth2/bc-authorize/"+authReqID+"/deny"),
		struct{}{},
		adminHeaders(),
	)
	require.Equal(t, http.StatusOK, denyResp.StatusCode)

	captured := capt.requests()
	require.Len(t, captured, 1, "deny must fire exactly one push callback")
	var payload map[string]any
	require.NoError(t, json.Unmarshal([]byte(captured[0].Body), &payload))
	require.Equal(t, "access_denied", payload["error"], "denial payload follows RFC 6749 §5.2 error shape")
	require.Equal(t, authReqID, payload["auth_req_id"])
	require.NotContains(t, payload, "access_token", "denied push MUST NOT carry a token")
}

// TestCIBA_RegisterClient_PushRequiresEndpoint guards the registration
// invariant: delivery_mode=push without client_notification_endpoint is
// rejected (same rule as ping).
func TestCIBA_RegisterClient_PushRequiresEndpoint(t *testing.T) {
	err := testZeroIDServer.EnsureClient(context.Background(), zeroid.OAuthClientConfig{
		ClientID:                     uid("ciba-push-noendpoint"),
		Name:                         "push-noendpoint",
		GrantTypes:                   []string{"client_credentials"},
		BackchannelTokenDeliveryMode: "push",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "client_notification_endpoint")
}
