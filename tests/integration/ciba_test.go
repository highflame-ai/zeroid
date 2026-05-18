package integration_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	zeroid "github.com/highflame-ai/zeroid"
)

// TestCIBA_PollingLifecycle covers the OpenID CIBA Core 1.0 polling-mode flow
// end-to-end against the shared test server:
//
//  1. Client posts /oauth2/bc-authorize → BackchannelNotifier fires with the
//     full payload (auth_req_id, login_hint, scope, binding_message).
//  2. Polling /oauth2/token before approval returns error=authorization_pending.
//  3. Admin (tenant-scoped) approves via /api/v1/oauth2/bc-authorize/{id}/approve.
//  4. Polling /oauth2/token after approval returns an access_token whose JWT
//     carries sub=<approved user>, token_exchange="ciba", and a non-empty jti.
//  5. The issued token introspects active=true via the standard endpoint.
//  6. Re-redeeming the same auth_req_id returns access_denied (single-use).
//  7. A deny-only path: a second pending request that is denied yields
//     error=access_denied when polled.
//
// The notifier is wired in synchronous-dispatch mode so the test can assert
// on the payload deterministically without sleeping for a goroutine.
func TestCIBA_PollingLifecycle(t *testing.T) {
	clientID := uid("ciba-client")
	registerTestOAuthClient(clientID, []string{"client_credentials"})

	notifier := newRecordingNotifier()
	testZeroIDServer.SetBackchannelNotifier(notifier.notify)
	testZeroIDServer.SetBackchannelNotifyDispatchSync(true)
	t.Cleanup(func() {
		// Restore async dispatch so other tests aren't affected. The notifier
		// itself stays installed but is harmless — no other test exercises
		// bc-authorize, so it will never be invoked.
		testZeroIDServer.SetBackchannelNotifyDispatchSync(false)
		testZeroIDServer.SetBackchannelNotifier(nil)
	})

	const (
		approvedUserID    = "user-alice-001"
		approvedUserEmail = "alice@example.com"
		bindingMessage    = "Approve sign-in to ACME for Project Apollo"
	)

	// ── Step 1: bc-authorize ─────────────────────────────────────────────────
	resp := post(t, "/oauth2/bc-authorize", map[string]any{
		"client_id":       clientID,
		"account_id":      testAccountID,
		"project_id":      testProjectID,
		"login_hint":      "alice@example.com",
		"scope":           "openid profile",
		"binding_message": bindingMessage,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "bc-authorize must return 200")
	body := decode(t, resp)

	authReqID, _ := body["auth_req_id"].(string)
	require.NotEmpty(t, authReqID)
	require.Greater(t, intField(body, "expires_in"), 0)
	require.Greater(t, intField(body, "interval"), 0)

	// Notifier saw the payload synchronously.
	got := notifier.last()
	require.NotNil(t, got, "notifier must have been invoked")
	require.Equal(t, authReqID, got.AuthReqID)
	require.Equal(t, clientID, got.ClientID)
	require.Equal(t, testAccountID, got.AccountID)
	require.Equal(t, "alice@example.com", got.LoginHint)
	require.Equal(t, bindingMessage, got.BindingMessage)

	// ── Step 2: poll while pending → authorization_pending ───────────────────
	pollResp := post(t, "/oauth2/token", map[string]any{
		"grant_type":  "urn:openid:params:grant-type:ciba",
		"auth_req_id": authReqID,
		"client_id":   clientID,
	}, nil)
	require.Equal(t, http.StatusBadRequest, pollResp.StatusCode)
	pollBody := decode(t, pollResp)
	require.Equal(t, "authorization_pending", pollBody["error"], "body=%v", pollBody)

	// ── Step 3: admin approves ───────────────────────────────────────────────
	approveResp := post(t,
		adminPath("/oauth2/bc-authorize/"+authReqID+"/approve"),
		map[string]any{
			"subject_id":    approvedUserID,
			"subject_email": approvedUserEmail,
			"subject_name":  "Alice",
		},
		adminHeaders(),
	)
	require.Equal(t, http.StatusOK, approveResp.StatusCode, "approve must succeed")
	approveBody := decode(t, approveResp)
	require.Equal(t, "approved", approveBody["status"])

	// ── Step 4: poll again → access_token issued ─────────────────────────────
	tokenResp := post(t, "/oauth2/token", map[string]any{
		"grant_type":  "urn:openid:params:grant-type:ciba",
		"auth_req_id": authReqID,
		"client_id":   clientID,
	}, nil)
	require.Equal(t, http.StatusOK, tokenResp.StatusCode, "token poll after approval must return 200")
	tokenBody := decode(t, tokenResp)

	accessToken, _ := tokenBody["access_token"].(string)
	require.NotEmpty(t, accessToken)
	claims := decodeJWTPayload(t, accessToken)
	require.Equal(t, approvedUserID, claims["sub"], "sub must be the approved user, not the agent")
	require.Equal(t, "ciba", claims["token_exchange"])
	require.Equal(t, clientID, claims["backchannel_client_id"])
	require.Equal(t, approvedUserEmail, claims["user_email"])
	require.NotEmpty(t, claims["jti"])
	require.Equal(t, string(zeroidGrantTypeCIBA), claims["grant_type"])

	// ── Step 5: introspect the issued token ──────────────────────────────────
	introspectBody := introspect(t, accessToken)
	require.Equal(t, true, introspectBody["active"], "issued CIBA token must introspect as active")

	// ── Step 6: re-redeem the same auth_req_id is denied ─────────────────────
	replayResp := post(t, "/oauth2/token", map[string]any{
		"grant_type":  "urn:openid:params:grant-type:ciba",
		"auth_req_id": authReqID,
		"client_id":   clientID,
	}, nil)
	require.Equal(t, http.StatusBadRequest, replayResp.StatusCode)
	replayBody := decode(t, replayResp)
	require.Equal(t, "access_denied", replayBody["error"], "single-use enforcement: %v", replayBody)

	// ── Step 7: deny-path on a separate request ──────────────────────────────
	resp2 := post(t, "/oauth2/bc-authorize", map[string]any{
		"client_id":  clientID,
		"account_id": testAccountID,
		"project_id": testProjectID,
		"login_hint": "alice@example.com",
		"scope":      "openid",
	}, nil)
	require.Equal(t, http.StatusOK, resp2.StatusCode)
	authReqID2, _ := decode(t, resp2)["auth_req_id"].(string)
	require.NotEmpty(t, authReqID2)

	denyResp := post(t,
		adminPath("/oauth2/bc-authorize/"+authReqID2+"/deny"),
		struct{}{},
		adminHeaders(),
	)
	require.Equal(t, http.StatusOK, denyResp.StatusCode, "deny must succeed")

	deniedPoll := post(t, "/oauth2/token", map[string]any{
		"grant_type":  "urn:openid:params:grant-type:ciba",
		"auth_req_id": authReqID2,
		"client_id":   clientID,
	}, nil)
	require.Equal(t, http.StatusBadRequest, deniedPoll.StatusCode)
	require.Equal(t, "access_denied", decode(t, deniedPoll)["error"])
}

// TestCIBA_TenantIsolation_OnApprove guards that an approver from tenant X
// cannot resolve a request created in tenant Y. The error MUST mirror "unknown
// auth_req_id" so existence is not leaked across tenants.
func TestCIBA_TenantIsolation_OnApprove(t *testing.T) {
	clientID := uid("ciba-tenant-client")
	registerTestOAuthClient(clientID, []string{"client_credentials"})
	testZeroIDServer.SetBackchannelNotifyDispatchSync(true)
	t.Cleanup(func() { testZeroIDServer.SetBackchannelNotifyDispatchSync(false) })

	resp := post(t, "/oauth2/bc-authorize", map[string]any{
		"client_id":  clientID,
		"account_id": testAccountID,
		"project_id": testProjectID,
		"login_hint": "alice@example.com",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	authReqID, _ := decode(t, resp)["auth_req_id"].(string)

	// Approve from a *different* tenant.
	wrongTenant := map[string]string{
		"X-Account-ID": "acct-other-999",
		"X-Project-ID": "proj-other-999",
	}
	approveResp := post(t,
		adminPath("/oauth2/bc-authorize/"+authReqID+"/approve"),
		map[string]any{"subject_id": "user-alice-001"},
		wrongTenant,
	)
	require.Equal(t, http.StatusBadRequest, approveResp.StatusCode,
		"cross-tenant approve must be rejected as a generic invalid_request")
}

// ── helpers ─────────────────────────────────────────────────────────────────

// recordingNotifier captures the most recent BackchannelNotification.
// Concurrent-safe so the test can read while dispatch fires.
type recordingNotifier struct {
	mu       sync.Mutex
	received []zeroid.BackchannelNotification
}

func newRecordingNotifier() *recordingNotifier { return &recordingNotifier{} }

func (r *recordingNotifier) notify(_ context.Context, n zeroid.BackchannelNotification) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.received = append(r.received, n)
	return nil
}

func (r *recordingNotifier) last() *zeroid.BackchannelNotification {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.received) == 0 {
		return nil
	}
	cp := r.received[len(r.received)-1]
	return &cp
}

// decodeJWTPayload base64url-decodes the JWT payload section without
// verifying the signature. Acceptable here because the issuer is the test
// server we built and the test scope trusts it.
func decodeJWTPayload(t *testing.T, tokenStr string) map[string]any {
	t.Helper()
	parts := strings.Split(tokenStr, ".")
	require.Len(t, parts, 3, "JWT must have 3 parts")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(payload, &m))
	return m
}

// intField extracts an int from a map[string]any where the value may have
// been JSON-decoded as float64.
func intField(m map[string]any, key string) int {
	v, ok := m[key]
	if !ok {
		return 0
	}
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	default:
		return 0
	}
}

// zeroidGrantTypeCIBA mirrors domain.GrantTypeCIBA without importing the
// internal domain package from the test (which already imports zeroid).
const zeroidGrantTypeCIBA = "urn:openid:params:grant-type:ciba"
