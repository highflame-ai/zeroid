// OpenID CIBA Core 1.0 (Client-Initiated Backchannel Authentication) compliance suite.
//
// See COMPLIANCE.md for the conventions this file follows. CIBA isn't an
// RFC, but the README's standards table advertises support and the
// COMPLIANCE.md pattern applies to any normative spec ZeroID claims to
// implement.
//
// Happy-path coverage (poll/ping/push lifecycle, approval / denial,
// tenant isolation) lives in ciba_test.go, ciba_ping_test.go, and
// ciba_push_test.go. This file pins §7 request-shape MUSTs, §7.3 + §11
// error-code mapping, and §10.1 discovery metadata advertising.

package integration_test

import (
	"net/http"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cibaBackchannelGrant is the CIBA grant_type URN per CIBA Core 1.0 §11.
const cibaBackchannelGrant = "urn:openid:params:grant-type:ciba"

// setupCIBAClient registers a confidential client with the CIBA grant in its
// allow-list and the canonical poll notification mode. Tests exercise
// negative-space request shapes against it.
func setupCIBAClient(t *testing.T) string {
	t.Helper()
	clientID := uid("compliance-ciba")
	registerTestOAuthClient(clientID, []string{"client_credentials"})
	return clientID
}

// ── CIBA Core 1.0 §7.1 — Backchannel Authentication Request ────────────────

func TestCIBACore1_0_S7_1_ClientIdRequired(t *testing.T) {
	// CIBA Core 1.0 §7.1: "client_id REQUIRED. The OAuth 2.0 client identifier."
	resp := post(t, "/oauth2/bc-authorize", map[string]any{
		// client_id deliberately omitted
		"account_id": testAccountID,
		"project_id": testProjectID,
		"login_hint": "alice@example.com",
		"scope":      "openid",
	}, nil)
	// Huma's required-field validator may reject before our handler; both
	// 400/422 are conformant signals (the spec says reject, doesn't pin status).
	require.NotEqual(t, http.StatusOK, resp.StatusCode,
		"bc-authorize without client_id MUST be rejected")
}

func TestCIBACore1_0_S7_1_AtLeastOneHintRequired(t *testing.T) {
	// CIBA Core 1.0 §7.1: "at least one of login_hint_token, id_token_hint,
	//   or login_hint MUST be present." ZeroID supports the login_hint
	//   variant and adds group_hint as an extension (see the Ext_GroupHint
	//   suite below); zeroid accepts EITHER login_hint OR group_hint to
	//   satisfy the §7.1 precondition. Sending NEITHER MUST be rejected.
	clientID := setupCIBAClient(t)
	resp := post(t, "/oauth2/bc-authorize", map[string]any{
		"client_id":  clientID,
		"account_id": testAccountID,
		"project_id": testProjectID,
		// neither login_hint nor group_hint
		"scope": "openid",
	}, nil)
	require.NotEqual(t, http.StatusOK, resp.StatusCode,
		"bc-authorize with no hints (login_hint AND group_hint omitted) MUST be rejected")
}

// ── ZeroID extension: group_hint (CIBA Core §7.1 extension) ────────────────

// TestCIBACore1_0_Ext_GroupHintAcceptedWithoutLoginHint pins the extension
// contract: group_hint alone satisfies the §7.1 "at least one hint"
// precondition. Required for AARM STEP_UP's role-targeted approval flow
// (e.g. `@step_up_required("finance_lead")`) where the policy names a
// role, not a specific user — Shield resolves the role to a
// group_hint and AuthN's BackchannelNotifier fans the prompt out to
// every user in the role.
func TestCIBACore1_0_Ext_GroupHintAcceptedWithoutLoginHint(t *testing.T) {
	clientID := setupCIBAClient(t)
	resp := post(t, "/oauth2/bc-authorize", map[string]any{
		"client_id":  clientID,
		"account_id": testAccountID,
		"project_id": testProjectID,
		"group_hint": "highflame:role:finance_lead",
		// login_hint deliberately omitted — group_hint MUST satisfy §7.1
		"scope": "openid",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"bc-authorize with group_hint and no login_hint MUST be accepted")
}

// TestCIBACore1_0_Ext_GroupHintOversized pins the size cap. group_hint
// is persisted on a VARCHAR(255) column; values exceeding 255
// codepoints (Postgres VARCHAR counts codepoints, not bytes) are
// rejected as invalid_request, not silently truncated.
func TestCIBACore1_0_Ext_GroupHintOversized(t *testing.T) {
	clientID := setupCIBAClient(t)

	// 256 runes of ASCII — one past the cap. Each char is 1 byte so
	// also 256 bytes, exercises the base ASCII path.
	oversized := strings.Repeat("a", 256)

	resp := post(t, "/oauth2/bc-authorize", map[string]any{
		"client_id":  clientID,
		"account_id": testAccountID,
		"project_id": testProjectID,
		"group_hint": oversized,
		"scope":      "openid",
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"group_hint > 255 characters MUST be rejected with 400")

	body := decode(t, resp)
	require.Equal(t, "invalid_request", body["error"])
	require.Contains(t, body["error_description"], "group_hint",
		"error_description MUST name the offending field")
}

// TestCIBACore1_0_Ext_GroupHintMultibyteAcceptedUnderRuneCap pins the
// codepoint-vs-byte distinction: a multi-byte UTF-8 string under 255
// codepoints MUST be accepted even when its byte length exceeds 255.
// A naive `len(str) > 255` byte check would over-reject non-ASCII
// roles (e.g. translated role names with CJK characters). 100 ✓ chars
// = 100 runes but 300 bytes (each `✓` is 3 bytes UTF-8).
func TestCIBACore1_0_Ext_GroupHintMultibyteAcceptedUnderRuneCap(t *testing.T) {
	clientID := setupCIBAClient(t)

	// 100 codepoints × 3 bytes/codepoint = 300 bytes — over a byte cap,
	// well under the rune cap (255).
	multibyte := strings.Repeat("✓", 100)
	require.Equal(t, 100, utf8.RuneCountInString(multibyte))
	require.Equal(t, 300, len(multibyte))

	resp := post(t, "/oauth2/bc-authorize", map[string]any{
		"client_id":  clientID,
		"account_id": testAccountID,
		"project_id": testProjectID,
		"group_hint": multibyte,
		"scope":      "openid",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"100-rune (300-byte) group_hint MUST be accepted; a byte-length check would over-reject")
}

// ── CIBA Core 1.0 §7.2 — Successful Authentication Request Response ────────

func TestCIBACore1_0_S7_2_ResponseContainsRequiredFields(t *testing.T) {
	// CIBA Core 1.0 §7.2: "auth_req_id REQUIRED. ... expires_in REQUIRED.
	//   ... interval OPTIONAL. The minimum amount of time in seconds that
	//   the Client SHOULD wait between polling requests."
	clientID := setupCIBAClient(t)
	resp := post(t, "/oauth2/bc-authorize", map[string]any{
		"client_id":       clientID,
		"account_id":      testAccountID,
		"project_id":      testProjectID,
		"login_hint":      "alice@example.com",
		"scope":           "openid",
		"binding_message": "compliance smoke test",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	assert.NotEmpty(t, body["auth_req_id"], "auth_req_id REQUIRED in success response")
	assert.Greater(t, intField(body, "expires_in"), 0,
		"expires_in REQUIRED and MUST be a positive integer")
	// interval is OPTIONAL but ZeroID emits it for poll-mode clients.
	assert.GreaterOrEqual(t, intField(body, "interval"), 0)
}

// ── CIBA Core 1.0 §11 — Token Endpoint (CIBA grant) ────────────────────────

func TestCIBACore1_0_S11_AuthorizationPendingWhilePending(t *testing.T) {
	// CIBA Core 1.0 §11: "If the user has not yet been authenticated or
	//   the consent decision has not yet been made ... the Authorization
	//   Server returns ... error: authorization_pending."
	clientID := setupCIBAClient(t)
	resp := post(t, "/oauth2/bc-authorize", map[string]any{
		"client_id":  clientID,
		"account_id": testAccountID,
		"project_id": testProjectID,
		"login_hint": "alice@example.com",
		"scope":      "openid",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	authReqID, _ := decode(t, resp)["auth_req_id"].(string)
	require.NotEmpty(t, authReqID)

	poll := post(t, "/oauth2/token", map[string]any{
		"grant_type":  cibaBackchannelGrant,
		"auth_req_id": authReqID,
		"client_id":   clientID,
	}, nil)
	require.Equal(t, http.StatusBadRequest, poll.StatusCode)
	body := decode(t, poll)
	assert.Equal(t, "authorization_pending", body["error"],
		"polling a pending request MUST return error=authorization_pending")
}

func TestCIBACore1_0_S11_UnknownAuthReqIdRejected(t *testing.T) {
	// CIBA Core 1.0 §11: an unknown auth_req_id MUST be rejected. The
	// canonical mapping is invalid_grant (RFC 6749 §5.2) since the auth
	// request value is the "grant" being exchanged.
	clientID := setupCIBAClient(t)
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":  cibaBackchannelGrant,
		"auth_req_id": "definitely-not-a-real-auth-req-id",
		"client_id":   clientID,
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body := decode(t, resp)
	assert.Equal(t, "invalid_grant", body["error"])
}

func TestCIBACore1_0_S11_GrantTypeMustBeCIBAURN(t *testing.T) {
	// CIBA Core 1.0 §11: "The value urn:openid:params:grant-type:ciba ...
	//   indicates that this is a CIBA token request." The dispatcher must
	//   only treat this exact URN as the CIBA grant.
	clientID := setupCIBAClient(t)
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":  "ciba", // missing URN prefix
		"auth_req_id": "anything",
		"client_id":   clientID,
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body := decode(t, resp)
	assert.Equal(t, "unsupported_grant_type", body["error"])
}

// ── CIBA Core 1.0 §10.1 — Discovery metadata ────────────────────────────────

func TestCIBACore1_0_S10_1_DiscoveryAdvertisesBackchannelEndpoint(t *testing.T) {
	// CIBA Core 1.0 §10.1: "backchannel_authentication_endpoint REQUIRED.
	//   URL of the OP's Backchannel Authentication Endpoint."
	body := fetchASMetadata(t)
	endpoint, _ := body["backchannel_authentication_endpoint"].(string)
	assert.NotEmpty(t, endpoint, "backchannel_authentication_endpoint REQUIRED")
	assert.Contains(t, endpoint, "/oauth2/bc-authorize")
}

func TestCIBACore1_0_S10_1_DiscoveryAdvertisesDeliveryModes(t *testing.T) {
	// CIBA Core 1.0 §10.1: "backchannel_token_delivery_modes_supported
	//   REQUIRED. JSON array containing one or more of the following
	//   values: poll, ping, push."
	body := fetchASMetadata(t)
	modes, ok := body["backchannel_token_delivery_modes_supported"].([]any)
	require.True(t, ok, "backchannel_token_delivery_modes_supported REQUIRED")
	require.NotEmpty(t, modes, "MUST advertise at least one delivery mode")
	for _, m := range modes {
		s, ok := m.(string)
		require.True(t, ok, "delivery mode entries MUST be strings")
		assert.Contains(t, []string{"poll", "ping", "push"}, s,
			"mode %q is not one of the spec-defined values", s)
	}
}

// TestCIBACore1_0_Ext_GroupHintReachesNotifier closes the loop: when a
// client posts a bc-authorize with group_hint, the deployer-registered
// BackchannelNotifier MUST see that exact group_hint value on the
// notification payload. Without this, AuthN's role-scoped SSE delivery
// can't fan out to the correct role.
func TestCIBACore1_0_Ext_GroupHintReachesNotifier(t *testing.T) {
	clientID := setupCIBAClient(t)

	notifier := newRecordingNotifier()
	testZeroIDServer.SetBackchannelNotifier(notifier.notify)
	testZeroIDServer.SetBackchannelNotifyDispatchSync(true)
	t.Cleanup(func() {
		testZeroIDServer.SetBackchannelNotifyDispatchSync(false)
		testZeroIDServer.SetBackchannelNotifier(nil)
	})

	resp := post(t, "/oauth2/bc-authorize", map[string]any{
		"client_id":  clientID,
		"account_id": testAccountID,
		"project_id": testProjectID,
		"group_hint": "highflame:role:finance_lead",
		"scope":      "openid",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	got := notifier.last()
	require.NotNil(t, got, "BackchannelNotifier MUST be invoked for group_hint-only requests")
	require.Equal(t, "highflame:role:finance_lead", got.GroupHint,
		"BackchannelNotification.GroupHint MUST carry the verbatim deployer-namespaced value")
	require.Empty(t, got.LoginHint,
		"BackchannelNotification.LoginHint MUST be empty when only group_hint was supplied")
}

func TestCIBACore1_0_S10_1_DiscoveryAdvertisesCIBAGrantType(t *testing.T) {
	// CIBA Core 1.0 §10.1 + RFC 8414 §2: the CIBA grant_type URN MUST
	// appear in grant_types_supported so clients can auto-discover that
	// the AS implements CIBA token issuance at /oauth2/token.
	body := fetchASMetadata(t)
	raw, _ := body["grant_types_supported"].([]any)
	found := false
	for _, g := range raw {
		if s, ok := g.(string); ok && s == cibaBackchannelGrant {
			found = true
			break
		}
	}
	assert.True(t, found,
		"grant_types_supported MUST include %q so CIBA-aware clients can discover the grant", cibaBackchannelGrant)
}
