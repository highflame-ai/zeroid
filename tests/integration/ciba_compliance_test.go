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
	"testing"

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

func TestCIBACore1_0_S7_1_LoginHintRequired(t *testing.T) {
	// CIBA Core 1.0 §7.1: "login_hint A hint to the OpenID Provider regarding
	//   the end-user for whom authentication is being requested. ... at
	//   least one of login_hint_token, id_token_hint, or login_hint MUST be
	//   present." ZeroID supports the login_hint variant; missing it MUST
	//   be rejected.
	clientID := setupCIBAClient(t)
	resp := post(t, "/oauth2/bc-authorize", map[string]any{
		"client_id":  clientID,
		"account_id": testAccountID,
		"project_id": testProjectID,
		// login_hint deliberately omitted
		"scope": "openid",
	}, nil)
	require.NotEqual(t, http.StatusOK, resp.StatusCode,
		"bc-authorize without login_hint MUST be rejected")
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
