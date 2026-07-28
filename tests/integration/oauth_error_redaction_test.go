// Regression coverage for #191 / #202: the RFC OAuth endpoints must (1) ignore
// unrecognized request parameters instead of 422ing on them (RFC 6749 §3.1),
// and (2) never echo submitted request-body values — which can carry a
// token/client_secret/notification token — back in a validation-error
// response, regardless of which validation rule fired.
package integration_test

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errorModelBody mirrors the subset of huma.ErrorModel this suite asserts on.
type errorModelBody struct {
	Errors []struct {
		Location string `json:"location"`
		Value    any    `json:"value"`
	} `json:"errors"`
}

// assertNoSecretLeak reads resp's body, asserts the given secret substring
// never appears anywhere in the raw response, and that every ErrorDetail.Value
// present has been redacted rather than echoing the submitted value.
func assertNoSecretLeak(t *testing.T, resp *http.Response, secret string) {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.NotContains(t, string(raw), secret,
		"validation-error response must never echo request body values on OAuth endpoints")

	var body errorModelBody
	require.NoError(t, json.Unmarshal(raw, &body))
	require.NotEmpty(t, body.Errors, "expected at least one validation error detail")
	for _, e := range body.Errors {
		if e.Value != nil {
			assert.Equal(t, "[redacted]", e.Value, "location %s: value must be redacted, not echoed", e.Location)
		}
	}
}

// ── RFC 6749 §3.1 — ignore unrecognized request parameters ─────────────────

func TestOAuthTokenIgnoresUnknownParams(t *testing.T) {
	agentID := uid("redaction-token-unknown-param")
	scopes := []string{"data:read"}
	registerIdentity(t, agentID, scopes)
	client := registerOAuthClient(t, agentID, scopes)

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":             "client_credentials",
		"client_id":              client.ClientID,
		"client_secret":          client.ClientSecret,
		"account_id":             testAccountID,
		"project_id":             testProjectID,
		"scope":                  "data:read",
		"not_a_real_oauth_field": "123",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"unrecognized request parameters must be ignored, not rejected (RFC 6749 §3.1)")
	body := decode(t, resp)
	assert.NotEmpty(t, body["access_token"])
}

func TestOAuthIntrospectIgnoresUnknownParams(t *testing.T) {
	// Exact repro from #191/#202: curl -d "token=12345&azz=123" .../introspect
	// used to 422 with the unknown "azz" field, echoing the whole body
	// (including the token) back in the error.
	resp := post(t, "/oauth2/token/introspect", map[string]any{
		"token": "12345",
		"azz":   "123",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"unrecognized request parameters must be ignored, not rejected (RFC 6749 §3.1)")
	body := decode(t, resp)
	assert.False(t, body["active"].(bool), "not a real token, so introspection reports inactive")
}

func TestOAuthBcAuthorizeIgnoresUnknownParams(t *testing.T) {
	clientID := setupCIBAClient(t)

	resp := post(t, "/oauth2/bc-authorize", map[string]any{
		"client_id":             clientID,
		"account_id":            testAccountID,
		"project_id":            testProjectID,
		"group_hint":            "highflame:role:finance_lead",
		"scope":                 "openid",
		"not_a_real_ciba_field": "123",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"unrecognized request parameters must be ignored, not rejected (RFC 6749 §3.1, "+
			"inherited by CIBA Core 1.0 §7.1)")
}

func TestOAuthRevokeIgnoresUnknownParams(t *testing.T) {
	resp := post(t, "/oauth2/token/revoke", map[string]any{
		"token": "12345",
		"azz":   "123",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"unrecognized request parameters must be ignored, not rejected (RFC 6749 §3.1); "+
			"revoke also always returns 200 per RFC 7009 §2.2")
	body := decode(t, resp)
	assert.True(t, body["revoked"].(bool))
}

// ── Validation-error responses must never echo submitted values ────────────

func TestOAuthTokenValidationErrorRedactsSecrets(t *testing.T) {
	// grant_type is Huma-required and deliberately omitted here, so Huma's own
	// schema validator rejects the request before tokenOp ever runs — the
	// path that used to echo the entire parsed body (including client_secret)
	// back in ErrorDetail.Value.
	resp := post(t, "/oauth2/token", map[string]any{
		"client_secret": "super-secret-should-never-leak",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
	}, nil)
	require.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode,
		"missing grant_type is a schema-level required-field failure")
	assertNoSecretLeak(t, resp, "super-secret-should-never-leak")
}

func TestOAuthIntrospectValidationErrorRedactsSecrets(t *testing.T) {
	// token is required and deliberately omitted; api_key stands in for a
	// secret submitted under an unexpected key (e.g. a caller typo) — the
	// exact shape that leaked in #191/#202 even after unknown params are
	// otherwise ignored.
	resp := post(t, "/oauth2/token/introspect", map[string]any{
		"api_key": "zid_sk_should_never_leak",
	}, nil)
	require.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode,
		"missing token is a schema-level required-field failure")
	assertNoSecretLeak(t, resp, "zid_sk_should_never_leak")
}

func TestOAuthBcAuthorizeValidationErrorRedactsSecrets(t *testing.T) {
	// client_id is required and deliberately omitted; client_notification_token
	// is the CIBA ping-mode bearer the leak mechanism applies to equally.
	resp := post(t, "/oauth2/bc-authorize", map[string]any{
		"account_id":                testAccountID,
		"project_id":                testProjectID,
		"login_hint":                "user@example.com",
		"client_notification_token": "should-never-leak-either",
	}, nil)
	require.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode,
		"missing client_id is a schema-level required-field failure")
	assertNoSecretLeak(t, resp, "should-never-leak-either")
}
