// RFC 7591 (Dynamic Client Registration) and RFC 7592 (Client Configuration
// Endpoint) compliance suite.
//
// See COMPLIANCE.md for the conventions this file follows: one MUST per test,
// test name carries the RFC + section citation, first comment quotes the
// clause, and the file groups tests in RFC order.
//
// Happy-path coverage (full register → GET → PUT → DELETE lifecycle) lives in
// dynamic_registration_test.go. This file is the negative-space proof that
// each normative clause is enforced.

package integration_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dcrRegisterWithIAT performs a successful registration so the management-
// endpoint compliance tests have a real client + registration_access_token to
// exercise. Reuses the IAT-minting helper from dynamic_registration_test.go.
func dcrRegisterWithIAT(t *testing.T, clientName string) (clientID, regToken string) {
	t.Helper()
	iat := issueClientRegisterToken(t)
	resp := post(t, "/oauth2/register", map[string]any{
		"client_name": clientName,
		"grant_types": []string{"client_credentials"},
		"scope":       "data:read",
	}, map[string]string{"Authorization": "Bearer " + iat})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	body := decode(t, resp)
	clientID, _ = body["client_id"].(string)
	regToken, _ = body["registration_access_token"].(string)
	require.NotEmpty(t, clientID)
	require.NotEmpty(t, regToken)
	return
}

// ── RFC 7591 §2 — Client metadata ────────────────────────────────────────────

func TestRFC7591_S2_DefaultAuthMethodIsClientSecretBasic(t *testing.T) {
	// RFC 7591 §2: "token_endpoint_auth_method ... If unspecified or omitted,
	//   the default is client_secret_basic, denoting the HTTP Basic
	//   authentication scheme as specified in Section 2.3.1 of OAuth 2.0."
	iat := issueClientRegisterToken(t)
	resp := post(t, "/oauth2/register", map[string]any{
		"client_name": "compliance-default-auth-method",
		"grant_types": []string{"client_credentials"},
		"scope":       "data:read",
		// token_endpoint_auth_method deliberately omitted
	}, map[string]string{"Authorization": "Bearer " + iat})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	body := decode(t, resp)
	assert.Equal(t, "client_secret_basic", body["token_endpoint_auth_method"],
		"omitted token_endpoint_auth_method must default to client_secret_basic per RFC 7591 §2")
}

func TestRFC7591_S2_TokenEndpointAuthMethodNoneRejected(t *testing.T) {
	// Not strictly an RFC MUST — RFC 7591 §2 enumerates "none" as a valid
	// value. ZeroID specialises: machine-to-machine deployments require
	// client authentication, so "none" is explicitly rejected with
	// invalid_client_metadata. The test pins this deployment policy.
	iat := issueClientRegisterToken(t)
	resp := post(t, "/oauth2/register", map[string]any{
		"client_name":                "compliance-none-auth-method",
		"grant_types":                []string{"client_credentials"},
		"token_endpoint_auth_method": "none",
	}, map[string]string{"Authorization": "Bearer " + iat})
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body := decode(t, resp)
	assert.Equal(t, "invalid_client_metadata", body["error"])
}

func TestRFC7591_S2_GrantTypesValidatedAgainstAllowList(t *testing.T) {
	// RFC 7591 §2: grant_types is OPTIONAL; servers MAY reject unsupported
	// values. ZeroID's DCR allow-list is {client_credentials, jwt-bearer};
	// any other grant_type returns invalid_client_metadata.
	iat := issueClientRegisterToken(t)
	resp := post(t, "/oauth2/register", map[string]any{
		"client_name": "compliance-bad-grant",
		"grant_types": []string{"password"}, // not allowed for DCR
	}, map[string]string{"Authorization": "Bearer " + iat})
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body := decode(t, resp)
	assert.Equal(t, "invalid_client_metadata", body["error"])
}

// ── RFC 7591 §3.1 — Client Registration Request ─────────────────────────────

func TestRFC7591_S3_1_InitialAccessTokenRequired(t *testing.T) {
	// RFC 7591 §3.1: "If the authorization server supports the use of OAuth
	//   2.0 [RFC6749] access tokens to authenticate to the client
	//   registration endpoint, the client developer MUST present an initial
	//   access token (...) in the Authorization HTTP header field."
	resp := post(t, "/oauth2/register", map[string]any{
		"client_name": "compliance-no-iat",
		"grant_types": []string{"client_credentials"},
	}, nil)
	// Huma may reject the missing required header at 422 or the handler at 401;
	// either is conformant — both signal "you didn't authenticate."
	require.Contains(t, []int{http.StatusUnauthorized, http.StatusUnprocessableEntity}, resp.StatusCode,
		"missing Authorization on POST /oauth2/register MUST be rejected; got %d", resp.StatusCode)
}

func TestRFC7591_S3_1_InsufficientScopeRejected(t *testing.T) {
	// RFC 7591 §3.1: the initial access token is "issued to the developer
	//   ... to authenticate or authorize the registration request." ZeroID
	//   ties that authorization to the `client:register` scope; a token
	//   without it MUST be rejected with insufficient_scope.
	agentID := uid("compliance-wrong-scope")
	registerIdentity(t, agentID, []string{"data:read"})
	client := registerOAuthClient(t, agentID, []string{"data:read"})
	tokenResp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, tokenResp.StatusCode)
	token, _ := decode(t, tokenResp)["access_token"].(string)

	resp := post(t, "/oauth2/register", map[string]any{
		"client_name": "compliance-wrong-scope-tool",
		"grant_types": []string{"client_credentials"},
	}, map[string]string{"Authorization": "Bearer " + token})
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
	body := decode(t, resp)
	assert.Equal(t, "insufficient_scope", body["error"])
}

// ── RFC 7591 §3.2.1 — Client Information Response ───────────────────────────

func TestRFC7591_S3_2_1_ResponseContainsRequiredFields(t *testing.T) {
	// RFC 7591 §3.2.1: "client_id REQUIRED. ... client_secret OPTIONAL. ...
	//   client_id_issued_at OPTIONAL. ... client_secret_expires_at REQUIRED
	//   if client_secret is issued."
	iat := issueClientRegisterToken(t)
	resp := post(t, "/oauth2/register", map[string]any{
		"client_name": "compliance-response-shape",
		"grant_types": []string{"client_credentials"},
		"scope":       "data:read",
	}, map[string]string{"Authorization": "Bearer " + iat})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	body := decode(t, resp)

	assert.NotEmpty(t, body["client_id"], "client_id REQUIRED")
	assert.NotEmpty(t, body["client_secret"], "DCR-issued clients are confidential; client_secret returned once")
	_, hasExpires := body["client_secret_expires_at"]
	assert.True(t, hasExpires, "client_secret_expires_at REQUIRED when client_secret is issued (RFC 7591 §3.2.1)")
}

func TestRFC7591_S3_2_1_ClientIdIssuedAtIsUnixSeconds(t *testing.T) {
	// RFC 7591 §3.2.1: "client_id_issued_at ... Time at which the client
	//   identifier was issued. The time is represented as the number of
	//   seconds from 1970-01-01T00:00:00Z."
	iat := issueClientRegisterToken(t)
	resp := post(t, "/oauth2/register", map[string]any{
		"client_name": "compliance-issued-at",
		"grant_types": []string{"client_credentials"},
	}, map[string]string{"Authorization": "Bearer " + iat})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	body := decode(t, resp)
	issued, ok := body["client_id_issued_at"].(float64)
	require.True(t, ok, "client_id_issued_at must be numeric (Unix seconds)")
	// Sanity: not before 2020-01-01 and not after 2200-01-01.
	assert.Greater(t, issued, 1577836800.0, "client_id_issued_at must look like a real Unix timestamp")
	assert.Less(t, issued, 7258118400.0, "client_id_issued_at must look like a real Unix timestamp")
}

func TestRFC7591_S3_2_1_RegistrationClientUriReturned(t *testing.T) {
	// RFC 7592 §1: "The OAuth 2.0 client registration response includes
	//   ... registration_client_uri: the URL at which the client can
	//   access its registration."
	iat := issueClientRegisterToken(t)
	resp := post(t, "/oauth2/register", map[string]any{
		"client_name": "compliance-reg-client-uri",
		"grant_types": []string{"client_credentials"},
	}, map[string]string{"Authorization": "Bearer " + iat})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	body := decode(t, resp)
	clientID, _ := body["client_id"].(string)
	uri, _ := body["registration_client_uri"].(string)
	assert.Contains(t, uri, "/oauth2/register/"+clientID,
		"registration_client_uri MUST point at the per-client management endpoint")
}

// ── RFC 7591 §3.2.2 — Client Registration Error Response ────────────────────

func TestRFC7591_S3_2_2_ErrorResponseShape(t *testing.T) {
	// RFC 7591 §3.2.2: "the authorization server SHALL include an HTTP 400
	//   Bad Request status code (...) and include the following parameters
	//   with the response: error (REQUIRED), error_description (OPTIONAL)."
	//
	// We trip the handler's own metadata validation (an unsupported
	// token_endpoint_auth_method) rather than Huma's framework-level
	// required-field check — the latter responds with RFC 7807 Problem
	// Details + 422, which is correct for a request-validation layer but
	// distinct from RFC 7591's wire shape for an *accepted-and-validated*
	// registration that fails metadata rules.
	iat := issueClientRegisterToken(t)
	resp := post(t, "/oauth2/register", map[string]any{
		"client_name":                "compliance-7591-error-shape",
		"grant_types":                []string{"client_credentials"},
		"token_endpoint_auth_method": "private_key_jwt", // not in DCR allow-list
	}, map[string]string{"Authorization": "Bearer " + iat})
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body := decode(t, resp)
	assert.Equal(t, "invalid_client_metadata", body["error"], "error field is REQUIRED and must be a registered code")
	assert.NotEmpty(t, body["error_description"], "error_description is OPTIONAL but recommended; ours provides one")
}

// ── RFC 7592 §2 — Client Configuration Endpoint ─────────────────────────────

func TestRFC7592_S2_1_ReadRequiresRegistrationAccessToken(t *testing.T) {
	// RFC 7592 §2.1: "The client MUST authenticate to the configuration
	//   endpoint using the registration_access_token (...) in the
	//   Authorization HTTP header."
	clientID, _ := dcrRegisterWithIAT(t, "compliance-7592-read-no-auth")
	resp := get(t, "/oauth2/register/"+clientID, nil)
	require.Contains(t, []int{http.StatusUnauthorized, http.StatusUnprocessableEntity}, resp.StatusCode,
		"GET without Authorization MUST be rejected; got %d", resp.StatusCode)
}

func TestRFC7592_S2_1_WrongRegistrationAccessTokenRejected(t *testing.T) {
	// RFC 7592 §2.1 / §3: an unknown or wrong registration_access_token
	// MUST result in an unauthenticated response.
	clientID, _ := dcrRegisterWithIAT(t, "compliance-7592-bad-token")
	resp := get(t, "/oauth2/register/"+clientID,
		map[string]string{"Authorization": "Bearer not-the-real-token"})
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	body := decode(t, resp)
	assert.Equal(t, "invalid_token", body["error"])
}

func TestRFC7592_S2_2_ReadDoesNotRevealClientSecret(t *testing.T) {
	// RFC 7592 §2.2: GET responses MUST NOT include secret credentials.
	// (Spec wording: "Note that the values returned in this response can
	//   be values other than the values that were originally sent (...)";
	//   our implementation strictly omits client_secret + reg token on GET.)
	clientID, regToken := dcrRegisterWithIAT(t, "compliance-7592-no-secret-in-get")
	resp := get(t, "/oauth2/register/"+clientID,
		map[string]string{"Authorization": "Bearer " + regToken})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decode(t, resp)
	_, hasSecret := body["client_secret"]
	assert.False(t, hasSecret, "GET MUST NOT re-reveal client_secret")
	_, hasRegToken := body["registration_access_token"]
	assert.False(t, hasRegToken, "GET MUST NOT re-reveal registration_access_token")
}

func TestRFC7592_S2_3_PutIsFullReplacement(t *testing.T) {
	// RFC 7592 §2.3: "the values of the entire client metadata MUST be
	//   replaced. Fields not present in the request MUST be treated as
	//   removed (or returned to defaults)."
	clientID, regToken := dcrRegisterWithIAT(t, "compliance-7592-put-replace")

	// PUT a body that omits `scope` → server must clear it / apply default
	// (empty slice).
	putResp := doRequest(t, http.MethodPut, "/oauth2/register/"+clientID, map[string]any{
		"client_name": "compliance-7592-put-replace",
		"grant_types": []string{"client_credentials"},
		// scope deliberately omitted
	}, map[string]string{"Authorization": "Bearer " + regToken})
	require.Equal(t, http.StatusOK, putResp.StatusCode)
	body := decode(t, putResp)
	// scope on the response should be the empty string (default), NOT the
	// `data:read` value the client was registered with.
	assert.Equal(t, "", body["scope"], "omitted scope on PUT MUST clear the previous value, not preserve it")
}

func TestRFC7592_S2_4_DeleteReturnsNoContent(t *testing.T) {
	// RFC 7592 §2.4: "The authorization server responds with HTTP 204 No
	//   Content if the deletion is successful."
	clientID, regToken := dcrRegisterWithIAT(t, "compliance-7592-delete-204")
	resp := doRequest(t, http.MethodDelete, "/oauth2/register/"+clientID, nil,
		map[string]string{"Authorization": "Bearer " + regToken})
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	_ = resp.Body.Close()
}

func TestRFC7592_S2_4_DeleteRemovesClient(t *testing.T) {
	// RFC 7592 §2.4: after successful deletion, the client_id is no longer
	// usable. Per ZeroID's semantics this manifests as a 401 invalid_token
	// when the registration_access_token's lookup fails.
	clientID, regToken := dcrRegisterWithIAT(t, "compliance-7592-delete-then-get")

	delResp := doRequest(t, http.MethodDelete, "/oauth2/register/"+clientID, nil,
		map[string]string{"Authorization": "Bearer " + regToken})
	require.Equal(t, http.StatusNoContent, delResp.StatusCode)
	_ = delResp.Body.Close()

	getResp := get(t, "/oauth2/register/"+clientID,
		map[string]string{"Authorization": "Bearer " + regToken})
	assert.Equal(t, http.StatusUnauthorized, getResp.StatusCode,
		"after delete, GET against the dead client_id MUST fail authentication")
}
