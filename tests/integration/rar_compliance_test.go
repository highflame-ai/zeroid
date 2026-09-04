// RFC 9396 (OAuth 2.0 Rich Authorization Requests) compliance suite.
//
// See COMPLIANCE.md for the conventions this file follows.
//
// Happy-path coverage of authorization_details (multi-element parsing,
// notifier delivery of the typed slice, opt-in per-type validator, form
// vs JSON content types, validator panic safety, token-side end-to-end)
// lives in `ciba_rar_test.go`. This file pins the RFC 9396 normative
// clauses explicitly so a future spec-revision sweep can grep `RFC9396`
// and touch every assertion. Each test enforces exactly one MUST.

package integration_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupRARClient registers a public client the compliance tests post to.
// Mirrors setupCIBAClient in ciba_compliance_test.go — RAR rides on the
// CIBA bc-authorize endpoint so the client registration shape is identical.
func setupRARClient(t *testing.T) string {
	t.Helper()

	clientID := uid("compliance-rar")
	registerTestOAuthClient(clientID, []string{"client_credentials"})

	return clientID
}

// postBcAuthorize is a thin wrapper that sends the canonical CIBA tenant
// + login_hint scaffolding so every test below only has to vary
// authorization_details. Mirrors the helper pattern in ciba_compliance_test.go.
func postBcAuthorize(t *testing.T, clientID string, authorizationDetails any) *http.Response {
	t.Helper()

	body := map[string]any{
		"client_id":  clientID,
		"account_id": testAccountID,
		"project_id": testProjectID,
		"login_hint": "alice@example.com",
		"scope":      "openid",
	}
	if authorizationDetails != nil {
		body["authorization_details"] = authorizationDetails
	}

	return post(t, "/oauth2/bc-authorize", body, nil)
}

// ── RFC 9396 §2 — Request Parameter "authorization_details" ────────────────

func TestRFC9396_S2_AuthorizationDetailsMustBeJSONArray(t *testing.T) {
	// RFC 9396 §2: "The request parameter authorization_details contains,
	//   in JSON notation, an array of objects."
	// A JSON object at the top level (no surrounding array) violates the
	// outer shape and MUST be rejected.
	clientID := setupRARClient(t)

	resp := postBcAuthorize(t, clientID, map[string]any{"type": "x"})
	require.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"authorization_details that is not a JSON array MUST be rejected")

	body := decode(t, resp)
	require.Equal(t, "invalid_authorization_details", body["error"],
		"outer-shape rejection MUST use the invalid_authorization_details error code")
}

func TestRFC9396_S2_EmptyArrayTreatedAsAbsent(t *testing.T) {
	// RFC 9396 §2: an authorization_details array of zero objects conveys
	//   no rights. ZeroID's contract — and the only sensible reading of
	//   "the rights of the access token" — is that this is indistinguishable
	//   from the parameter being omitted. The legacy CIBA flow MUST continue
	//   to succeed unchanged.
	clientID := setupRARClient(t)

	notifier := newRecordingNotifier()
	testZeroIDServer.SetBackchannelNotifier(notifier.notify)
	testZeroIDServer.SetBackchannelNotifyDispatchSync(true)
	t.Cleanup(func() {
		testZeroIDServer.SetBackchannelNotifyDispatchSync(false)
		testZeroIDServer.SetBackchannelNotifier(nil)
	})

	resp := postBcAuthorize(t, clientID, []map[string]any{})
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"explicit empty authorization_details MUST be accepted (legacy CIBA semantics preserved)")

	got := notifier.last()
	require.NotNil(t, got)
	assert.Empty(t, got.AuthorizationDetails,
		"empty array MUST surface as empty typed slice (no synthesised entries)")
}

func TestRFC9396_S2_MultipleEntriesPreserveOrder(t *testing.T) {
	// RFC 9396 §2 (and §2.3): a request may carry multiple authorization
	//   details objects. The server must process every entry; the typed
	//   slice handed to a consumer (approver UX) MUST reflect the order
	//   in which the client supplied them so the approval prompt renders
	//   in the client's declared sequence.
	clientID := setupRARClient(t)

	notifier := newRecordingNotifier()
	testZeroIDServer.SetBackchannelNotifier(notifier.notify)
	testZeroIDServer.SetBackchannelNotifyDispatchSync(true)
	t.Cleanup(func() {
		testZeroIDServer.SetBackchannelNotifyDispatchSync(false)
		testZeroIDServer.SetBackchannelNotifier(nil)
	})

	resp := postBcAuthorize(t, clientID, []map[string]any{
		{"type": "type-a"},
		{"type": "type-b"},
		{"type": "type-c"},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)

	got := notifier.last()
	require.NotNil(t, got)
	require.Len(t, got.AuthorizationDetails, 3,
		"every supplied entry MUST be delivered to the consumer")

	assert.Equal(t, "type-a", got.AuthorizationDetails[0].Type)
	assert.Equal(t, "type-b", got.AuthorizationDetails[1].Type)
	assert.Equal(t, "type-c", got.AuthorizationDetails[2].Type)
}

// ── RFC 9396 §2.1 — Authorization Details Types ────────────────────────────

func TestRFC9396_S2_1_TypeFieldRequiredOnEveryElement(t *testing.T) {
	// RFC 9396 §2.1: "Every authorization details object MUST contain a
	//   `type` element."
	clientID := setupRARClient(t)

	resp := postBcAuthorize(t, clientID, []map[string]any{
		{"not_type": "still not a type"},
	})
	require.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"authorization_details element missing `type` MUST be rejected")

	body := decode(t, resp)
	require.Equal(t, "invalid_authorization_details", body["error"])
}

func TestRFC9396_S2_1_TypeMustBeString(t *testing.T) {
	// RFC 9396 §2.1: "The string value of the `type` field determines
	//   the actual structure of the rest of the authorization details
	//   object." A non-string `type` cannot discriminate the structure
	//   and MUST be rejected as malformed.
	clientID := setupRARClient(t)

	resp := postBcAuthorize(t, clientID, []map[string]any{
		{"type": 42},
	})
	require.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"non-string `type` MUST be rejected")

	body := decode(t, resp)
	require.Equal(t, "invalid_authorization_details", body["error"])
}

func TestRFC9396_S2_1_TypeMustBeNonEmpty(t *testing.T) {
	// RFC 9396 §2.1: the `type` field is a "string identifier" used as a
	//   discriminator. An empty string cannot identify anything and so
	//   cannot dispatch to a per-type validator or to a typed approver UX.
	//   ZeroID treats `type = ""` as a malformed contract violation, not a
	//   distinct "untyped" namespace.
	clientID := setupRARClient(t)

	resp := postBcAuthorize(t, clientID, []map[string]any{
		{"type": ""},
	})
	require.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"empty-string `type` MUST be rejected")

	body := decode(t, resp)
	require.Equal(t, "invalid_authorization_details", body["error"])
}

func TestRFC9396_S2_1_UnknownTypeFieldsPreservedVerbatim(t *testing.T) {
	// RFC 9396 §2.1: "The data fields of any concrete authorization details
	//   object are derived from the `type` field." ZeroID does not know
	//   any concrete schema beyond `type` — yet the consumer (per-type
	//   validator, BackchannelNotifier, the future token-embed path) MUST
	//   see the full original payload, not just `type`. This pins the
	//   raw-preservation contract that lets deployers layer arbitrary
	//   typed schemas on top without the library re-marshalling them.
	clientID := setupRARClient(t)

	notifier := newRecordingNotifier()
	testZeroIDServer.SetBackchannelNotifier(notifier.notify)
	testZeroIDServer.SetBackchannelNotifyDispatchSync(true)
	t.Cleanup(func() {
		testZeroIDServer.SetBackchannelNotifyDispatchSync(false)
		testZeroIDServer.SetBackchannelNotifier(nil)
	})

	resp := postBcAuthorize(t, clientID, []map[string]any{
		{
			"type":      "highflame_tool_call",
			"tool":      "transfer_funds",
			"amount":    50000,
			"locations": []string{"acct_X"},
			"datatypes": []string{"pii"},
		},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)

	got := notifier.last()
	require.NotNil(t, got)
	require.Len(t, got.AuthorizationDetails, 1)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(got.AuthorizationDetails[0].Raw, &decoded))

	for _, key := range []string{"type", "tool", "amount", "locations", "datatypes"} {
		assert.Contains(t, decoded, key,
			"field %q MUST survive round-trip in the raw payload", key)
	}
}

// ── RFC 9396 §3 / §5 — Content Type and Error Response ─────────────────────

func TestRFC9396_S3_FormEncodedAuthorizationDetailsAccepted(t *testing.T) {
	// RFC 9396 §3 (and the underlying RFC 6749 §3.1 / §3.2 form-encoding
	//   requirements for OAuth-style request bodies): clients MAY send
	//   the request body as application/x-www-form-urlencoded with
	//   `authorization_details` carrying the URL-encoded JSON array
	//   string. The authorization server MUST decode the JSON value and
	//   process it identically to the JSON-body case.
	clientID := setupRARClient(t)

	notifier := newRecordingNotifier()
	testZeroIDServer.SetBackchannelNotifier(notifier.notify)
	testZeroIDServer.SetBackchannelNotifyDispatchSync(true)
	t.Cleanup(func() {
		testZeroIDServer.SetBackchannelNotifyDispatchSync(false)
		testZeroIDServer.SetBackchannelNotifier(nil)
	})

	rar := `[{"type":"highflame_tool_call","tool":"transfer_funds"}]`
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("account_id", testAccountID)
	form.Set("project_id", testProjectID)
	form.Set("login_hint", "alice@example.com")
	form.Set("scope", "openid")
	form.Set("authorization_details", rar)

	req, err := http.NewRequest(http.MethodPost,
		testServer.URL+"/oauth2/bc-authorize",
		bytes.NewReader([]byte(form.Encode())),
	)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode,
		"form-encoded authorization_details MUST be accepted")

	got := notifier.last()
	require.NotNil(t, got)
	require.Len(t, got.AuthorizationDetails, 1,
		"form-encoded entry MUST reach the consumer identically to JSON-body")
	assert.Equal(t, "highflame_tool_call", got.AuthorizationDetails[0].Type)
}

func TestRFC9396_S5_ErrorCodeIsInvalidAuthorizationDetails(t *testing.T) {
	// RFC 9396 §5 (Error Response): "If the request itself is not valid or
	//   any of the given authorization details is not valid, the
	//   authorization server fails the request indicating
	//   `invalid_authorization_details` as the error code."
	//
	// This pins the OAuth error-code uniformity contract — every RAR-side
	// rejection MUST map to `invalid_authorization_details`, not the
	// adjacent `invalid_request` (RFC 6749 §5.2) which clients may handle
	// differently (retry, reject scope, surface to user).
	clientID := setupRARClient(t)

	resp := postBcAuthorize(t, clientID, []map[string]any{
		{"not_type": "still missing"},
	})
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(body, &parsed))
	require.Equal(t, "invalid_authorization_details", parsed["error"],
		"RFC 9396 §5: any authorization_details-side rejection MUST use error code invalid_authorization_details")
	assert.NotEmpty(t, parsed["error_description"],
		"error_description SHOULD be set so the client can render the failure")
}

func TestRFC9396_S5_ValidatorErrorMapsToInvalidAuthorizationDetails(t *testing.T) {
	// RFC 9396 §5: any "of the given authorization details is not valid"
	//   path resolves to the same error code. The opt-in per-type validator
	//   hook is one of those paths — a validator rejection MUST not leak
	//   as a different error code (e.g. `invalid_request` or `access_denied`)
	//   just because the rejection source is deployer code rather than
	//   library code.
	clientID := setupRARClient(t)

	testZeroIDServer.RegisterAuthorizationDetailValidator(
		"compliance_test_only",
		func(_ json.RawMessage) error {
			return assert.AnError
		},
	)
	t.Cleanup(func() {
		testZeroIDServer.RegisterAuthorizationDetailValidator("compliance_test_only", nil)
	})

	resp := postBcAuthorize(t, clientID, []map[string]any{
		{"type": "compliance_test_only"},
	})
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	body := decode(t, resp)
	require.Equal(t, "invalid_authorization_details", body["error"],
		"validator rejection MUST surface as invalid_authorization_details, not invalid_request")
}

// ── RFC 9396 §5.2 — Token Response ─────────────────────────────────────────
//
// The §5/§6/§7 token-side tests share the bc-authorize → approve → poll
// scaffolding. issueRARToken returns the parsed token-response body and the
// approved access-token string so each compliance test can pick the surface
// it cares about (response field, JWT claim, introspection) without
// duplicating the lifecycle.
func issueRARToken(t *testing.T, rar []map[string]any) (tokenBody map[string]any, accessToken string) {
	t.Helper()

	clientID := setupRARClient(t)

	resp := postBcAuthorize(t, clientID, rar)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	authReqID, _ := decode(t, resp)["auth_req_id"].(string)
	require.NotEmpty(t, authReqID)

	approveResp := post(t,
		adminPath("/oauth2/bc-authorize/"+authReqID+"/approve"),
		map[string]any{"subject_id": "compliance-subject"},
		adminHeaders(),
	)
	require.Equal(t, http.StatusOK, approveResp.StatusCode)

	tokenResp := post(t, "/oauth2/token", map[string]any{
		"grant_type":  "urn:openid:params:grant-type:ciba",
		"auth_req_id": authReqID,
		"client_id":   clientID,
	}, nil)
	require.Equal(t, http.StatusOK, tokenResp.StatusCode)

	tokenBody = decode(t, tokenResp)
	accessToken, _ = tokenBody["access_token"].(string)
	require.NotEmpty(t, accessToken)

	return tokenBody, accessToken
}

func TestRFC9396_S5_2_TokenResponseIncludesAuthorizationDetails(t *testing.T) {
	// RFC 9396 §5.2: "If the authorization_details parameter of the request
	//   was [...] not modified by the authorization server, [...] the AS
	//   MUST include the granted authorization_details ... in the token
	//   response." ZeroID grants verbatim (no modification), so the token
	//   response MUST carry the exact array the client supplied.
	tokenBody, _ := issueRARToken(t, []map[string]any{
		{"type": "highflame_tool_call", "tool": "transfer_funds"},
	})

	ad, ok := tokenBody["authorization_details"].([]any)
	require.True(t, ok,
		"token response MUST include authorization_details as a JSON array; got %T", tokenBody["authorization_details"])
	require.Len(t, ad, 1, "every granted element MUST be present on the response")

	first, _ := ad[0].(map[string]any)
	require.Equal(t, "highflame_tool_call", first["type"])
	require.Equal(t, "transfer_funds", first["tool"])
}

func TestRFC9396_S5_2_TokenResponseCarriesEmptyArrayForLegacyFlow(t *testing.T) {
	// RFC 9396 §5.2: the AS MUST include the granted authorization_details on
	//   the token response. For legacy CIBA (no RAR supplied on bc-authorize),
	//   the grant is the empty array. ZeroID surfaces that empty array on the
	//   response — consumers branch on `len > 0` to detect "actual typed grant
	//   in effect" rather than on field presence. (Earlier drafts of this PR
	//   omitted the field when empty; dropped per #168 review feedback.)
	clientID := setupRARClient(t)

	resp := postBcAuthorize(t, clientID, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	authReqID, _ := decode(t, resp)["auth_req_id"].(string)

	approveResp := post(t,
		adminPath("/oauth2/bc-authorize/"+authReqID+"/approve"),
		map[string]any{"subject_id": "compliance-subject-legacy"},
		adminHeaders(),
	)
	require.Equal(t, http.StatusOK, approveResp.StatusCode)

	tokenResp := post(t, "/oauth2/token", map[string]any{
		"grant_type":  "urn:openid:params:grant-type:ciba",
		"auth_req_id": authReqID,
		"client_id":   clientID,
	}, nil)
	require.Equal(t, http.StatusOK, tokenResp.StatusCode)

	tokenBody := decode(t, tokenResp)

	ad, ok := tokenBody["authorization_details"].([]any)
	require.True(t, ok,
		"legacy CIBA token response carries authorization_details as a JSON array (empty); got %T", tokenBody["authorization_details"])
	require.Empty(t, ad, "legacy flow MUST surface the empty array, not synthesised entries")
}

// ── RFC 9396 §6.1 — Enrich the Access Token ─────────────────────────────────

func TestRFC9396_S6_1_AccessTokenJWTEmbedsAuthorizationDetails(t *testing.T) {
	// RFC 9396 §6.1: "The AS MAY enrich the access token with the granted
	//   authorization_details" — when the AS does enrich, the claim's
	//   value MUST be the same JSON shape the client supplied. ZeroID
	//   embeds the claim by default so resource servers can read the
	//   typed grant without an introspection round-trip; this test pins
	//   that contract.
	_, accessToken := issueRARToken(t, []map[string]any{
		{"type": "highflame_tool_call", "tool": "transfer_funds", "amount": 50000},
	})

	claims := decodeJWTPayload(t, accessToken)
	ad, ok := claims["authorization_details"].([]any)
	require.True(t, ok,
		"access-token JWT MUST carry authorization_details claim; got %T", claims["authorization_details"])
	require.Len(t, ad, 1)

	first, _ := ad[0].(map[string]any)
	require.Equal(t, "highflame_tool_call", first["type"])
	require.Equal(t, "transfer_funds", first["tool"])
}

// ── RFC 9396 §7 — Token Introspection ───────────────────────────────────────

func TestRFC9396_S7_IntrospectionExposesAuthorizationDetails(t *testing.T) {
	// RFC 9396 §7: "The authorization_details element ... MAY be included
	//   in the response of the introspection endpoint [RFC7662]." When
	//   included, it MUST be the same JSON shape granted on issuance so
	//   resource servers and audit pipelines see a consistent view across
	//   the token + introspection surfaces.
	_, accessToken := issueRARToken(t, []map[string]any{
		{"type": "highflame_tool_call", "tool": "transfer_funds"},
	})

	introspectBody := introspect(t, accessToken)
	require.Equal(t, true, introspectBody["active"])

	ad, ok := introspectBody["authorization_details"].([]any)
	require.True(t, ok,
		"introspection MUST surface authorization_details when the token carries it; got %T", introspectBody["authorization_details"])
	require.Len(t, ad, 1)

	first, _ := ad[0].(map[string]any)
	require.Equal(t, "highflame_tool_call", first["type"])
	require.Equal(t, "transfer_funds", first["tool"])
}
