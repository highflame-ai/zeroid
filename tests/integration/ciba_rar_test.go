package integration_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCIBA_RAR_NotifierReceivesParsedDetails covers the happy-path RAR flow
// against /oauth2/bc-authorize: a client posts a well-formed
// authorization_details array, the request is accepted, and the
// BackchannelNotifier hook receives the typed slice with each element's
// Type populated and Raw preserving the original JSON bytes.
//
// This is the load-bearing integration assertion for AuthN's BackchannelNotifier
// implementation downstream — AuthN will read AuthorizationDetails to
// construct typed approval prompts for Studio. If this contract breaks,
// AuthN's typed payload construction breaks silently.
func TestCIBA_RAR_NotifierReceivesParsedDetails(t *testing.T) {
	clientID := uid("ciba-rar-client")
	registerTestOAuthClient(clientID, []string{"client_credentials"})

	notifier := newRecordingNotifier()
	testZeroIDServer.SetBackchannelNotifier(notifier.notify)
	testZeroIDServer.SetBackchannelNotifyDispatchSync(true)
	t.Cleanup(func() {
		testZeroIDServer.SetBackchannelNotifyDispatchSync(false)
		testZeroIDServer.SetBackchannelNotifier(nil)
	})

	// Multi-element payload — RFC 9396 explicitly allows N entries per
	// request. Two distinct types so the test also covers per-element
	// Type fidelity.
	resp := post(t, "/oauth2/bc-authorize", map[string]any{
		"client_id":  clientID,
		"account_id": testAccountID,
		"project_id": testProjectID,
		"login_hint": "alice@example.com",
		"scope":      "openid",
		"authorization_details": []map[string]any{
			{
				"type":   "highflame_tool_call",
				"tool":   "transfer_funds",
				"amount": 50000,
			},
			{
				"type":    "highflame_audit",
				"trace":   "abc-123",
				"actions": []string{"log"},
			},
		},
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "bc-authorize must accept well-formed RAR")

	got := notifier.last()
	require.NotNil(t, got, "notifier must have been invoked")
	require.Len(t, got.AuthorizationDetails, 2,
		"notifier must receive both RAR elements")
	require.Equal(t, "highflame_tool_call", got.AuthorizationDetails[0].Type)
	require.Equal(t, "highflame_audit", got.AuthorizationDetails[1].Type)

	// Raw bytes preserve the full per-element payload (not just `type`).
	// AuthN's typed payload construction will decode the Raw into its own
	// per-type Go struct, so the contract is "every field the client sent
	// survives intact."
	var first map[string]any
	require.NoError(t, json.Unmarshal(got.AuthorizationDetails[0].Raw, &first))
	require.Equal(t, "transfer_funds", first["tool"])
	require.InEpsilon(t, float64(50000), first["amount"], 0.0001)
}

// TestCIBA_RAR_BackwardCompatibleWhenOmitted confirms the legacy CIBA path
// is unchanged: a client that omits authorization_details continues to work
// exactly as before. The notifier sees an empty (nil) typed slice — not an
// error, not a non-empty array.
func TestCIBA_RAR_BackwardCompatibleWhenOmitted(t *testing.T) {
	clientID := uid("ciba-rar-legacy")
	registerTestOAuthClient(clientID, []string{"client_credentials"})

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
		"login_hint": "alice@example.com",
		"scope":      "openid",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"legacy bc-authorize (no RAR) must keep working unchanged")

	got := notifier.last()
	require.NotNil(t, got)
	require.Empty(t, got.AuthorizationDetails,
		"omitted authorization_details must surface as empty slice on the notification")
}

// TestCIBA_RAR_MalformedRejects covers the fail-closed outer-shape cases.
// Every rejection MUST come back as invalid_authorization_details (RFC 9396
// §5.4) — not invalid_request, not server_error — so clients can branch on
// the OAuth error code rather than parsing the description string.
func TestCIBA_RAR_MalformedRejects(t *testing.T) {
	clientID := uid("ciba-rar-bad")
	registerTestOAuthClient(clientID, []string{"client_credentials"})

	cases := []struct {
		name string
		body map[string]any
	}{
		{
			name: "outer is object not array",
			body: map[string]any{
				"client_id":             clientID,
				"account_id":            testAccountID,
				"project_id":            testProjectID,
				"login_hint":            "alice@example.com",
				"scope":                 "openid",
				"authorization_details": map[string]any{"type": "x"},
			},
		},
		{
			name: "element missing type",
			body: map[string]any{
				"client_id":             clientID,
				"account_id":            testAccountID,
				"project_id":            testProjectID,
				"login_hint":            "alice@example.com",
				"scope":                 "openid",
				"authorization_details": []map[string]any{{"foo": "bar"}},
			},
		},
		{
			name: "element empty type",
			body: map[string]any{
				"client_id":             clientID,
				"account_id":            testAccountID,
				"project_id":            testProjectID,
				"login_hint":            "alice@example.com",
				"scope":                 "openid",
				"authorization_details": []map[string]any{{"type": ""}},
			},
		},
		{
			name: "element non-string type",
			body: map[string]any{
				"client_id":             clientID,
				"account_id":            testAccountID,
				"project_id":            testProjectID,
				"login_hint":            "alice@example.com",
				"scope":                 "openid",
				"authorization_details": []map[string]any{{"type": 42}},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := post(t, "/oauth2/bc-authorize", c.body, nil)
			require.Equal(t, http.StatusBadRequest, resp.StatusCode,
				"malformed RAR must be rejected with 400")
			body := decode(t, resp)
			require.Equal(t, "invalid_authorization_details", body["error"],
				"RFC 9396 §5.4: error code must be invalid_authorization_details, got %v", body)
		})
	}
}

// TestCIBA_RAR_PerTypeValidator covers the opt-in per-type validator hook:
// a deployer-registered validator runs for matching `type` entries, and a
// validator rejection fails the entire request with the validator's error
// surfaced in the error_description.
func TestCIBA_RAR_PerTypeValidator(t *testing.T) {
	clientID := uid("ciba-rar-validator")
	registerTestOAuthClient(clientID, []string{"client_credentials"})

	// Register a strict validator for the `highflame_tool_call` type that
	// requires `tool` to be one of a small allowlist. Mirrors the kind of
	// policy AuthN will register in production.
	var validatorCalls int

	allowedTools := map[string]bool{"transfer_funds": true, "send_email": true}

	testZeroIDServer.RegisterAuthorizationDetailValidator(
		"highflame_tool_call",
		func(raw json.RawMessage) error {
			validatorCalls++

			var payload struct {
				Tool string `json:"tool"`
			}
			if err := json.Unmarshal(raw, &payload); err != nil {
				return err
			}

			if !allowedTools[payload.Tool] {
				return errors.New("tool not in allowlist")
			}

			return nil
		},
	)
	t.Cleanup(func() {
		testZeroIDServer.RegisterAuthorizationDetailValidator("highflame_tool_call", nil)
	})

	// Happy path: validator passes.
	respOK := post(t, "/oauth2/bc-authorize", map[string]any{
		"client_id":  clientID,
		"account_id": testAccountID,
		"project_id": testProjectID,
		"login_hint": "alice@example.com",
		"scope":      "openid",
		"authorization_details": []map[string]any{
			{"type": "highflame_tool_call", "tool": "transfer_funds"},
		},
	}, nil)
	require.Equal(t, http.StatusOK, respOK.StatusCode, "registered validator must accept allowed tool")
	require.Equal(t, 1, validatorCalls, "validator must have been invoked once for the matching element")

	// Reject path: validator returns error.
	respBad := post(t, "/oauth2/bc-authorize", map[string]any{
		"client_id":  clientID,
		"account_id": testAccountID,
		"project_id": testProjectID,
		"login_hint": "alice@example.com",
		"scope":      "openid",
		"authorization_details": []map[string]any{
			{"type": "highflame_tool_call", "tool": "drain_funds"},
		},
	}, nil)
	require.Equal(t, http.StatusBadRequest, respBad.StatusCode)
	body := decode(t, respBad)
	require.Equal(t, "invalid_authorization_details", body["error"])
	require.Contains(t, body["error_description"], "tool not in allowlist",
		"validator's error message must surface in error_description")
	require.Equal(t, 2, validatorCalls, "validator must have been invoked again on the bad payload")

	// Unregistered types pass through with outer-shape validation only —
	// the registered validator is type-scoped, not catch-all.
	respUnregistered := post(t, "/oauth2/bc-authorize", map[string]any{
		"client_id":  clientID,
		"account_id": testAccountID,
		"project_id": testProjectID,
		"login_hint": "alice@example.com",
		"scope":      "openid",
		"authorization_details": []map[string]any{
			{"type": "some_other_type", "anything": "goes"},
		},
	}, nil)
	require.Equal(t, http.StatusOK, respUnregistered.StatusCode,
		"unregistered types pass through under the permissive default")
	require.Equal(t, 2, validatorCalls,
		"validator must NOT be invoked for an unregistered type")
}

// TestCIBA_RAR_ExplicitEmptyArray covers the subtle case where the client
// supplies authorization_details but as an empty array. Distinct from the
// omitted-field case (which is covered above) because an explicit `[]` is
// a deliberate "no RAR for this request, but the client knows the field
// exists" signal. Behaviour must match omission: notifier sees an empty
// typed slice, no error, no validator dispatch.
func TestCIBA_RAR_ExplicitEmptyArray(t *testing.T) {
	clientID := uid("ciba-rar-empty")
	registerTestOAuthClient(clientID, []string{"client_credentials"})

	notifier := newRecordingNotifier()
	testZeroIDServer.SetBackchannelNotifier(notifier.notify)
	testZeroIDServer.SetBackchannelNotifyDispatchSync(true)
	t.Cleanup(func() {
		testZeroIDServer.SetBackchannelNotifyDispatchSync(false)
		testZeroIDServer.SetBackchannelNotifier(nil)
	})

	resp := post(t, "/oauth2/bc-authorize", map[string]any{
		"client_id":             clientID,
		"account_id":            testAccountID,
		"project_id":            testProjectID,
		"login_hint":            "alice@example.com",
		"scope":                 "openid",
		"authorization_details": []map[string]any{},
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"explicit empty authorization_details must succeed (legacy CIBA semantics)")

	got := notifier.last()
	require.NotNil(t, got)
	require.Empty(t, got.AuthorizationDetails,
		"explicit empty array must surface as an empty slice on the notification")
}

// TestCIBA_RAR_ValidatorPanicMapsToOAuthError covers the deployer-bug case:
// a registered per-type validator panics (nil-deref, library bug, etc.). The
// service MUST convert the panic into the same invalid_authorization_details
// response RFC 9396 §5.4 specifies for any RAR rejection, not let it propagate
// to a generic HTTP 500. Without this, a single buggy validator can deny
// every bc-authorize request with an opaque server error.
func TestCIBA_RAR_ValidatorPanicMapsToOAuthError(t *testing.T) {
	clientID := uid("ciba-rar-panic")
	registerTestOAuthClient(clientID, []string{"client_credentials"})

	testZeroIDServer.RegisterAuthorizationDetailValidator(
		"highflame_panicky",
		func(_ json.RawMessage) error {
			panic("simulated validator bug")
		},
	)
	t.Cleanup(func() {
		testZeroIDServer.RegisterAuthorizationDetailValidator("highflame_panicky", nil)
	})

	resp := post(t, "/oauth2/bc-authorize", map[string]any{
		"client_id":  clientID,
		"account_id": testAccountID,
		"project_id": testProjectID,
		"login_hint": "alice@example.com",
		"scope":      "openid",
		"authorization_details": []map[string]any{
			{"type": "highflame_panicky", "any": "payload"},
		},
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"validator panic must map to 400, not 500")
	body := decode(t, resp)
	require.Equal(t, "invalid_authorization_details", body["error"],
		"validator panic must map to RFC 9396 §5.4 error code")
}

// TestCIBA_RAR_FormEncoded covers RFC 9396 §2.1: a client MAY post the
// bc-authorize body as application/x-www-form-urlencoded. The
// authorization_details value is then a URL-encoded JSON array string. The
// oauthFormCompatMiddleware must bridge that to the JSON shape downstream
// so the notifier sees a typed slice exactly as it would for a JSON-body
// client. Without this, RFC-compliant clients written to the form-encoded
// path silently break.
func TestCIBA_RAR_FormEncoded(t *testing.T) {
	clientID := uid("ciba-rar-form")
	registerTestOAuthClient(clientID, []string{"client_credentials"})

	notifier := newRecordingNotifier()
	testZeroIDServer.SetBackchannelNotifier(notifier.notify)
	testZeroIDServer.SetBackchannelNotifyDispatchSync(true)
	t.Cleanup(func() {
		testZeroIDServer.SetBackchannelNotifyDispatchSync(false)
		testZeroIDServer.SetBackchannelNotifier(nil)
	})

	rar := `[{"type":"highflame_tool_call","tool":"transfer_funds","amount":50000}]`
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
		"form-encoded RAR must be accepted (RFC 9396 §2.1)")

	got := notifier.last()
	require.NotNil(t, got, "notifier must fire for form-encoded RAR")
	require.Len(t, got.AuthorizationDetails, 1)
	require.Equal(t, "highflame_tool_call", got.AuthorizationDetails[0].Type)

	var first map[string]any
	require.NoError(t, json.Unmarshal(got.AuthorizationDetails[0].Raw, &first))
	require.Equal(t, "transfer_funds", first["tool"])
}

// TestCIBA_RAR_FormEncodedMalformed covers the form-encoded sad path: an
// invalid JSON value supplied as the form parameter. The downstream parser
// must still return invalid_authorization_details, not a generic 400 — the
// error code is the contract clients branch on.
func TestCIBA_RAR_FormEncodedMalformed(t *testing.T) {
	clientID := uid("ciba-rar-form-bad")
	registerTestOAuthClient(clientID, []string{"client_credentials"})

	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("account_id", testAccountID)
	form.Set("project_id", testProjectID)
	form.Set("login_hint", "alice@example.com")
	form.Set("scope", "openid")
	form.Set("authorization_details", "not-json")

	req, err := http.NewRequest(http.MethodPost,
		testServer.URL+"/oauth2/bc-authorize",
		bytes.NewReader([]byte(form.Encode())),
	)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(body, &parsed))
	require.Equal(t, "invalid_authorization_details", parsed["error"],
		"malformed form-encoded RAR must map to RFC 9396 §5.4 error code")
}

// TestCIBA_RAR_TokenSideEndToEnd exercises the full RFC 9396 token-side flow:
// bc-authorize with authorization_details → admin approves → client polls
// the token endpoint → the issued access token carries authorization_details
// (a) on the token response body (§5.2), (b) as a JWT claim (§6.1), and
// (c) on the introspection result (§7). All three surfaces MUST agree on
// the same JSON payload that the bc-authorize call originally supplied.
//
// This is the load-bearing end-to-end test for AuthN's downstream consumers:
// Shield reads authorization_details from the JWT claim; any human-facing UI
// reads it from introspection. If the three surfaces drift, downstream
// receipt-chain commitment breaks silently.
func TestCIBA_RAR_TokenSideEndToEnd(t *testing.T) {
	clientID := uid("ciba-rar-token-side")
	registerTestOAuthClient(clientID, []string{"client_credentials"})

	const (
		approvedUserID    = "user-bob-001"
		approvedUserEmail = "bob@example.com"
	)

	// ── Step 1: bc-authorize with authorization_details ─────────────────────
	resp := post(t, "/oauth2/bc-authorize", map[string]any{
		"client_id":  clientID,
		"account_id": testAccountID,
		"project_id": testProjectID,
		"login_hint": "bob@example.com",
		"scope":      "openid",
		"authorization_details": []map[string]any{
			{
				"type":   "highflame_tool_call",
				"tool":   "transfer_funds",
				"amount": 50000,
			},
		},
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	authReqID, _ := decode(t, resp)["auth_req_id"].(string)
	require.NotEmpty(t, authReqID)

	// ── Step 2: admin approves ──────────────────────────────────────────────
	approveResp := post(t,
		adminPath("/oauth2/bc-authorize/"+authReqID+"/approve"),
		map[string]any{
			"subject_id":    approvedUserID,
			"subject_email": approvedUserEmail,
		},
		adminHeaders(),
	)
	require.Equal(t, http.StatusOK, approveResp.StatusCode)

	// ── Step 3: poll → access token issued ──────────────────────────────────
	tokenResp := post(t, "/oauth2/token", map[string]any{
		"grant_type":  "urn:openid:params:grant-type:ciba",
		"auth_req_id": authReqID,
		"client_id":   clientID,
	}, nil)
	require.Equal(t, http.StatusOK, tokenResp.StatusCode)
	tokenBody := decode(t, tokenResp)

	// (a) Token response body carries authorization_details (RFC 9396 §5.2).
	ad, ok := tokenBody["authorization_details"].([]any)
	require.True(t, ok, "token response body must carry authorization_details as a JSON array; got %T (%v)", tokenBody["authorization_details"], tokenBody)
	require.Len(t, ad, 1)

	first, _ := ad[0].(map[string]any)
	require.NotNil(t, first)
	require.Equal(t, "highflame_tool_call", first["type"])
	require.Equal(t, "transfer_funds", first["tool"])

	// (b) Access-token JWT carries authorization_details as a claim (§6.1).
	accessToken, _ := tokenBody["access_token"].(string)
	require.NotEmpty(t, accessToken)

	claims := decodeJWTPayload(t, accessToken)
	jwtAD, ok := claims["authorization_details"].([]any)
	require.True(t, ok, "access-token JWT must carry authorization_details claim; got %T", claims["authorization_details"])
	require.Len(t, jwtAD, 1)

	jwtFirst, _ := jwtAD[0].(map[string]any)
	require.Equal(t, "highflame_tool_call", jwtFirst["type"])
	require.Equal(t, "transfer_funds", jwtFirst["tool"])

	// (c) Introspection surfaces authorization_details (§7).
	introspectBody := introspect(t, accessToken)
	require.Equal(t, true, introspectBody["active"])
	introAD, ok := introspectBody["authorization_details"].([]any)
	require.True(t, ok, "introspection must surface authorization_details; got %T", introspectBody["authorization_details"])
	require.Len(t, introAD, 1)

	introFirst, _ := introAD[0].(map[string]any)
	require.Equal(t, "highflame_tool_call", introFirst["type"])
	require.Equal(t, "transfer_funds", introFirst["tool"])
}

// TestCIBA_RAR_LegacyFlowCarriesEmptyArray pins the legacy-CIBA token-side
// shape: a client that did not supply authorization_details on bc-authorize
// still gets the authorization_details field on the token response, in the
// JWT, and in introspection — populated with the canonical empty array `[]`.
//
// Earlier drafts of this PR special-cased the empty array to "omit the
// field everywhere", but per #168 review (Sharath) that was redundant
// complexity: an empty array IS the "no RAR grant" signal, and consumers
// can branch on `len > 0` either way. Dropping the omit-when-empty filter
// removed a re-parse on every CIBA token issuance and ~30 LOC of
// special-case code.
func TestCIBA_RAR_LegacyFlowCarriesEmptyArray(t *testing.T) {
	clientID := uid("ciba-rar-legacy-token")
	registerTestOAuthClient(clientID, []string{"client_credentials"})

	const approvedUserID = "user-legacy-001"

	resp := post(t, "/oauth2/bc-authorize", map[string]any{
		"client_id":  clientID,
		"account_id": testAccountID,
		"project_id": testProjectID,
		"login_hint": "legacy@example.com",
		"scope":      "openid",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	authReqID, _ := decode(t, resp)["auth_req_id"].(string)

	approveResp := post(t,
		adminPath("/oauth2/bc-authorize/"+authReqID+"/approve"),
		map[string]any{"subject_id": approvedUserID},
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

	bodyAD, ok := tokenBody["authorization_details"].([]any)
	require.True(t, ok,
		"legacy CIBA token response carries authorization_details as a JSON array (empty); got %T", tokenBody["authorization_details"])
	require.Empty(t, bodyAD, "legacy flow MUST surface the empty array, not synthesised entries")

	accessToken, _ := tokenBody["access_token"].(string)
	claims := decodeJWTPayload(t, accessToken)
	jwtAD, ok := claims["authorization_details"].([]any)
	require.True(t, ok, "legacy CIBA JWT carries authorization_details claim as empty array; got %T", claims["authorization_details"])
	require.Empty(t, jwtAD)

	introspectBody := introspect(t, accessToken)
	introAD, ok := introspectBody["authorization_details"].([]any)
	require.True(t, ok, "introspection surfaces authorization_details as empty array; got %T", introspectBody["authorization_details"])
	require.Empty(t, introAD)
}
