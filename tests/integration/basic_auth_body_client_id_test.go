package integration_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/domain"
)

// A body client_id beside an HTTP Basic header (highflame-firehog#700).
//
// RFC 6749 §2.3 forbids more than one client authentication METHOD per request.
// A bare client_id is an identifier, not a method (RFC 6749 §3.2.1: "A client
// MAY use the "client_id" request parameter to identify itself"), and the
// reference MCP SDK always sends Basic plus a body client_id. These tests drive
// the decision table through all three endpoints that accept client_secret_basic
// over the canonical form-encoded wire, and redeem an ID-JAG with the exact
// request the reference SDK builds.
//
// Run in isolation:
//
//	go test ./tests/integration/ -run 'TestBasicAuthBodyClientID' -count=1

// sdkBasicHeader builds the Basic header the way the reference MCP SDK does:
// Python's quote(s, safe="") on each half — percent-encoding, with a space as
// %20 rather than '+' — then base64 of "id:secret" (RFC 6749 §2.3.1).
func sdkBasicHeader(clientID, clientSecret string) map[string]string {
	enc := func(s string) string { return strings.ReplaceAll(url.QueryEscape(s), "+", "%20") }
	cred := base64.StdEncoding.EncodeToString([]byte(enc(clientID) + ":" + enc(clientSecret)))
	return map[string]string{"Authorization": "Basic " + cred}
}

// TestBasicAuthBodyClientID_DecisionTable runs the four rows of the #700 table
// against token, introspection and revocation.
func TestBasicAuthBodyClientID_DecisionTable(t *testing.T) {
	type row struct {
		name       string
		bodyID     func(client oauthClientResp) string
		bodySecret func(client oauthClientResp) string
		wantOK     bool
	}
	none := func(oauthClientResp) string { return "" }
	rows := []row{
		{"Basic only", none, none, true},
		{"Basic + equal body client_id", func(c oauthClientResp) string { return c.ClientID }, none, true},
		{"Basic + different body client_id", func(oauthClientResp) string { return "some-other-client" }, none, false},
		{"Basic + body client_secret", none, func(c oauthClientResp) string { return c.ClientSecret }, false},
	}

	// Each endpoint returns (status, error code) for the given form + client.
	endpoints := map[string]func(t *testing.T, client oauthClientResp, token string, form url.Values) (int, string){
		"token": func(t *testing.T, client oauthClientResp, _ string, form url.Values) (int, string) {
			form.Set("grant_type", "client_credentials")
			form.Set("account_id", testAccountID)
			form.Set("project_id", testProjectID)
			form.Set("scope", "data:read")
			return formStatus(t, "/oauth2/token", form, client)
		},
		"introspection": func(t *testing.T, client oauthClientResp, token string, form url.Values) (int, string) {
			form.Set("token", token)
			return formStatus(t, "/oauth2/token/introspect", form, client)
		},
		"revocation": func(t *testing.T, client oauthClientResp, token string, form url.Values) (int, string) {
			form.Set("token", token)
			return formStatus(t, "/oauth2/token/revoke", form, client)
		},
	}

	for epName, call := range endpoints {
		for _, r := range rows {
			t.Run(epName+"/"+r.name, func(t *testing.T) {
				token, client := inspectionFixture(t, "basic-bodyid-"+epName)

				form := url.Values{}
				if v := r.bodyID(client); v != "" {
					form.Set("client_id", v)
				}
				if v := r.bodySecret(client); v != "" {
					form.Set("client_secret", v)
				}

				status, errCode := call(t, client, token, form)
				if r.wantOK {
					require.Equal(t, http.StatusOK, status, "error=%s", errCode)
					assert.Empty(t, errCode)
					if epName == "revocation" {
						assert.False(t, introspect(t, token)["active"].(bool),
							"an accepted revocation must actually revoke")
					}
					return
				}
				require.Equal(t, http.StatusBadRequest, status)
				assert.Equal(t, "invalid_request", errCode)
				if epName == "revocation" {
					assert.True(t, introspect(t, token)["active"].(bool),
						"a refused revocation must leave the token active")
				}
			})
		}
	}
}

// formStatus posts a form with the client's SDK-shaped Basic header and returns
// the status and RFC 6749 §5.2 error code (empty on success).
func formStatus(t *testing.T, path string, form url.Values, client oauthClientResp) (int, string) {
	t.Helper()
	resp := postFormWithHeaders(t, path, form, sdkBasicHeader(client.ClientID, client.ClientSecret))
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	code, _ := body["error"].(string)
	return resp.StatusCode, code
}

// TestBasicAuthBodyClientID_ReferenceSDKRedeemsIDJAG sends the request the
// reference MCP SDK (mcp 2.3.0, IdentityAssertionOAuthProvider
// ._build_token_request) builds for client_secret_basic — form-encoded
// grant_type + assertion + client_id + resource, Basic header, no body secret,
// plus ZeroID's tenant parameters — and requires the ID-JAG to redeem. Before #700 this exact shape was refused
// with 400 before the assertion was read.
func TestBasicAuthBodyClientID_ReferenceSDKRedeemsIDJAG(t *testing.T) {
	upstreamIss := "https://corp-idp.basic-bodyid.test"
	federationAud := "https://zeroid.basic-bodyid.test"
	const mcpResource = "https://mcp-server.basic-bodyid.test"

	upstream := newFakeUpstreamIdP(t)
	defer upstream.Close()

	fedSrv, fedHTTPSrv, fedCfg := newFederationServer(t, domain.ExternalIssuerConfig{
		Issuer:          upstreamIss,
		JWKSURI:         upstream.JWKSURL(),
		Audience:        federationAud,
		ClaimMapping:    map[string]string{"user_id": "sub", "email": "email"},
		AllowedAccounts: []string{"acct-fed-001"},
	})
	defer fedHTTPSrv.Close()
	defer func() { _ = fedSrv.Shutdown(context.Background()) }()

	client := registerOAuthClient(t, uid("basic-bodyid-idjag"), []string{"data:read"})

	now := time.Now()
	idjag := upstream.SignTokenWithTyp(t, idJAGTyp, map[string]any{
		"iss":       upstreamIss,
		"aud":       federationAud,
		"sub":       "00uBASICBODYID",
		"email":     "agent@corp.example.com",
		"client_id": client.ClientID,
		"jti":       uid("basic-bodyid-jti"),
		"resource":  mcpResource,
		"scope":     "tools:read",
		"iat":       now.Unix(),
		"exp":       now.Add(5 * time.Minute).Unix(),
	})

	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {idjag},
		"client_id":  {client.ClientID},
		"resource":   {mcpResource},
		"scope":      {"tools:read"},
		// ZeroID-specific tenant binding, which the ID-JAG grant currently
		// requires and the reference SDK does not send. Orthogonal to client
		// authentication, so it is added here to isolate the #700 behaviour.
		"account_id": {fedCfg.AccountID},
		"project_id": {fedCfg.ProjectID},
	}

	req, err := http.NewRequest(http.MethodPost, fedHTTPSrv.URL+"/oauth2/token", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range sdkBasicHeader(client.ClientID, client.ClientSecret) {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, resp.StatusCode,
		"the reference SDK's Basic + body client_id shape must redeem; body=%s", raw)

	var body map[string]any
	require.NoError(t, json.Unmarshal(raw, &body))
	tok, _ := body["access_token"].(string)
	claims := decodeIssuedTokenClaims(t, tok)
	assert.Equal(t, []any{mcpResource}, claims["aud"])
	assert.Equal(t, client.ClientID, claims["client_id"],
		"the minted token must name the Basic-authenticated client")
}
