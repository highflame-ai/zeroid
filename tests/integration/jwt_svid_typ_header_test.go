package integration_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIssuedES256TokenHasTypHeader verifies that ES256 NHI tokens issued via
// client_credentials carry typ="JWT" in the JOSE header per JWT-SVID §3 (and
// RFC 7519 best practice). Verifiers that distinguish token kinds via the
// header — including some SPIFFE-aware verifiers — rely on this signal.
func TestIssuedES256TokenHasTypHeader(t *testing.T) {
	agentID := uid("typ-header-es256")
	scopes := []string{"data:read"}

	registerIdentity(t, agentID, scopes)
	client := registerOAuthClient(t, agentID, scopes)

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	accessToken := decode(t, resp)["access_token"].(string)
	require.NotEmpty(t, accessToken)

	assertTypHeaderJWT(t, accessToken)
}

// TestIssuedRS256TokenHasTypHeader verifies that RS256 SDK/human-flow tokens
// (api_key grant) also carry typ="JWT". Same spec requirement, separate code
// path inside CredentialService.IssueCredential.
func TestIssuedRS256TokenHasTypHeader(t *testing.T) {
	headers := adminHeaders()
	headers["X-User-ID"] = "test-user"

	createResp := post(t, adminPath("/api-keys"), map[string]any{
		"name":    "typ-header-rs256",
		"product": "typ-header-rs256-product",
	}, headers)
	require.Equal(t, http.StatusCreated, createResp.StatusCode)

	apiKey := decode(t, createResp)["key"].(string)
	require.NotEmpty(t, apiKey, "api-key creation must return the full key once")

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type": "api_key",
		"api_key":    apiKey,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	accessToken := decode(t, resp)["access_token"].(string)
	require.NotEmpty(t, accessToken)

	assertTypHeaderJWT(t, accessToken)
}

// assertTypHeaderJWT decodes the JOSE header of a JWT and asserts the typ
// parameter is "JWT". Uses jws.Parse so the assertion is exact (rather than
// a substring scan that could pick up "JWT" from base64-encoded payload).
func assertTypHeaderJWT(t *testing.T, token string) {
	t.Helper()
	msg, err := jws.Parse([]byte(token))
	require.NoError(t, err, "JWT must be a parseable JWS")
	sigs := msg.Signatures()
	require.NotEmpty(t, sigs, "JWS must have at least one signature")

	hdr := sigs[0].ProtectedHeaders()
	require.NotNil(t, hdr, "JWS must have protected headers")

	typ := hdr.Type()
	assert.Equalf(t, "JWT", typ,
		"JOSE header must declare typ=JWT (JWT-SVID §3); got %q (full token: %s…)",
		typ, truncate(token, 32))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.TrimRight(s[:n], "=") + "…"
}
