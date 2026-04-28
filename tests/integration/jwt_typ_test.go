package integration_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIssuedTokenHasTypHeader locks in JWT-SVID §3's typ=JWT on issued
// tokens. api_key hits the RS256 branch, client_credentials hits ES256 —
// both have to set the header.
func TestIssuedTokenHasTypHeader(t *testing.T) {
	t.Run("api_key_RS256", func(t *testing.T) {
		token := issueAPIKeyToken(t, uid("typ-rs"))
		assertTokenTypIsJWT(t, token)
	})

	t.Run("client_credentials_ES256", func(t *testing.T) {
		agentID := uid("typ-es")
		registerIdentity(t, agentID, []string{"data:read"})
		client := registerOAuthClient(t, agentID, []string{"data:read"})

		resp := post(t, "/oauth2/token", map[string]any{
			"grant_type":    "client_credentials",
			"account_id":    testAccountID,
			"project_id":    testProjectID,
			"client_id":     client.ClientID,
			"client_secret": client.ClientSecret,
			"scope":         "data:read",
		}, nil)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		token := decode(t, resp)["access_token"].(string)

		assertTokenTypIsJWT(t, token)
	})
}

func assertTokenTypIsJWT(t *testing.T, tokenStr string) {
	t.Helper()
	dot := strings.IndexByte(tokenStr, '.')
	require.Greater(t, dot, 0, "token is not a compact JWS")

	raw, err := base64.RawURLEncoding.DecodeString(tokenStr[:dot])
	require.NoError(t, err, "header is not valid base64url")

	var hdr map[string]any
	require.NoError(t, json.Unmarshal(raw, &hdr), "header is not valid JSON")

	assert.Equal(t, "JWT", hdr["typ"], "JWT-SVID §3 expects typ=JWT in the header")
	// kid is required so verifiers can pick the right key from the JWKS.
	// Asserted here too since this test already cracks the header open.
	assert.NotEmpty(t, hdr["kid"], "issued tokens must carry a kid header")
}
