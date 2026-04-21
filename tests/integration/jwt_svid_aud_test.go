package integration_test

import (
	"net/http"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIssuedTokenHasAudClaimDefault verifies that tokens issued without an
// explicit audience still carry the `aud` claim, defaulted to the issuer URL.
// This satisfies the JWT-SVID §3 MUST requirement and keeps tokens
// interoperable with spec-compliant verifiers (e.g., pkg/authjwt with a
// configured audience).
//
// Pre-fix behavior: any grant that did not set Audience on the IssueRequest
// produced a token with no aud claim at all — breaking JWT-SVID outright and
// RFC 7519 §4.1.3 guidance.
func TestIssuedTokenHasAudClaimDefault(t *testing.T) {
	agentID := uid("aud-default-agent")
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

	parsed, err := jwt.ParseInsecure([]byte(accessToken))
	require.NoError(t, err)

	aud := parsed.Audience()
	require.NotEmpty(t, aud, "aud claim MUST be present on issued tokens (JWT-SVID §3)")
	assert.Equal(t, []string{testIssuer}, aud,
		"aud must default to the issuer URL when no audience was requested")
}

// TestIssuedTokenPreservesExplicitAudience verifies that an explicit audience
// passed via the admin /credentials/issue path is preserved on the issued
// token (not clobbered by the default-to-issuer logic).
func TestIssuedTokenPreservesExplicitAudience(t *testing.T) {
	agentID := uid("aud-explicit-agent")
	scopes := []string{"data:read"}
	identity := registerIdentity(t, agentID, scopes)

	explicitAud := []string{"https://target.example.com/api"}

	resp := post(t, adminPath("/credentials/issue"), map[string]any{
		"identity_id": identity.ID,
		"scopes":      scopes,
		"audience":    explicitAud,
	}, adminHeaders())
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	body := decode(t, resp)
	tok := body["token"].(map[string]any)
	accessToken := tok["access_token"].(string)
	require.NotEmpty(t, accessToken)

	parsed, err := jwt.ParseInsecure([]byte(accessToken))
	require.NoError(t, err)

	assert.Equal(t, explicitAud, parsed.Audience(),
		"explicit audience must be preserved, not overwritten by the issuer default")
}
