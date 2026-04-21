package integration_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/pkg/authjwt"
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

// TestAuthjwtAcceptsDefaultedAudience is the end-to-end proof that the fix
// restores interop with spec-compliant verifiers: a token issued without an
// explicit audience must pass validation under an authjwt.Verifier that is
// configured with Audience = issuer URL. Pre-fix this failed with
// ErrInvalidAudience because no aud claim was present.
//
// Also exercises the negative path (mismatched audience → ErrInvalidAudience)
// to confirm the verifier is actually enforcing the check, not silently
// passing every token.
func TestAuthjwtAcceptsDefaultedAudience(t *testing.T) {
	agentID := uid("aud-verify-agent")
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

	// Positive: verifier configured with Audience = issuer accepts the token.
	verifier, err := authjwt.NewVerifier(authjwt.VerifierConfig{
		JWKSURL:  testServer.URL + "/.well-known/jwks.json",
		Issuer:   testIssuer,
		Audience: testIssuer,
	})
	require.NoError(t, err)
	defer verifier.Close()

	_, err = verifier.Verify(context.Background(), accessToken)
	require.NoError(t, err,
		"token with defaulted aud=issuer must verify under a spec-compliant verifier configured with the same audience")

	// Negative: verifier configured with a different audience rejects the
	// token — proves the verifier is actually checking aud, not no-opping.
	strictVerifier, err := authjwt.NewVerifier(authjwt.VerifierConfig{
		JWKSURL:  testServer.URL + "/.well-known/jwks.json",
		Issuer:   testIssuer,
		Audience: "https://different.example.com/api",
	})
	require.NoError(t, err)
	defer strictVerifier.Close()

	_, err = strictVerifier.Verify(context.Background(), accessToken)
	require.Error(t, err, "mismatched audience must be rejected")
	assert.True(t, errors.Is(err, authjwt.ErrInvalidAudience),
		"rejection reason should be ErrInvalidAudience, got: %v", err)
}
