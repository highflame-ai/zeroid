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

// TestIntrospectionReturnsAudience verifies that RFC 7662 introspection
// surfaces the `aud` claim. Since every issued token now carries aud
// (defaulted to the issuer if unspecified), including it in the introspection
// response gives relying parties an easy way to check audience without
// parsing the JWT themselves.
func TestIntrospectionReturnsAudience(t *testing.T) {
	// Defaulted case: client_credentials with no audience → introspect → aud=[issuer].
	agentID := uid("aud-introspect-default")
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
	defaultedToken := decode(t, resp)["access_token"].(string)

	result := introspect(t, defaultedToken)
	require.True(t, result["active"].(bool))
	audRaw, ok := result["aud"]
	require.True(t, ok, "introspection response must include aud")
	require.NotNil(t, audRaw, "aud must not be null")
	audSlice, ok := audRaw.([]any)
	require.True(t, ok, "aud should be a JSON array, got %T", audRaw)
	require.Len(t, audSlice, 1)
	assert.Equal(t, testIssuer, audSlice[0])

	// Explicit-audience case: admin /credentials/issue with explicit audience →
	// introspect → aud preserved.
	explicitID := uid("aud-introspect-explicit")
	explicitIdentity := registerIdentity(t, explicitID, scopes)
	explicitAud := []string{"https://target.example.com/api"}

	issueResp := post(t, adminPath("/credentials/issue"), map[string]any{
		"identity_id": explicitIdentity.ID,
		"scopes":      scopes,
		"audience":    explicitAud,
	}, adminHeaders())
	require.Equal(t, http.StatusCreated, issueResp.StatusCode)
	explicitToken := decode(t, issueResp)["token"].(map[string]any)["access_token"].(string)

	result = introspect(t, explicitToken)
	require.True(t, result["active"].(bool))
	audSlice, ok = result["aud"].([]any)
	require.True(t, ok)
	require.Len(t, audSlice, 1)
	assert.Equal(t, explicitAud[0], audSlice[0])
}

// TestRotationPreservesExplicitAudience verifies that RotateCredential
// propagates the explicit audience from the original credential onto the
// rotated one. Without this, rotating a token issued for a specific audience
// would silently produce a new token with aud=issuer, breaking clients that
// check a specific audience value.
func TestRotationPreservesExplicitAudience(t *testing.T) {
	agentID := uid("aud-rotate-agent")
	scopes := []string{"data:read"}
	identity := registerIdentity(t, agentID, scopes)

	explicitAud := []string{"https://target.example.com/api"}

	// Issue with explicit audience.
	issueResp := post(t, adminPath("/credentials/issue"), map[string]any{
		"identity_id": identity.ID,
		"scopes":      scopes,
		"audience":    explicitAud,
	}, adminHeaders())
	require.Equal(t, http.StatusCreated, issueResp.StatusCode)
	body := decode(t, issueResp)
	credID := body["credential"].(map[string]any)["id"].(string)
	require.NotEmpty(t, credID)

	// Rotate the credential.
	rotateResp := post(t, adminPath("/credentials/"+credID+"/rotate"), nil, adminHeaders())
	require.Equal(t, http.StatusCreated, rotateResp.StatusCode)
	rotated := decode(t, rotateResp)
	rotatedToken := rotated["token"].(map[string]any)["access_token"].(string)
	require.NotEmpty(t, rotatedToken)

	// Rotated token must carry the original audience.
	parsed, err := jwt.ParseInsecure([]byte(rotatedToken))
	require.NoError(t, err)
	assert.Equal(t, explicitAud, parsed.Audience(),
		"rotation must propagate the original explicit audience")
}

// TestRotationDefaultsAudienceWhenOriginalHadNone verifies that rotating a
// credential issued without an audience re-defaults `aud` to the issuer URL
// (consistent with fresh issuance behavior) rather than producing a token
// with no aud claim at all.
func TestRotationDefaultsAudienceWhenOriginalHadNone(t *testing.T) {
	agentID := uid("aud-rotate-default-agent")
	scopes := []string{"data:read"}
	identity := registerIdentity(t, agentID, scopes)

	// Issue without audience — JWT gets aud=[issuer], DB row stores audience=NULL.
	issueResp := post(t, adminPath("/credentials/issue"), map[string]any{
		"identity_id": identity.ID,
		"scopes":      scopes,
	}, adminHeaders())
	require.Equal(t, http.StatusCreated, issueResp.StatusCode)
	body := decode(t, issueResp)
	credID := body["credential"].(map[string]any)["id"].(string)

	// Rotate — since old.Audience is nil, new token re-defaults.
	rotateResp := post(t, adminPath("/credentials/"+credID+"/rotate"), nil, adminHeaders())
	require.Equal(t, http.StatusCreated, rotateResp.StatusCode)
	rotated := decode(t, rotateResp)
	rotatedToken := rotated["token"].(map[string]any)["access_token"].(string)

	parsed, err := jwt.ParseInsecure([]byte(rotatedToken))
	require.NoError(t, err)
	assert.Equal(t, []string{testIssuer}, parsed.Audience(),
		"rotation must default aud to issuer when the original had none")
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
