package integration_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/highflame-ai/zeroid/pkg/authjwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuthjwtVerifiesZeroIDToken is an end-to-end integration test that verifies
// the authjwt client package can verify tokens issued by ZeroID's /oauth2/token
// endpoint, using ZeroID's /.well-known/jwks.json for key resolution.
//
// Flow: register agent → get API key → exchange for RS256 JWT → verify with
// authjwt.Verifier against live JWKS → assert all claims round-trip correctly.
func TestAuthjwtVerifiesZeroIDToken(t *testing.T) {
	agentID := uid("authjwt-agent")

	// 1. Register an agent identity and get an API key.
	reg := registerAgent(t, agentID)
	require.NotEmpty(t, reg.APIKey)

	// 2. Exchange API key for an RS256 JWT via /oauth2/token.
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type": "api_key",
		"api_key":    reg.APIKey,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	tokenResp := decode(t, resp)
	accessToken, ok := tokenResp["access_token"].(string)
	require.True(t, ok, "response should contain access_token")
	require.NotEmpty(t, accessToken)

	// 3. Create an authjwt.Verifier pointing at ZeroID's JWKS endpoint.
	verifier, err := authjwt.NewVerifier(authjwt.VerifierConfig{
		JWKSURL: testServer.URL + "/.well-known/jwks.json",
		Issuer:  testIssuer,
	})
	require.NoError(t, err, "authjwt.NewVerifier should connect to ZeroID JWKS")
	defer verifier.Close()

	// 4. Verify the token using authjwt (JWKS-based, kid+alg matching).
	claims, err := verifier.Verify(context.Background(), accessToken)
	require.NoError(t, err, "authjwt should verify a ZeroID-issued token")

	// 5. Assert claims round-trip correctly.
	assert.Equal(t, testIssuer, claims.Issuer, "issuer should match ZeroID config")
	assert.Equal(t, testAccountID, claims.AccountID, "account_id should match")
	assert.Equal(t, testProjectID, claims.ProjectID, "project_id should match")
	assert.Equal(t, "api_key", claims.GrantType, "grant_type should be api_key")
	assert.NotEmpty(t, claims.Subject, "sub should be set")
	assert.NotEmpty(t, claims.JWTID, "jti should be set")
	assert.False(t, claims.ExpiresAt.IsZero(), "exp should be set")
	assert.False(t, claims.IssuedAt.IsZero(), "iat should be set")
}
