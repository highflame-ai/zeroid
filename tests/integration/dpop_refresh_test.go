package integration_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// authCodeWithDPoP exchanges a freshly-built auth code for an access + refresh
// token while presenting a DPoP proof. Returns the refresh_token and the
// thumbprint of the proof key (which both halves of the token chain must be
// bound to).
func authCodeWithDPoP(t *testing.T, userID string, dpopKey *ecdsa.PrivateKey) (refreshToken, thumbprint string) {
	t.Helper()
	verifier, challenge := buildPKCEPair(t)
	code := buildAuthCode(t, testMCPClientID, userID, testRedirectURI, challenge, []string{"data:read"})

	proof := buildDPoPProof(t, dpopKey, http.MethodPost, testServer.URL+"/oauth2/token", uuid.New().String())
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "authorization_code",
		"client_id":     testMCPClientID,
		"code":          code,
		"code_verifier": verifier,
		"redirect_uri":  testRedirectURI,
	}, map[string]string{"DPoP": proof})
	require.Equal(t, http.StatusOK, resp.StatusCode, "auth_code+DPoP exchange must succeed")
	body := decode(t, resp)
	assert.Equal(t, "DPoP", body["token_type"], "token_type must be DPoP when a proof is present")
	refreshToken, _ = body["refresh_token"].(string)
	require.NotEmpty(t, refreshToken, "auth-code exchange with refresh_token grant must return a refresh_token")
	thumbprint = dpopKeyThumbprint(t, &dpopKey.PublicKey)
	return
}

// TestDPoPRefreshBoundOriginalKeySucceeds verifies the happy path: a refresh
// token minted under DPoP can be redeemed by presenting a proof signed by the
// same key, and the rotated successor stays bound to that key.
func TestDPoPRefreshBoundOriginalKeySucceeds(t *testing.T) {
	dpopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	refreshToken, _ := authCodeWithDPoP(t, "user-dpop-refresh-ok", dpopKey)

	refreshProof := buildDPoPProof(t, dpopKey, http.MethodPost, testServer.URL+"/oauth2/token", uuid.New().String())
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "refresh_token",
		"client_id":     testMCPClientID,
		"refresh_token": refreshToken,
	}, map[string]string{"DPoP": refreshProof})
	require.Equal(t, http.StatusOK, resp.StatusCode, "refresh with the original DPoP key must succeed")
	body := decode(t, resp)
	assert.Equal(t, "DPoP", body["token_type"], "rotated access token must remain DPoP-bound")
	successorRT, _ := body["refresh_token"].(string)
	require.NotEmpty(t, successorRT)

	// Successor refresh token is itself bound — replaying the original is forbidden
	// (single-use, RFC 6749 §6) but the successor must rotate again with the same
	// key.
	successorProof := buildDPoPProof(t, dpopKey, http.MethodPost, testServer.URL+"/oauth2/token", uuid.New().String())
	resp2 := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "refresh_token",
		"client_id":     testMCPClientID,
		"refresh_token": successorRT,
	}, map[string]string{"DPoP": successorProof})
	require.Equal(t, http.StatusOK, resp2.StatusCode, "successor refresh must stay bound across the rotation chain")
	_ = resp2.Body.Close()
}

// TestDPoPRefreshBoundWithDifferentKeyRejected verifies that a refresh request
// signed by a different DPoP key is rejected with invalid_dpop_proof, and the
// underlying refresh token is NOT consumed by the failed attempt (so the
// legitimate client can still rotate it with the original key).
func TestDPoPRefreshBoundWithDifferentKeyRejected(t *testing.T) {
	originalKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	refreshToken, _ := authCodeWithDPoP(t, "user-dpop-refresh-wrong-key", originalKey)

	attackerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	require.NotEqual(t, dpopKeyThumbprint(t, &originalKey.PublicKey), dpopKeyThumbprint(t, &attackerKey.PublicKey))

	attackerProof := buildDPoPProof(t, attackerKey, http.MethodPost, testServer.URL+"/oauth2/token", uuid.New().String())
	bad := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "refresh_token",
		"client_id":     testMCPClientID,
		"refresh_token": refreshToken,
	}, map[string]string{"DPoP": attackerProof})
	require.Equal(t, http.StatusBadRequest, bad.StatusCode, "different-key DPoP proof must be rejected")
	errBody := decode(t, bad)
	assert.Equal(t, "invalid_dpop_proof", errBody["error"])

	// Original key still works — the failed attempt did NOT consume the refresh token.
	goodProof := buildDPoPProof(t, originalKey, http.MethodPost, testServer.URL+"/oauth2/token", uuid.New().String())
	good := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "refresh_token",
		"client_id":     testMCPClientID,
		"refresh_token": refreshToken,
	}, map[string]string{"DPoP": goodProof})
	require.Equal(t, http.StatusOK, good.StatusCode, "after a rejected wrong-key proof, the original key must still rotate the same refresh token")
	_ = good.Body.Close()
}

// TestDPoPRefreshBoundWithoutProofRejected verifies that a refresh request
// against a DPoP-bound refresh token without any DPoP header is rejected.
func TestDPoPRefreshBoundWithoutProofRejected(t *testing.T) {
	dpopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	refreshToken, _ := authCodeWithDPoP(t, "user-dpop-refresh-no-proof", dpopKey)

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "refresh_token",
		"client_id":     testMCPClientID,
		"refresh_token": refreshToken,
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "DPoP-bound refresh without proof must be rejected")
	errBody := decode(t, resp)
	assert.Equal(t, "invalid_dpop_proof", errBody["error"])
}
