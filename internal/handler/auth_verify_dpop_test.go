package handler

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/pkg/dpop"
)

func TestCnfJKTFromClaims(t *testing.T) {
	assert.Equal(t, "", cnfJKTFromClaims(nil))
	assert.Equal(t, "", cnfJKTFromClaims(map[string]any{"active": true}))
	assert.Equal(t, "abc", cnfJKTFromClaims(map[string]any{
		"cnf": map[string]any{"jkt": "abc"},
	}))
	assert.Equal(t, "def", cnfJKTFromClaims(map[string]any{
		"cnf": map[string]string{"jkt": "def"},
	}))
}

func TestRejectBoundTokenWithoutDPoP(t *testing.T) {
	verifier, err := dpop.NewVerifier(dpop.Config{Store: dpop.NewMemoryStore()})
	require.NoError(t, err)

	boundClaims := map[string]any{
		"active": true,
		"cnf":    map[string]any{"jkt": "thumbprint-of-agent-key"},
	}
	unboundClaims := map[string]any{"active": true}

	t.Run("unbound token passes without DPoP header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://rs.test/oauth2/token/verify", nil)
		rr := httptest.NewRecorder()
		rejected := rejectBoundTokenWithoutDPoP(rr, req, "access-token", unboundClaims, verifier, "https://issuer/.well-known/oauth-protected-resource")
		assert.False(t, rejected)
		assert.Equal(t, http.StatusOK, rr.Code) // helper did not write
	})

	t.Run("bound token without DPoP header is rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://rs.test/oauth2/token/verify", nil)
		rr := httptest.NewRecorder()
		rejected := rejectBoundTokenWithoutDPoP(rr, req, "access-token", boundClaims, verifier, "https://issuer/.well-known/oauth-protected-resource")
		assert.True(t, rejected)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Contains(t, rr.Header().Get("WWW-Authenticate"), "invalid_token")
		assert.Contains(t, rr.Body.String(), "DPoP-bound")
	})

	t.Run("nil verifier leaves bound token alone", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://rs.test/oauth2/token/verify", nil)
		rr := httptest.NewRecorder()
		rejected := rejectBoundTokenWithoutDPoP(rr, req, "access-token", boundClaims, nil, "")
		assert.False(t, rejected)
	})

	t.Run("bound token with matching DPoP proof is accepted", func(t *testing.T) {
		dpopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		jkt := dpopThumbprint(t, &dpopKey.PublicKey)
		accessToken := "bound-access-token-for-ath"
		proof := buildBoundDPoPProof(t, dpopKey, http.MethodGet, "http://rs.test/oauth2/token/verify", accessToken)

		req := httptest.NewRequest(http.MethodGet, "http://rs.test/oauth2/token/verify", nil)
		req.Header.Set("DPoP", proof)
		rr := httptest.NewRecorder()
		claims := map[string]any{"cnf": map[string]any{"jkt": jkt}}
		rejected := rejectBoundTokenWithoutDPoP(rr, req, accessToken, claims, verifier, "")
		assert.False(t, rejected, "matching proof must pass; body=%s", rr.Body.String())
	})

	t.Run("bound token with wrong-key DPoP proof is rejected", func(t *testing.T) {
		dpopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		accessToken := "bound-access-token-wrong-key"
		proof := buildBoundDPoPProof(t, dpopKey, http.MethodGet, "http://rs.test/oauth2/token/verify", accessToken)

		req := httptest.NewRequest(http.MethodGet, "http://rs.test/oauth2/token/verify", nil)
		req.Header.Set("DPoP", proof)
		rr := httptest.NewRecorder()
		claims := map[string]any{"cnf": map[string]any{"jkt": "not-the-proof-key-thumbprint"}}
		rejected := rejectBoundTokenWithoutDPoP(rr, req, accessToken, claims, verifier, "")
		assert.True(t, rejected)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})
}

func dpopThumbprint(t *testing.T, pub *ecdsa.PublicKey) string {
	t.Helper()
	k, err := jwk.Import[jwk.Key](pub)
	require.NoError(t, err)
	tb, err := k.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(tb)
}

func buildBoundDPoPProof(t *testing.T, priv *ecdsa.PrivateKey, method, htu, accessToken string) string {
	t.Helper()
	privJWK, err := jwk.Import[jwk.Key](priv)
	require.NoError(t, err)
	pubJWK, err := jwk.Import[jwk.Key](&priv.PublicKey)
	require.NoError(t, err)

	sum := sha256.Sum256([]byte(accessToken))
	ath := base64.RawURLEncoding.EncodeToString(sum[:])

	payload, err := json.Marshal(map[string]any{
		"htm": method,
		"htu": htu,
		"iat": time.Now().Unix(),
		"jti": base64.RawURLEncoding.EncodeToString([]byte(time.Now().Format(time.RFC3339Nano))),
		"ath": ath,
	})
	require.NoError(t, err)

	hdrs := jws.NewHeaders()
	require.NoError(t, hdrs.Set("typ", "dpop+jwt"))
	require.NoError(t, hdrs.Set("jwk", pubJWK))

	signed, err := jws.Sign(payload,
		jws.WithKey(jwa.ES256(), privJWK, jws.WithProtectedHeaders(hdrs)),
	)
	require.NoError(t, err)
	return string(signed)
}
