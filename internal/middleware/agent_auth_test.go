package middleware

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testKeySetIssuer = "https://issuer.test"

// addTestKey mirrors signing.addToKeySet: a public key with its kid, alg and
// use=sig, which is what jwx needs to resolve a token by kid.
func addTestKey(t *testing.T, set jwk.Set, pub any, kid string, alg jwa.SignatureAlgorithm) {
	t.Helper()
	k, err := jwk.Import[jwk.Key](pub)
	require.NoError(t, err)
	require.NoError(t, k.Set(jwk.KeyIDKey, kid))
	require.NoError(t, k.Set(jwk.AlgorithmKey, alg))
	require.NoError(t, k.Set(jwk.KeyUsageKey, "sig"))
	require.NoError(t, set.AddKey(k))
}

// mintKeySetToken signs a minimal agent token, stamping kid the way
// credential.go does so the verifier can select the key.
func mintKeySetToken(t *testing.T, alg jwa.SignatureAlgorithm, priv any, kid, issuer string) string {
	t.Helper()
	tok := jwt.New()
	require.NoError(t, tok.Set(jwt.IssuerKey, issuer))
	require.NoError(t, tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour)))
	require.NoError(t, tok.Set("account_id", "acct-1"))
	require.NoError(t, tok.Set("project_id", "proj-1"))

	hdrs := jws.NewHeaders()
	require.NoError(t, hdrs.Set(jws.KeyIDKey, kid))
	require.NoError(t, hdrs.Set(jws.TypeKey, "JWT"))

	signed, err := jwt.Sign(tok, jwt.WithKey(alg, priv, jws.WithProtectedHeaders(hdrs)))
	require.NoError(t, err)
	return string(signed)
}

// TestAgentAuthMiddleware_AcceptsEveryIssuedAlgorithm is the regression for
// #357. The middleware pinned jwa.ES256 and one EC key, so every RS256 token
// the grants issue was refused. It must now resolve either key by kid.
func TestAgentAuthMiddleware_AcceptsEveryIssuedAlgorithm(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	set := jwk.NewSet()
	addTestKey(t, set, &ecKey.PublicKey, "ec-1", jwa.ES256())
	addTestKey(t, set, &rsaKey.PublicKey, "rsa-1", jwa.RS256())

	handler := AgentAuthMiddleware(AgentAuthConfig{
		KeySet: set,
		Issuer: testKeySetIssuer,
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	cases := []struct {
		name  string
		token string
	}{
		{"ES256 — clientCredentials, tokenExchange, jwtBearer, refreshToken",
			mintKeySetToken(t, jwa.ES256(), ecKey, "ec-1", testKeySetIssuer)},
		{"RS256 — apiKeyGrant, authorizationCode, CIBA, ID-JAG",
			mintKeySetToken(t, jwa.RS256(), rsaKey, "rsa-1", testKeySetIssuer)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			req.Header.Set("Authorization", "Bearer "+tc.token)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusOK, rec.Code)
		})
	}
}

// TestAgentAuthMiddleware_KeyTrustStaysNarrow keeps the fix honest. Accepting
// more algorithms must not accept more keys, and must not accept a token from
// another issuer.
func TestAgentAuthMiddleware_KeyTrustStaysNarrow(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	foreignKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	foreignRSA, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	set := jwk.NewSet()
	addTestKey(t, set, &ecKey.PublicKey, "ec-1", jwa.ES256())

	handler := AgentAuthMiddleware(AgentAuthConfig{
		KeySet: set,
		Issuer: testKeySetIssuer,
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	cases := []struct {
		name  string
		token string
	}{
		// Right kid, wrong key: the signature must still fail.
		{"foreign EC key reusing a known kid",
			mintKeySetToken(t, jwa.ES256(), foreignKey, "ec-1", testKeySetIssuer)},
		// An RSA key nobody published, now that RS256 is an accepted algorithm.
		{"foreign RSA key",
			mintKeySetToken(t, jwa.RS256(), foreignRSA, "rsa-unknown", testKeySetIssuer)},
		// A kid outside the set.
		{"unknown kid",
			mintKeySetToken(t, jwa.ES256(), ecKey, "ec-does-not-exist", testKeySetIssuer)},
		// Correct key, wrong issuer.
		{"wrong issuer",
			mintKeySetToken(t, jwa.ES256(), ecKey, "ec-1", "https://evil.test")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			req.Header.Set("Authorization", "Bearer "+tc.token)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusUnauthorized, rec.Code)
		})
	}
}
