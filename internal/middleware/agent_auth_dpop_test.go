package middleware

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/pkg/dpop"
)

func mintAgentToken(t *testing.T, key *ecdsa.PrivateKey, issuer string, withCnf bool) string {
	t.Helper()
	tok := jwt.New()
	require.NoError(t, tok.Set(jwt.IssuerKey, issuer))
	require.NoError(t, tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour)))
	require.NoError(t, tok.Set("account_id", "acct-1"))
	require.NoError(t, tok.Set("project_id", "proj-1"))
	if withCnf {
		require.NoError(t, tok.Set("cnf", map[string]string{"jkt": "thumbprint-of-agent-key"}))
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), key))
	require.NoError(t, err)
	return string(signed)
}

func TestAgentAuthMiddleware_DPOPBinding(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	verifier, err := dpop.NewVerifier(dpop.Config{Store: dpop.NewMemoryStore()})
	require.NoError(t, err)

	cfg := AgentAuthConfig{
		PublicKey:    &key.PublicKey,
		Issuer:       "https://issuer.test",
		DPoPVerifier: verifier,
	}

	okHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	h := AgentAuthMiddleware(cfg)(okHandler)

	t.Run("unbound token passes without DPoP header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/agents/self", nil)
		req.Header.Set("Authorization", "Bearer "+mintAgentToken(t, key, "https://issuer.test", false))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusNoContent, rr.Code)
	})

	t.Run("bound token without DPoP header is rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/agents/self", nil)
		req.Header.Set("Authorization", "Bearer "+mintAgentToken(t, key, "https://issuer.test", true))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})
}
