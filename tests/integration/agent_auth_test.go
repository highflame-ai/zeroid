package integration_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// foreignSignedToken mints a well-formed agent token signed by a key the
// server has never seen. Every claim is correct; only the signing key is
// wrong, so it isolates key trust from claim validation.
func foreignSignedToken(t *testing.T) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tok := jwt.New()
	require.NoError(t, tok.Set(jwt.IssuerKey, testIssuer))
	require.NoError(t, tok.Set(jwt.SubjectKey, "spiffe://zeroid.dev/forged"))
	require.NoError(t, tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour)))
	require.NoError(t, tok.Set("account_id", testAccountID))
	require.NoError(t, tok.Set("project_id", testProjectID))

	hdrs := jws.NewHeaders()
	require.NoError(t, hdrs.Set(jws.TypeKey, "JWT"))

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), key, jws.WithProtectedHeaders(hdrs)))
	require.NoError(t, err)
	return string(signed)
}

// AgentAuthMiddleware guards the agent self-service and proof-generation
// groups. Nothing exercised it before, because the suite signs api_key grant
// tokens with RS256 while the middleware accepted ES256 only — every request
// failed on the algorithm before reaching the behaviour under test. See #357.

// TestAgentAuth_AcceptsIssuedToken pins the contract the middleware exists to
// serve: a token ZeroID itself issued must clear it. The request may still
// fail later on its body, so the assertion is that it is not a 401.
func TestAgentAuth_AcceptsIssuedToken(t *testing.T) {
	token := issueAPIKeyToken(t, uid("agent-auth-accepts"))

	resp := post(t, "/agents/self/public-key", map[string]any{
		"new_public_key": "not-a-real-key",
		"new_key_proof":  "not-a-real-proof",
	}, map[string]string{"Authorization": "Bearer " + token})
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)

	assert.NotEqual(t, http.StatusUnauthorized, resp.StatusCode,
		"a ZeroID-issued token must clear agent auth; body=%s", string(body))
}

// TestAgentAuth_SameTokenBothDoors pins the two paths against each other. The
// forward-auth endpoint and the agent middleware verify the same issuer's
// tokens, so a token one accepts the other must not reject.
func TestAgentAuth_SameTokenBothDoors(t *testing.T) {
	token := issueAPIKeyToken(t, uid("agent-auth-both-doors"))

	verify := get(t, "/oauth2/token/verify", map[string]string{
		"Authorization": "Bearer " + token,
	})
	defer func() { _ = verify.Body.Close() }()
	require.Equal(t, http.StatusOK, verify.StatusCode,
		"precondition: forward-auth must accept this token")

	agent := post(t, "/agents/self/public-key", map[string]any{
		"new_public_key": "not-a-real-key",
		"new_key_proof":  "not-a-real-proof",
	}, map[string]string{"Authorization": "Bearer " + token})
	defer func() { _ = agent.Body.Close() }()

	assert.NotEqual(t, http.StatusUnauthorized, agent.StatusCode,
		"forward-auth accepted this token, so agent auth must not reject it")
}

// TestAgentAuth_RejectsForeignToken keeps the fix honest: widening the
// accepted algorithm set must not widen which keys are trusted. A token signed
// by a key outside the server's JWKS is still refused.
func TestAgentAuth_RejectsForeignToken(t *testing.T) {
	resp := post(t, "/agents/self/public-key", map[string]any{
		"new_public_key": "not-a-real-key",
		"new_key_proof":  "not-a-real-proof",
	}, map[string]string{"Authorization": "Bearer " + foreignSignedToken(t)})
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"a token signed by an unknown key must be refused")
}
