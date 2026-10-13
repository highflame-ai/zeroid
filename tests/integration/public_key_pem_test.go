package integration_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// badKeyPEMs are public_key_pem values every admin write path must refuse with
// 400 and the specific reason. Each used to 500 on all four paths below
// because the validator's error reached the handler unwrapped.
func badKeyPEMs(t *testing.T) map[string]struct{ pem, reason string } {
	t.Helper()
	pkix := func(pub any) string {
		der, err := x509.MarshalPKIXPublicKey(pub)
		require.NoError(t, err)
		return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	return map[string]struct{ pem, reason string }{
		"rsa":     {pkix(&rsaKey.PublicKey), "key type is RSA, want ECDSA"},
		"p384":    {pkix(&p384.PublicKey), "curve is P-384, want P-256"},
		"garbage": {"definitely not a key", "no PEM block found"},
	}
}

func requireBadKey400(t *testing.T, resp *http.Response, reason string) {
	t.Helper()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body := decode(t, resp)
	detail, _ := body["detail"].(string)
	assert.Contains(t, detail, "invalid public_key_pem: must be a PEM-encoded P-256 (ES256) public key")
	assert.Contains(t, detail, reason)
}

func TestPublicKeyPEM_InvalidIs400OnEveryWritePath(t *testing.T) {
	agent := registerAgent(t, uid("pkpem-agent"))
	identity := registerIdentity(t, uid("pkpem-ident"), nil)

	for name, tc := range badKeyPEMs(t) {
		t.Run(name, func(t *testing.T) {
			t.Run("POST /agents/register", func(t *testing.T) {
				ext := uid("pkpem-reg-" + name)
				resp := post(t, adminPath("/agents/register"), map[string]any{
					"name":           ext,
					"external_id":    ext,
					"created_by":     "test-user",
					"public_key_pem": tc.pem,
				}, adminHeaders())
				requireBadKey400(t, resp, tc.reason)
			})
			t.Run("POST /identities", func(t *testing.T) {
				resp := post(t, adminPath("/identities"), map[string]any{
					"external_id":    uid("pkpem-id-" + name),
					"owner_user_id":  "user-test-owner",
					"public_key_pem": tc.pem,
				}, adminHeaders())
				requireBadKey400(t, resp, tc.reason)
			})
			t.Run("PATCH /agents/registry/{id}", func(t *testing.T) {
				resp := doRequest(t, http.MethodPatch, adminPath("/agents/registry/"+agent.AgentID), map[string]any{
					"public_key_pem": tc.pem,
				}, adminHeaders())
				requireBadKey400(t, resp, tc.reason)
			})
			t.Run("PATCH /identities/{id}", func(t *testing.T) {
				resp := doRequest(t, http.MethodPatch, adminPath("/identities/"+identity.ID), map[string]any{
					"public_key_pem": tc.pem,
				}, adminHeaders())
				requireBadKey400(t, resp, tc.reason)
			})
		})
	}
}

// TestPublicKeyPEM_EmptyLeavesKeyUnchanged pins the existing PATCH semantics:
// an empty public_key_pem is "not set", so neither update path can clear an
// enrolled key.
func TestPublicKeyPEM_EmptyLeavesKeyUnchanged(t *testing.T) {
	keyPEM := ecPublicKeyPEM(t, generateKey(t))
	identity := registerIdentity(t, uid("pkpem-keep"), nil, keyPEM)

	for _, path := range []string{"/identities/" + identity.ID, "/agents/registry/" + identity.ID} {
		resp := doRequest(t, http.MethodPatch, adminPath(path), map[string]any{"public_key_pem": ""}, adminHeaders())
		require.Equal(t, http.StatusOK, resp.StatusCode, path)
		_ = resp.Body.Close()
	}

	got := decode(t, get(t, adminPath("/identities/"+identity.ID), adminHeaders()))
	assert.Equal(t, keyPEM, got["public_key_pem"])
}
