package integration_test

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/require"
)

// selfKeyProof signs a proof for POST /agents/self/public-key with key. When
// newKey is set, the proof is the current-key half of a rotation and carries
// nkt, the thumbprint of the key being rotated to.
func selfKeyProof(t *testing.T, key *ecdsa.PrivateKey, wimseURI string, newKey *ecdsa.PrivateKey) string {
	t.Helper()
	now := time.Now()
	b := jwt.NewBuilder().
		Subject(wimseURI).
		Audience([]string{testIssuer + "/agents/self/public-key"}).
		JwtID(uuid.NewString()).
		IssuedAt(now).
		Expiration(now.Add(time.Minute))
	if newKey != nil {
		der, err := x509.MarshalPKIXPublicKey(&newKey.PublicKey)
		require.NoError(t, err)
		sum := sha256.Sum256(der)
		b = b.Claim("nkt", base64.RawURLEncoding.EncodeToString(sum[:]))
	}
	tok, err := b.Build()
	require.NoError(t, err)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), key))
	require.NoError(t, err)
	return string(signed)
}

func enrollOwnKey(t *testing.T, token string, body map[string]any) *http.Response {
	t.Helper()
	return post(t, "/agents/self/public-key", body, map[string]string{"Authorization": "Bearer " + token})
}

// TestSelfKeyEnrollment_APIKeyAgentMovesToJWTBearer is the path an agent takes
// from an API key to its own key: enroll with the API-key token, authenticate
// with the jwt-bearer grant, rotate with both proofs. Before this, the endpoint
// looked the agent up from an identity_id claim ZeroID never issues, so every
// real token was refused with 401.
func TestSelfKeyEnrollment_APIKeyAgentMovesToJWTBearer(t *testing.T) {
	token := issueAPIKeyToken(t, uid("self-key"))
	wimse, _ := decodeJWTPayload(t, token)["sub"].(string)
	require.NotEmpty(t, wimse)

	key1 := generateKey(t)
	resp := enrollOwnKey(t, token, map[string]any{
		"new_public_key_pem": ecPublicKeyPEM(t, key1),
		"new_key_proof":      selfKeyProof(t, key1, wimse, nil),
	})
	body := decode(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode, "first enrollment: %v", body)
	require.Equal(t, wimse, body["wimse_uri"])

	resp = jwtBearerScope(t, buildAssertion(t, key1, wimse), "")
	body = decode(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode, "jwt-bearer with the enrolled key: %v", body)

	// A rotation needs the current key's proof, bound to the new key.
	key2 := generateKey(t)
	resp = enrollOwnKey(t, token, map[string]any{
		"new_public_key_pem": ecPublicKeyPEM(t, key2),
		"new_key_proof":      selfKeyProof(t, key2, wimse, nil),
	})
	_ = decode(t, resp)
	require.Equal(t, http.StatusForbidden, resp.StatusCode, "rotation without the current key's proof")

	resp = enrollOwnKey(t, token, map[string]any{
		"new_public_key_pem": ecPublicKeyPEM(t, key2),
		"new_key_proof":      selfKeyProof(t, key2, wimse, nil),
		"current_key_proof":  selfKeyProof(t, key1, wimse, key2),
	})
	body = decode(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode, "rotation: %v", body)

	resp = jwtBearerScope(t, buildAssertion(t, key2, wimse), "")
	_ = decode(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode, "jwt-bearer with the rotated key")
	resp = jwtBearerScope(t, buildAssertion(t, key1, wimse), "")
	_ = decode(t, resp)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "the replaced key no longer authenticates")
}

// TestSelfKeyEnrollment_RefusesDelegatedToken: an exchanged token is held by
// its current actor for a delegation chain. It cannot set that actor's key.
func TestSelfKeyEnrollment_RefusesDelegatedToken(t *testing.T) {
	orchToken, _ := mintOrchestratorToken(t, "self-key-orch")
	delegated := exchangeForSubAgent(t, orchToken, "self-key-sub")
	actor, _ := decodeJWTPayload(t, delegated)["act"].(map[string]any)
	actorWIMSE, _ := actor["sub"].(string)
	require.NotEmpty(t, actorWIMSE, "an rfc8693 exchanged token names its current actor in act")

	key := generateKey(t)
	resp := enrollOwnKey(t, delegated, map[string]any{
		"new_public_key_pem": ecPublicKeyPEM(t, key),
		"new_key_proof":      selfKeyProof(t, key, actorWIMSE, nil),
	})
	_ = decode(t, resp)
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
}
