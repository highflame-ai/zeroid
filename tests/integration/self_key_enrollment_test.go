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
// its current actor for a delegation chain, so it cannot set that actor's key
// even with valid proofs. The same request on the actor's own jwt-bearer token
// succeeds, so the 403 comes from the token check and not from the proofs.
func TestSelfKeyEnrollment_RefusesDelegatedToken(t *testing.T) {
	orchToken, _ := mintOrchestratorToken(t, "self-key-orch")
	subKey := generateKey(t)
	sub := registerIdentity(t, uid("self-key-sub"), []string{"data:read"}, ecPublicKeyPEM(t, subKey))
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": orchToken,
		"actor_token":   buildAssertion(t, subKey, sub.WIMSEURI),
		"scope":         "data:read",
	}, nil)
	body := decode(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode, "token exchange: %v", body)
	delegated, _ := body["access_token"].(string)

	newKey := generateKey(t)
	rotation := func() map[string]any {
		return map[string]any{
			"new_public_key_pem": ecPublicKeyPEM(t, newKey),
			"new_key_proof":      selfKeyProof(t, newKey, sub.WIMSEURI, nil),
			"current_key_proof":  selfKeyProof(t, subKey, sub.WIMSEURI, newKey),
		}
	}

	resp = enrollOwnKey(t, delegated, rotation())
	body = decode(t, resp)
	require.Equal(t, http.StatusForbidden, resp.StatusCode, "%v", body)
	require.Contains(t, body["detail"], "agent's own token")

	resp = jwtBearerScope(t, buildAssertion(t, subKey, sub.WIMSEURI), "")
	body = decode(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", body)
	own, _ := body["access_token"].(string)
	resp = enrollOwnKey(t, own, rotation())
	body = decode(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode, "the same rotation on the agent's own token: %v", body)
}

// TestSelfKeyEnrollment_RefusesProofToken: a proof token is signed by the
// issuer for the agent, but it is handed to the third party named in its
// audience. That party must not be able to enroll its own key on an agent
// that has none.
func TestSelfKeyEnrollment_RefusesProofToken(t *testing.T) {
	agent := registerAgent(t, uid("self-key-wpt"))
	resp := post(t, "/oauth2/token", map[string]any{"grant_type": "api_key", "api_key": agent.APIKey}, nil)
	body := decode(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", body)
	agentToken, _ := body["access_token"].(string)

	resp = post(t, adminPath("/proof/generate"), map[string]any{
		"identity_id": agent.AgentID,
		"audience":    "https://relying-party.example.com",
		"nonce":       uid("self-key-nonce"),
	}, map[string]string{"Authorization": "Bearer " + agentToken})
	body = decode(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode, "proof generation: %v", body)
	proofToken, _ := body["proof_token"].(string)
	wimse, _ := decodeJWTPayload(t, proofToken)["sub"].(string)
	require.NotEmpty(t, wimse)

	key := generateKey(t)
	resp = enrollOwnKey(t, proofToken, map[string]any{
		"new_public_key_pem": ecPublicKeyPEM(t, key),
		"new_key_proof":      selfKeyProof(t, key, wimse, nil),
	})
	body = decode(t, resp)
	require.Equal(t, http.StatusForbidden, resp.StatusCode, "%v", body)

	resp = jwtBearerScope(t, buildAssertion(t, key, wimse), "")
	_ = decode(t, resp)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "no key was enrolled")
}

// TestSelfKeyEnrollment_RefusesRevokedToken: a revoked token must not bind a
// key that would outlive the revocation.
func TestSelfKeyEnrollment_RefusesRevokedToken(t *testing.T) {
	token := issueAPIKeyToken(t, uid("self-key-revoked"))
	wimse, _ := decodeJWTPayload(t, token)["sub"].(string)
	revoke := post(t, "/oauth2/token/revoke", map[string]string{"token": token}, nil)
	require.Equal(t, http.StatusOK, revoke.StatusCode)
	_ = revoke.Body.Close()

	key := generateKey(t)
	resp := enrollOwnKey(t, token, map[string]any{
		"new_public_key_pem": ecPublicKeyPEM(t, key),
		"new_key_proof":      selfKeyProof(t, key, wimse, nil),
	})
	_ = decode(t, resp)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestSelfKeyEnrollment_RefusesAudienceBoundToken: a token bound to another
// audience (here an RFC 8707 resource) is held by that audience too, so it
// cannot enroll a key on an agent that has none. A gateway-bound token is the
// same case.
func TestSelfKeyEnrollment_RefusesAudienceBoundToken(t *testing.T) {
	agent := registerAgent(t, uid("self-key-aud"))
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type": "api_key",
		"api_key":    agent.APIKey,
		"resource":   "https://mcp.example.com",
	}, nil)
	body := decode(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", body)
	bound, _ := body["access_token"].(string)
	claims := decodeJWTPayload(t, bound)
	require.NotContains(t, claims["aud"], testIssuer, "precondition: the token is bound to the resource, not the issuer")
	wimse, _ := claims["sub"].(string)

	key := generateKey(t)
	resp = enrollOwnKey(t, bound, map[string]any{
		"new_public_key_pem": ecPublicKeyPEM(t, key),
		"new_key_proof":      selfKeyProof(t, key, wimse, nil),
	})
	body = decode(t, resp)
	require.Equal(t, http.StatusForbidden, resp.StatusCode, "%v", body)
	require.Contains(t, body["detail"], "audience")
}
