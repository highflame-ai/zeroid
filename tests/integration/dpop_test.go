package integration_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildDPoPProof creates a valid DPoP proof JWT (RFC 9449) signed with privKey.
// method is the HTTP method (e.g. "POST") and htu is the full target URI.
func buildDPoPProof(t *testing.T, privKey *ecdsa.PrivateKey, method, htu, jti string) string {
	t.Helper()

	privJWK, err := jwk.Import[jwk.Key](privKey)
	require.NoError(t, err)

	pubJWK, err := jwk.Import[jwk.Key](&privKey.PublicKey)
	require.NoError(t, err)

	payloadBytes, err := json.Marshal(map[string]any{
		"htm": method,
		"htu": htu,
		"iat": time.Now().Unix(),
		"jti": jti,
	})
	require.NoError(t, err)

	hdrs := jws.NewHeaders()
	require.NoError(t, hdrs.Set("typ", "dpop+jwt"))
	require.NoError(t, hdrs.Set("jwk", pubJWK))

	signed, err := jws.Sign(payloadBytes,
		jws.WithKey(jwa.ES256(), privJWK, jws.WithProtectedHeaders(hdrs)),
	)
	require.NoError(t, err)
	return string(signed)
}

// dpopKeyThumbprint computes the base64url SHA-256 JWK thumbprint (RFC 7638) of an ECDSA public key.
func dpopKeyThumbprint(t *testing.T, pubKey *ecdsa.PublicKey) string {
	t.Helper()
	k, err := jwk.Import[jwk.Key](pubKey)
	require.NoError(t, err)
	tb, err := k.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(tb)
}

// TestDPoPClientCredentialsFlow verifies the full DPoP happy path:
// proof present → token_type "DPoP" → introspection surfaces cnf.jkt bound to the proof key.
func TestDPoPClientCredentialsFlow(t *testing.T) {
	agentID := uid("dpop-agent")
	registerIdentity(t, agentID, []string{"billing:read"})
	client := registerOAuthClient(t, agentID, []string{"billing:read"})

	dpopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// htu must match the URL the request actually reaches —
	// testServer.URL (httptest's loopback listener), not testIssuer (the
	// configured iss/baseURL value used only for JWT iss claims).
	proof := buildDPoPProof(t, dpopKey, http.MethodPost, testServer.URL+"/oauth2/token", uuid.New().String())

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"scope":         "billing:read",
	}, map[string]string{"DPoP": proof})
	require.Equal(t, http.StatusOK, resp.StatusCode)

	token := decode(t, resp)
	assert.Equal(t, "DPoP", token["token_type"], "token_type must be DPoP when proof is present")
	accessToken, _ := token["access_token"].(string)
	require.NotEmpty(t, accessToken)

	// Introspect: cnf.jkt must match the DPoP key thumbprint.
	result := introspect(t, accessToken)
	assert.Equal(t, true, result["active"], "introspected DPoP-bound token should be active")

	cnf, ok := result["cnf"].(map[string]any)
	require.True(t, ok, "cnf claim must be present in introspection for DPoP-bound token")
	jkt, _ := cnf["jkt"].(string)
	assert.Equal(t, dpopKeyThumbprint(t, &dpopKey.PublicKey), jkt, "cnf.jkt must match the DPoP proof key thumbprint")
}

// TestDPoPBearerFallback verifies that omitting the DPoP header preserves the
// existing Bearer-token behaviour: token_type is "Bearer" and cnf is absent.
func TestDPoPBearerFallback(t *testing.T) {
	agentID := uid("dpop-fallback-agent")
	registerIdentity(t, agentID, []string{"billing:read"})
	client := registerOAuthClient(t, agentID, []string{"billing:read"})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"scope":         "billing:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	token := decode(t, resp)
	assert.Equal(t, "Bearer", token["token_type"], "no DPoP header → token_type stays Bearer")

	accessToken, _ := token["access_token"].(string)
	require.NotEmpty(t, accessToken)
	result := introspect(t, accessToken)
	_, hasCnf := result["cnf"]
	assert.False(t, hasCnf, "Bearer tokens must not carry cnf in introspection")
}

// TestDPoPReplayRejected verifies that the second use of the same DPoP proof
// (same jti) is rejected by the JTI replay-prevention store.
func TestDPoPReplayRejected(t *testing.T) {
	agentID := uid("dpop-replay-agent")
	registerIdentity(t, agentID, []string{"billing:read"})
	client := registerOAuthClient(t, agentID, []string{"billing:read"})

	dpopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	jti := uuid.New().String()
	proof := buildDPoPProof(t, dpopKey, http.MethodPost, testServer.URL+"/oauth2/token", jti)

	body := map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"scope":         "billing:read",
	}

	resp1 := post(t, "/oauth2/token", body, map[string]string{"DPoP": proof})
	require.Equal(t, http.StatusOK, resp1.StatusCode, "first DPoP use must succeed")
	_ = resp1.Body.Close()

	resp2 := post(t, "/oauth2/token", body, map[string]string{"DPoP": proof})
	require.Equal(t, http.StatusBadRequest, resp2.StatusCode, "replay of same DPoP jti must be rejected")
	errBody := decode(t, resp2)
	assert.Equal(t, "invalid_dpop_proof", errBody["error"])
}

// TestDPoPRejectsHTMMismatch verifies that a proof whose htm claim doesn't match
// the request method is rejected.
func TestDPoPRejectsHTMMismatch(t *testing.T) {
	agentID := uid("dpop-htm-agent")
	registerIdentity(t, agentID, []string{"billing:read"})
	client := registerOAuthClient(t, agentID, []string{"billing:read"})

	dpopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	// Build a proof claiming GET, then send POST.
	proof := buildDPoPProof(t, dpopKey, http.MethodGet, testServer.URL+"/oauth2/token", uuid.New().String())

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"scope":         "billing:read",
	}, map[string]string{"DPoP": proof})
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "htm mismatch must be rejected")
	errBody := decode(t, resp)
	assert.Equal(t, "invalid_dpop_proof", errBody["error"])
}

// TestDPoPRejectsBadHTU verifies that a proof whose htu points at a different
// endpoint is rejected.
func TestDPoPRejectsBadHTU(t *testing.T) {
	agentID := uid("dpop-htu-agent")
	registerIdentity(t, agentID, []string{"billing:read"})
	client := registerOAuthClient(t, agentID, []string{"billing:read"})

	dpopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	proof := buildDPoPProof(t, dpopKey, http.MethodPost, "https://attacker.example/oauth2/token", uuid.New().String())

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     client.ClientID,
		"client_secret": client.ClientSecret,
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"scope":         "billing:read",
	}, map[string]string{"DPoP": proof})
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "htu mismatch must be rejected")
	errBody := decode(t, resp)
	assert.Equal(t, "invalid_dpop_proof", errBody["error"])
	// Pin the cause — if a future regression made a different check fire
	// (e.g. iat or jti), the test would still see invalid_dpop_proof and
	// silently lose its grip. The error_description carries the reason.
	desc, _ := errBody["error_description"].(string)
	assert.Contains(t, desc, "htu", "error_description must identify htu as the mismatch cause")
}
