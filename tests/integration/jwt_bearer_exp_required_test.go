// Regression guards for the RFC 7523 §3 (4) exp-required fix.
//
// jwx's `WithValidate(true)` honors `exp` when present but does not require
// it. The OAuth service now supplements with an explicit check on both the
// jwt_bearer assertion and the token_exchange actor_token; these tests
// ensure that supplement stays in place across future refactors.

package integration_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// signAssertionNoExp builds a jwt-bearer assertion with everything RFC 7523
// requires EXCEPT the exp claim. Used to prove the server rejects it.
func signAssertionNoExp(t *testing.T, key *ecdsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	b := jwt.NewBuilder()
	for k, v := range claims {
		b = b.Claim(k, v)
	}
	tok, err := b.Build()
	require.NoError(t, err)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), key))
	require.NoError(t, err)
	return string(signed)
}

func TestJwtBearer_ExpClaimRequired(t *testing.T) {
	// RFC 7523 §3 (4): "The JWT MUST contain an 'exp' (expiration) claim
	//   that limits the time window during which the JWT can be used."
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	agentID := uid("exp-required-jwt-bearer")
	identity := registerIdentity(t, agentID, []string{"data:read"}, ecPublicKeyPEM(t, key))

	now := time.Now()
	bad := signAssertionNoExp(t, key, map[string]any{
		"iss": identity.WIMSEURI,
		"sub": identity.WIMSEURI,
		"aud": testIssuer,
		"iat": now.Unix(),
		// exp deliberately omitted
	})

	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
		"subject":    bad,
		"scope":      "data:read",
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"jwt-bearer assertion without exp MUST be rejected")
	body := decode(t, resp)
	assert.Equal(t, "invalid_grant", body["error"])
	desc, _ := body["error_description"].(string)
	assert.Contains(t, desc, "exp",
		"error_description should name the missing claim — proves the new check fired, not some other validator")
}

func TestTokenExchange_ActorTokenExpClaimRequired(t *testing.T) {
	// RFC 7523 §3 (4) applies to the actor_token via RFC 8693 §1.2 —
	// the actor_token is a JWT-bearer-style assertion and inherits the same
	// MUST-have-exp contract.
	orchID := uid("exp-required-tx-orch")
	registerIdentity(t, orchID, []string{"data:read"})
	orchClient := registerOAuthClient(t, orchID, []string{"data:read"})
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     orchClient.ClientID,
		"client_secret": orchClient.ClientSecret,
		"account_id":    testAccountID,
		"project_id":    testProjectID,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	orchToken, _ := decode(t, resp)["access_token"].(string)

	subKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	subID := uid("exp-required-tx-sub")
	subIdentity := registerIdentity(t, subID, []string{"data:read"}, ecPublicKeyPEM(t, subKey))

	now := time.Now()
	actorNoExp := signAssertionNoExp(t, subKey, map[string]any{
		"iss": subIdentity.WIMSEURI,
		"sub": subIdentity.WIMSEURI,
		"aud": testIssuer,
		"iat": now.Unix(),
		// exp deliberately omitted
	})

	exch := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": orchToken,
		"actor_token":   actorNoExp,
		"scope":         "data:read",
	}, nil)
	require.Equal(t, http.StatusBadRequest, exch.StatusCode,
		"actor_token without exp MUST be rejected")
	body := decode(t, exch)
	assert.Equal(t, "invalid_grant", body["error"])
	desc, _ := body["error_description"].(string)
	assert.Contains(t, desc, "exp",
		"error_description should name the missing claim for token-exchange too")
}
