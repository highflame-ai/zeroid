package integration_test

import (
	"context"
	"testing"

	"github.com/highflame-ai/zeroid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFederatedCredentialExchange is the mint-level contract for the WIF broker
// path (ADR 0028 / CAP-IDN-023). Called directly on the Server (authn exposes it
// behind an internal endpoint, not the /oauth2/token grants), it mints a token
// whose:
//   - sub = the acting agent's WIMSE (the principal the provider matches);
//   - act.sub = the AUTHENTICATED broker name (delegation, not impersonation);
//   - aud = the free-form provider audience (NOT a scope profile);
//   - scopes = none (the assertion conveys zero ZeroID authority).
func TestFederatedCredentialExchange(t *testing.T) {
	const (
		agentWIMSE = "spiffe://highflame.io/ns/proj-test-001/agent-x"
		provider   = "https://api.anthropic.com"
	)
	trustedCtx := context.WithValue(context.Background(), trustedServiceCtxKey{}, "firehog")

	t.Run("mints a delegated, provider-audienced, scopeless assertion", func(t *testing.T) {
		tok, err := testZeroIDServer.FederatedCredentialExchange(trustedCtx, zeroid.FederatedExchangeRequest{
			AccountID:    testAccountID,
			ProjectID:    testProjectID,
			SubjectWIMSE: agentWIMSE,
			ExternalID:   "agent-x",
			Audience:     provider,
		})
		require.NoError(t, err)
		claims := decodeJWTPayload(t, tok.AccessToken)

		assert.Equal(t, agentWIMSE, claims["sub"], "sub is the acting agent, never the broker")
		assert.Equal(t, []string{provider}, audienceOf(t, claims), "aud is the free-form provider audience")

		act, ok := claims["act"].(map[string]any)
		require.True(t, ok, "act claim must be present (delegation)")
		assert.Equal(t, "firehog", act["sub"], "act.sub is the AUTHENTICATED broker, not caller-supplied")

		assert.Empty(t, scopesOf(t, claims), "the assertion carries NO ZeroID scopes")
		assert.Equal(t, "provider_federation", claims["token_use"],
			"token_use marks the assertion so the shared verifier rejects it for Highflame auth (audit round 1)")
		assert.Equal(t, "agent-x", claims["external_id"], "external_id recorded for audit correlation")
		assert.Equal(t, testIssuer, claims["iss"], "iss is the ZeroID issuer the provider trusts")
		assert.Equal(t, testAccountID, tok.AccountID)
		assert.Equal(t, testProjectID, tok.ProjectID)
		assert.LessOrEqual(t, tok.ExpiresIn, 900, "short-lived (<= default 900s)")
	})

	t.Run("actor is the authenticated service, not spoofable by the request", func(t *testing.T) {
		// A DIFFERENT trusted service name in the context must surface as act.sub;
		// the request carries no actor field, so the broker identity can only come
		// from the authenticated gate.
		otherCtx := context.WithValue(context.Background(), trustedServiceCtxKey{}, "some-other-service")
		tok, err := testZeroIDServer.FederatedCredentialExchange(otherCtx, zeroid.FederatedExchangeRequest{
			AccountID:    testAccountID,
			ProjectID:    testProjectID,
			SubjectWIMSE: agentWIMSE,
			Audience:     provider,
		})
		require.NoError(t, err)
		act := decodeJWTPayload(t, tok.AccessToken)["act"].(map[string]any)
		assert.Equal(t, "some-other-service", act["sub"])
	})

	t.Run("untrusted caller is refused (no mint)", func(t *testing.T) {
		_, err := testZeroIDServer.FederatedCredentialExchange(context.Background(), zeroid.FederatedExchangeRequest{
			AccountID:    testAccountID,
			ProjectID:    testProjectID,
			SubjectWIMSE: agentWIMSE,
			Audience:     provider,
		})
		require.Error(t, err, "no trusted-service context must fail closed")
	})

	t.Run("TTL is clamped into the federation window", func(t *testing.T) {
		tok, err := testZeroIDServer.FederatedCredentialExchange(trustedCtx, zeroid.FederatedExchangeRequest{
			AccountID:    testAccountID,
			ProjectID:    testProjectID,
			SubjectWIMSE: agentWIMSE,
			Audience:     provider,
			TTLSeconds:   100000, // absurd -> clamped to 3600
		})
		require.NoError(t, err)
		assert.LessOrEqual(t, tok.ExpiresIn, 3600, "TTL clamped to the 3600s ceiling")
	})
}
