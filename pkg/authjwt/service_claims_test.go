package authjwt

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The accessors a receiver uses to identify a calling service: the token's
// client, the current actor's client, and the reserved tenant and user
// claims. Each reads exactly one claim.
func TestClaims_ServiceTokenAccessors(t *testing.T) {
	c := claimsFrom(t, map[string]any{
		"sub":                  "alice",
		"principal_type":       "user",
		"client_id":            "top-client",
		"tenant_source":        "asserted",
		"resolved_user_id":     "alice",
		"resolved_user_source": "subject",
		"act": map[string]any{
			"sub":       "spiffe://zeroid.test/platform/p/service/gw",
			"client_id": "gw",
			"act": map[string]any{
				"sub":       "spiffe://zeroid.test/a/p/agent/x",
				"client_id": "nested-must-not-be-read",
			},
		},
	})
	assert.Equal(t, "top-client", c.ClientID())
	assert.Equal(t, "gw", c.ActorClientID())
	assert.Equal(t, "asserted", c.TenantSource())
	assert.Equal(t, "alice", c.ResolvedUserID())
	assert.Equal(t, "subject", c.ResolvedUserSource())

	// Only the outermost act carries client_id: a prior actor never reads as
	// an authenticated client.
	require.NotNil(t, c.ActorClaims.Actor)
	assert.Empty(t, c.ActorClaims.Actor.ClientID)

	// The accessors are additive: client_id stays readable through Custom for
	// consumers that already read it there.
	assert.Equal(t, "top-client", c.GetCustomString("client_id"))
}

func TestClaims_ServiceTokenAccessorsEmptyWhenAbsent(t *testing.T) {
	c := claimsFrom(t, map[string]any{"sub": "spiffe://zeroid.test/a/p/agent/x"})
	assert.Empty(t, c.ClientID())
	assert.Empty(t, c.ActorClientID(), "no act, no actor client")
	assert.Empty(t, c.TenantSource())
	assert.Empty(t, c.ResolvedUserID())
	assert.Empty(t, c.ResolvedUserSource())
}

// A claim of the wrong type reads as absent rather than panicking or being
// stringified: a receiver that requires the value then refuses.
func TestClaims_ServiceTokenAccessorsWrongType(t *testing.T) {
	c := claimsFrom(t, map[string]any{
		"sub":              "x",
		"tenant_source":    []string{"asserted"},
		"resolved_user_id": 42,
		"act":              map[string]any{"sub": "y", "client_id": 7},
	})
	assert.Empty(t, c.TenantSource())
	assert.Empty(t, c.ResolvedUserID())
	assert.Empty(t, c.ActorClientID())
}

func TestClaims_RequireResource(t *testing.T) {
	c := claimsFrom(t, map[string]any{
		"sub":      "x",
		"aud":      []string{"urn:example:svc:b"},
		"resource": []string{"urn:example:svc:a", "urn:example:svc:c"},
	})
	assert.NoError(t, c.RequireResource("urn:example:svc:a"))
	assert.NoError(t, c.RequireResource("urn:example:svc:c"))

	err := c.RequireResource("urn:example:svc:b")
	assert.True(t, errors.Is(err, ErrResourceMismatch), "aud alone is not a resource binding")
	assert.ErrorIs(t, c.RequireResource(""), ErrResourceMismatch, "an empty id never matches")

	unbound := claimsFrom(t, map[string]any{"sub": "x", "aud": []string{"urn:example:svc:a"}})
	assert.ErrorIs(t, unbound.RequireResource("urn:example:svc:a"), ErrResourceMismatch,
		"a token with no resource claim is not bound to anything")
}
