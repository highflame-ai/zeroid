package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResolveAudienceScopeProfiles covers the config-driven mechanism: a new
// audience is added via CONFIG (no code release), config merges over the built-in
// defaults, and every granted scope is bounded by the server's allowlist so a
// config entry can never invent authority (fail closed).
func TestResolveAudienceScopeProfiles(t *testing.T) {
	t.Run("nil config yields the built-in defaults", func(t *testing.T) {
		out, err := ResolveAudienceScopeProfiles(nil)
		require.NoError(t, err)
		assert.Contains(t, out, audienceCodeoid)
		assert.Equal(t, []string{"nhi:manage"}, out[audienceAgentSandbox],
			"agent-sandbox is the minimal mint profile")
	})

	t.Run("config adds a NEW audience without a code change; defaults survive", func(t *testing.T) {
		out, err := ResolveAudienceScopeProfiles(map[string][]string{
			"my-new-audience": {"session:read", "nhi:manage"},
		})
		require.NoError(t, err)
		assert.Contains(t, out, audienceCodeoid, "built-in defaults survive the merge")
		assert.Contains(t, out, audienceAgentSandbox)
		assert.ElementsMatch(t, []string{"session:read", "nhi:manage"}, out["my-new-audience"])
	})

	t.Run("config can override a default audience's scopes", func(t *testing.T) {
		out, err := ResolveAudienceScopeProfiles(map[string][]string{
			audienceCodeoid: {"session:read"},
		})
		require.NoError(t, err)
		assert.Equal(t, []string{"session:read"}, out[audienceCodeoid])
	})

	t.Run("a scope outside the allowlist is rejected (fail closed)", func(t *testing.T) {
		_, err := ResolveAudienceScopeProfiles(map[string][]string{"bad": {"admin:*"}})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "admin:*",
			"config can never grant a scope the server doesn't recognize")
	})

	t.Run("an empty audience name is rejected", func(t *testing.T) {
		_, err := ResolveAudienceScopeProfiles(map[string][]string{"  ": {"nhi:manage"}})
		require.Error(t, err)
	})
}
