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

	t.Run("an empty scope LIST is rejected (would silently neuter a profile)", func(t *testing.T) {
		// A config typo like `codeoid: []` must fail loud at boot, not ship an
		// audience that mints scopeless tokens.
		_, err := ResolveAudienceScopeProfiles(map[string][]string{"x": {}})
		require.Error(t, err)
		_, err = ResolveAudienceScopeProfiles(map[string][]string{audienceCodeoid: {}})
		require.Error(t, err, "overriding a default down to zero scopes must also fail")
	})
}

// TestDefaultAudienceProfilesAreWithinAllowlist pins the invariant that every
// built-in default profile grants at least one scope and only scopes the server
// recognizes — so a future default can't drift out of allowedProfileScopes (which
// would let a default grant a scope a deployer config is then rejected for).
func TestDefaultAudienceProfilesAreWithinAllowlist(t *testing.T) {
	for aud, scopes := range defaultAudienceScopeProfiles {
		assert.NotEmptyf(t, scopes, "default profile %q must grant at least one scope", aud)
		for _, sc := range scopes {
			assert.Truef(t, allowedProfileScopes[sc],
				"default profile %q scope %q must be in allowedProfileScopes", aud, sc)
		}
	}
}

// TestAudienceProfilesOrDefaultClones proves both the nil and non-nil paths return
// a deep copy, so a caller can never mutate the shared package-global defaults nor
// a config map it passed in and still holds a reference to.
func TestAudienceProfilesOrDefaultClones(t *testing.T) {
	t.Run("nil path clones defaults", func(t *testing.T) {
		got := audienceProfilesOrDefault(nil)
		got[audienceCodeoid][0] = "MUTATED"
		got["injected"] = []string{"x"}
		assert.NotEqual(t, "MUTATED", defaultAudienceScopeProfiles[audienceCodeoid][0],
			"mutating the returned map's slice must not corrupt the shared default")
		assert.NotContains(t, defaultAudienceScopeProfiles, "injected",
			"adding a key to the returned map must not corrupt the shared default")
	})

	t.Run("non-nil path clones the configured map", func(t *testing.T) {
		input := map[string][]string{"custom": {"session:read"}}
		got := audienceProfilesOrDefault(input)
		got["custom"][0] = "MUTATED"
		got["injected"] = []string{"x"}
		assert.Equal(t, "session:read", input["custom"][0],
			"mutating the returned map's slice must not corrupt the input config")
		assert.NotContains(t, input, "injected",
			"adding a key to the returned map must not corrupt the input config")
	})
}
