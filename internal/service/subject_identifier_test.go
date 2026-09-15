package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests for RFC 9493 subject identifiers on ID-JAG redemption (zeroid#265).

func TestResolveSubjectIdentifier(t *testing.T) {
	t.Parallel()

	t.Run("absent is not an error", func(t *testing.T) {
		// The ordinary case: most ID-JAGs carry a plain `sub`. Absence must be
		// distinguishable from failure, because the caller falls back on it.
		got, ok, err := resolveSubjectIdentifier(map[string]any{"sub": "alice"})
		require.NoError(t, err)
		assert.False(t, ok)
		assert.Empty(t, got)
	})

	t.Run("email", func(t *testing.T) {
		got, ok, err := resolveSubjectIdentifier(map[string]any{
			"sub_id": map[string]any{"format": "email", "email": "alice@example.com"},
		})
		require.NoError(t, err)
		require.True(t, ok)
		assert.Equal(t, "alice@example.com", got)
	})

	t.Run("opaque", func(t *testing.T) {
		got, ok, err := resolveSubjectIdentifier(map[string]any{
			"sub_id": map[string]any{"format": "opaque", "id": "5be6d4a1"},
		})
		require.NoError(t, err)
		require.True(t, ok)
		assert.Equal(t, "5be6d4a1", got)
	})

	t.Run("iss_sub keeps the issuer, so subjects cannot collide across IdPs", func(t *testing.T) {
		// The case that decides whether this helper is worth having. `sub` is
		// unique only WITHIN an issuer — rendering it alone would merge subject
		// "1001" at one IdP with subject "1001" at another onto one principal,
		// and user_id is what Cedar policy matches on.
		a, ok, err := resolveSubjectIdentifier(map[string]any{
			"sub_id": map[string]any{"format": "iss_sub", "iss": "https://idp-a.example", "sub": "1001"},
		})
		require.NoError(t, err)
		require.True(t, ok)

		b, ok, err := resolveSubjectIdentifier(map[string]any{
			"sub_id": map[string]any{"format": "iss_sub", "iss": "https://idp-b.example", "sub": "1001"},
		})
		require.NoError(t, err)
		require.True(t, ok)

		assert.NotEqual(t, a, b, "the same sub at two issuers must NOT resolve to one principal")
		assert.Contains(t, a, "https://idp-a.example")
		assert.Contains(t, a, "1001")
	})

	// A present-but-broken sub_id is an ERROR, never an absence. Treating it as
	// absent would fall through to whatever other claim is available, which is
	// how an assertion ends up authorising someone it was not written for.
	for name, claim := range map[string]any{
		"not an object":           "alice@example.com",
		"missing format":          map[string]any{"email": "alice@example.com"},
		"empty format":            map[string]any{"format": "   ", "email": "a@b.c"},
		"unknown format":          map[string]any{"format": "phone_number", "phone_number": "+15551234"},
		"email without email":     map[string]any{"format": "email"},
		"email with empty member": map[string]any{"format": "email", "email": ""},
		"opaque without id":       map[string]any{"format": "opaque"},
		"iss_sub without iss":     map[string]any{"format": "iss_sub", "sub": "1001"},
		"iss_sub without sub":     map[string]any{"format": "iss_sub", "iss": "https://idp.example"},
		"non-string member":       map[string]any{"format": "email", "email": 42},
		"aliases is refused by design": map[string]any{
			"format":  "aliases",
			"aliases": []any{map[string]any{"format": "email", "email": "a@b.c"}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, ok, err := resolveSubjectIdentifier(map[string]any{"sub_id": claim})
			require.Error(t, err, "a malformed sub_id must fail, not read as absent")
			assert.False(t, ok)
		})
	}
}

func TestSubjectIdentifierConflicts(t *testing.T) {
	t.Parallel()

	assert.True(t, subjectIdentifierConflicts("alice", "bob"),
		"two different principals in one assertion must be refused, not ranked")
	assert.False(t, subjectIdentifierConflicts("alice", "alice"))

	// Only one side present is not a conflict — it is the ordinary case for an
	// assertion carrying just one of the two.
	assert.False(t, subjectIdentifierConflicts("", "alice"))
	assert.False(t, subjectIdentifierConflicts("alice", ""))

	// Comparison is EXACT on purpose. Case folding, email normalisation, or
	// treating an iss_sub composite as "containing" the plain sub would each be
	// a rule about when two different strings may be treated as one person —
	// precisely the judgement this refuses to make on an IdP's behalf.
	assert.True(t, subjectIdentifierConflicts("Alice@Example.com", "alice@example.com"),
		"near-matches are conflicts: deciding they are the same person is not ours to do")
	assert.True(t, subjectIdentifierConflicts("1001", "https://idp.example#1001"))
}
