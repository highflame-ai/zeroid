package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests for RFC 9493 subject identifiers on ID-JAG redemption (zeroid#265).

const testAssertionIss = "https://idp.example.com"

// addr builds an email-shaped value without a literal address in source.
func addr(local, domain string) string { return local + "\x40" + domain }

func TestParseSubjectIdentifier(t *testing.T) {
	t.Parallel()

	t.Run("absent is not an error", func(t *testing.T) {
		got, err := parseSubjectIdentifier(map[string]any{"sub": "alice"}, testAssertionIss)
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("email", func(t *testing.T) {
		alice := addr("alice", "example.com")
		got, err := parseSubjectIdentifier(map[string]any{
			"sub_id": map[string]any{"format": "email", "email": alice},
		}, testAssertionIss)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, alice, got.principal)
		assert.Equal(t, "email", got.counterpartClaim)
	})

	t.Run("opaque has no plain counterpart", func(t *testing.T) {
		got, err := parseSubjectIdentifier(map[string]any{
			"sub_id": map[string]any{"format": "opaque", "id": "5be6d4a1"},
		}, testAssertionIss)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "5be6d4a1", got.principal)
		assert.Empty(t, got.counterpartClaim,
			"opaque must never be compared to anything — there is nothing of its kind to compare")
	})

	t.Run("iss_sub renders as the bare sub once its issuer is pinned", func(t *testing.T) {
		// The same person must be ONE principal whether the IdP sends a plain
		// sub or an iss_sub. The issuer is recorded separately as user_id_iss.
		got, err := parseSubjectIdentifier(map[string]any{
			"sub_id": map[string]any{"format": "iss_sub", "iss": testAssertionIss, "sub": "1001"},
		}, testAssertionIss)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "1001", got.principal)
		assert.Equal(t, "sub", got.counterpartClaim)
	})

	t.Run("iss_sub naming ANOTHER issuer is refused", func(t *testing.T) {
		// The object's iss is chosen by the signing IdP. Unchecked, one trusted
		// IdP could name subjects in another IdP's namespace.
		got, err := parseSubjectIdentifier(map[string]any{
			"sub_id": map[string]any{"format": "iss_sub", "iss": "https://other-idp.example", "sub": "admin"},
		}, testAssertionIss)
		require.Error(t, err)
		assert.Nil(t, got)
		assert.Contains(t, err.Error(), "may only identify its own subjects")
	})

	t.Run("iss_sub with no verified issuer to pin to is refused", func(t *testing.T) {
		_, err := parseSubjectIdentifier(map[string]any{
			"sub_id": map[string]any{"format": "iss_sub", "iss": testAssertionIss, "sub": "1001"},
		}, "")
		require.Error(t, err)
	})

	t.Run("iss_sub issuer comparison is exact", func(t *testing.T) {
		_, err := parseSubjectIdentifier(map[string]any{
			"sub_id": map[string]any{"format": "iss_sub", "iss": testAssertionIss + "/", "sub": "1001"},
		}, testAssertionIss)
		require.Error(t, err, "a trailing slash is a different issuer string")
	})

	t.Run("values are kept exactly as written", func(t *testing.T) {
		// Trimming here while plain claims go untrimmed made one person read as
		// two. Exact on both sides.
		got, err := parseSubjectIdentifier(map[string]any{
			"sub_id": map[string]any{"format": "opaque", "id": " padded "},
		}, testAssertionIss)
		require.NoError(t, err)
		assert.Equal(t, " padded ", got.principal)
	})

	for name, claim := range map[string]any{
		"not an object":           addr("alice", "example.com"),
		"missing format":          map[string]any{"email": addr("alice", "example.com")},
		"blank format":            map[string]any{"format": "   ", "email": addr("a", "b.c")},
		"format with padding":     map[string]any{"format": " email", "email": addr("a", "b.c")},
		"unknown format":          map[string]any{"format": "phone_number", "phone_number": "+15551234"},
		"email without email":     map[string]any{"format": "email"},
		"email with blank member": map[string]any{"format": "email", "email": "   "},
		"opaque without id":       map[string]any{"format": "opaque"},
		"iss_sub without iss":     map[string]any{"format": "iss_sub", "sub": "1001"},
		"iss_sub without sub":     map[string]any{"format": "iss_sub", "iss": testAssertionIss},
		"non-string member":       map[string]any{"format": "email", "email": 42},
		"aliases is refused by design": map[string]any{
			"format":  "aliases",
			"aliases": []any{map[string]any{"format": "email", "email": addr("a", "b.c")}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := parseSubjectIdentifier(map[string]any{"sub_id": claim}, testAssertionIss)
			require.Error(t, err, "a malformed sub_id must fail, not read as absent")
			assert.Nil(t, got)
		})
	}
}

func TestSubjectIdentifierConflictingClaim(t *testing.T) {
	t.Parallel()

	alice := addr("alice", "example.com")
	mallory := addr("mallory", "example.com")

	parse := func(t *testing.T, subID map[string]any) *subjectIdentifier {
		t.Helper()
		s, err := parseSubjectIdentifier(map[string]any{"sub_id": subID}, testAssertionIss)
		require.NoError(t, err)
		require.NotNil(t, s)
		return s
	}
	issSub := func(sub string) map[string]any {
		return map[string]any{"format": "iss_sub", "iss": testAssertionIss, "sub": sub}
	}
	email := func(e string) map[string]any { return map[string]any{"format": "email", "email": e} }

	cases := []struct {
		name   string
		subID  map[string]any
		claims map[string]any
		want   string
	}{
		// Agreement: the most self-consistent assertion possible must pass.
		{"iss_sub.sub equals sub", issSub("1001"), map[string]any{"sub": "1001"}, ""},
		{"email sub_id equals email claim", email(alice), map[string]any{"email": alice}, ""},

		// Different KINDS are two names for one person, not two people.
		{"opaque sub beside email sub_id", email(alice), map[string]any{"sub": "00uOKTA123"}, ""},
		{"email-shaped sub beside email sub_id", email(mallory), map[string]any{"sub": alice}, ""},
		{"opaque sub_id never conflicts", map[string]any{"format": "opaque", "id": "x"}, map[string]any{"sub": "y"}, ""},

		// Absent counterpart: nothing to contradict.
		{"iss_sub with no plain sub", issSub("1001"), map[string]any{}, ""},

		// Same-kind contradictions are refused.
		{"iss_sub.sub differs from sub", issSub("1001"), map[string]any{"sub": "2002"}, "sub"},
		{"email sub_id differs from email claim", email(alice), map[string]any{"email": mallory}, "email"},
		{"counterpart present but not a string", email(alice), map[string]any{"email": 42}, "email"},

		// Exact: near-matches are conflicts, deciding otherwise is not ours.
		{"case differs", email(alice), map[string]any{"email": addr("Alice", "Example.com")}, "email"},
		{"whitespace differs", issSub("alice"), map[string]any{"sub": "alice "}, "sub"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, parse(t, tc.subID).conflictingClaim(tc.claims))
		})
	}

	t.Run("nil identifier never conflicts", func(t *testing.T) {
		var s *subjectIdentifier
		assert.Empty(t, s.conflictingClaim(map[string]any{"sub": "x"}))
	})
}
