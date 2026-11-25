package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// subjectPerson is the ladder the external-principal exchange matches user_id
// against. Each case is a token shape a caller may present.
func TestSubjectPerson(t *testing.T) {
	const agent = "spiffe://zeroid.test/acct/proj/agent/a"
	cases := []struct {
		name   string
		claims map[string]any
		want   string
	}{
		{"rfc8693 person token", map[string]any{"sub": "alice", "principal_type": "user"}, "alice"},
		{"rfc8693 person chain acted on by an agent", map[string]any{
			"sub": "alice", "principal_type": "user", "act": map[string]any{"sub": agent},
		}, "alice"},
		{"rfc8693 workload token names no person", map[string]any{
			"sub": agent, "principal_type": "workload", "user_id": "alice",
		}, ""},
		{"rfc8693 user principal with a workload sub", map[string]any{"sub": agent, "principal_type": "user"}, ""},
		{"legacy user_id wins", map[string]any{"sub": agent, "user_id": "alice"}, "alice"},
		{"legacy delegated act.sub", map[string]any{
			"sub": agent, "delegation_depth": 1, "act": map[string]any{"sub": "alice"},
		}, "alice"},
		{"legacy act.sub at depth 0 is a key's creator, not a person acting", map[string]any{
			"sub": agent, "act": map[string]any{"sub": "alice"},
		}, ""},
		{"legacy workload act.sub never qualifies", map[string]any{
			"sub": agent, "delegation_depth": 2, "act": map[string]any{"sub": "spiffe://zeroid.test/acct/proj/agent/b"},
		}, ""},
		{"legacy person sub", map[string]any{"sub": "alice"}, "alice"},
		{"legacy workload sub, nothing else", map[string]any{"sub": agent}, ""},
		{"legacy workload user_id falls through", map[string]any{"sub": "bob", "user_id": "SPIFFE://zeroid.test/x"}, "bob"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, subjectPerson(tokenWith(t, tc.claims)))
		})
	}
}

func TestIsWorkloadURI(t *testing.T) {
	for _, v := range []string{"spiffe://d/a/p/agent/x", "SPIFFE://d/a", " spiffe://d/a"} {
		assert.True(t, isWorkloadURI(v), v)
	}
	for _, v := range []string{"user_2abc", "alice@example.com", "https://idp/alice", ""} {
		assert.False(t, isWorkloadURI(v), v)
	}
}
