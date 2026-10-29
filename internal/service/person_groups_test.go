package service

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwt"
)

func TestExtractPersonGroups(t *testing.T) {
	many := func(n int) []any {
		out := make([]any, n)
		for i := range out {
			out[i] = fmt.Sprintf("g%03d", i)
		}
		return out
	}
	cases := []struct {
		name   string
		claims map[string]any
		claim  string
		want   []string
	}{
		{name: "array of strings", claims: map[string]any{"groups": []any{"eng", "oncall"}}, claim: "groups", want: []string{"eng", "oncall"}},
		{name: "typed string slice", claims: map[string]any{"groups": []string{"eng"}}, claim: "groups", want: []string{"eng"}},
		{name: "single string is one group, not split", claims: map[string]any{"groups": "Domain Users"}, claim: "groups", want: []string{"Domain Users"}},
		{name: "renamed claim", claims: map[string]any{"member_of": []any{"eng"}, "groups": []any{"other"}}, claim: "member_of", want: []string{"eng"}},
		{name: "unmapped", claims: map[string]any{"groups": []any{"eng"}}, claim: ""},
		{name: "absent", claims: map[string]any{"sub": "alice"}, claim: "groups"},
		{name: "empty array", claims: map[string]any{"groups": []any{}}, claim: "groups"},
		{name: "empty string", claims: map[string]any{"groups": ""}, claim: "groups"},
		{name: "number is malformed", claims: map[string]any{"groups": 42.0}, claim: "groups"},
		{name: "object is malformed", claims: map[string]any{"groups": map[string]any{"eng": true}}, claim: "groups"},
		{name: "bool is malformed", claims: map[string]any{"groups": true}, claim: "groups"},
		{name: "non-string entries are skipped", claims: map[string]any{"groups": []any{"eng", 7.0, nil, map[string]any{}, "ops"}}, claim: "groups", want: []string{"eng", "ops"}},
		{name: "only non-string entries", claims: map[string]any{"groups": []any{1.0, false}}, claim: "groups"},
		{name: "control and format characters are skipped", claims: map[string]any{"groups": []any{"eng\x1b[31m", "ad‮min", "ops"}}, claim: "groups", want: []string{"ops"}},
		{name: "duplicates collapse in order", claims: map[string]any{"groups": []any{"b", "a", "b"}}, claim: "groups", want: []string{"b", "a"}},
		{name: "at the count limit", claims: map[string]any{"groups": many(MaxPersonGroups)}, claim: "groups", want: func() []string {
			out := make([]string, MaxPersonGroups)
			for i := range out {
				out[i] = fmt.Sprintf("g%03d", i)
			}
			return out
		}()},
		{name: "above the count limit drops the claim", claims: map[string]any{"groups": many(MaxPersonGroups + 1)}, claim: "groups"},
		{name: "a group name above the length limit drops the claim", claims: map[string]any{"groups": []any{"eng", strings.Repeat("x", MaxPersonGroupLength+1)}}, claim: "groups"},
		{name: "a group name at the length limit", claims: map[string]any{"groups": []any{strings.Repeat("x", MaxPersonGroupLength)}}, claim: "groups", want: []string{strings.Repeat("x", MaxPersonGroupLength)}},
		{name: "above the total size drops the claim", claims: map[string]any{"groups": func() []any {
			out := make([]any, MaxPersonGroupsBytes/MaxPersonGroupLength+1)
			for i := range out {
				out[i] = fmt.Sprintf("%03d", i) + strings.Repeat("x", MaxPersonGroupLength-3)
			}
			return out
		}()}, claim: "groups"},
		{name: "entra overage (distributed claim) is no groups", claims: map[string]any{
			"_claim_names":   map[string]any{"groups": "src1"},
			"_claim_sources": map[string]any{"src1": map[string]any{"endpoint": "https://graph.microsoft.com/v1.0/users/x/getMemberObjects"}},
		}, claim: "groups"},
		{name: "entra hasgroups is no groups", claims: map[string]any{"hasgroups": true}, claim: "groups"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractPersonGroups(tc.claims, tc.claim, "https://idp.example")
			if !slices.Equal(got, tc.want) {
				t.Fatalf("groups = %#v, want %#v", got, tc.want)
			}
			if tc.want == nil && got != nil {
				t.Fatalf("groups = %#v, want nil (no claim on the token)", got)
			}
		})
	}
}

func TestParentGroups(t *testing.T) {
	tok, err := jwt.NewBuilder().Subject("alice").IssuedAt(time.Now()).Build()
	if err != nil {
		t.Fatal(err)
	}
	if got := parentGroups(tok); got != nil {
		t.Fatalf("a parent without groups yields %v", got)
	}
	if err := tok.Set("groups", []any{"eng", 3.0, "ops"}); err != nil {
		t.Fatal(err)
	}
	if got := parentGroups(tok); !slices.Equal(got, []string{"eng", "ops"}) {
		t.Fatalf("groups = %v", got)
	}
	if err := tok.Set("groups", []string{"eng"}); err != nil {
		t.Fatal(err)
	}
	if got := parentGroups(tok); !slices.Equal(got, []string{"eng"}) {
		t.Fatalf("groups = %v", got)
	}
}

// TestGroupsIsReserved: only ZeroID, from the IdP token or the verified
// parent, may set `groups`; additional_claims never can.
func TestGroupsIsReserved(t *testing.T) {
	if !reservedClaims["groups"] {
		t.Fatal("groups must be a reserved claim")
	}
}
