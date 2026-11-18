package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/highflame-ai/zeroid/domain"
)

func policy(name string, allowed, userGrant []string) *domain.CredentialPolicy {
	return &domain.CredentialPolicy{Name: name, AllowedScopes: allowed, UserGrantScopes: userGrant}
}

// TestCheckChildCeilings pins the rule that a child identity can hold no scope
// its parent cannot. Each case names the layers the request supplied
// (rowNamed, policyNamed); the others were copied from the parent.
func TestCheckChildCeilings(t *testing.T) {
	t.Parallel()

	open := policy("open", nil, nil)
	ab := policy("ab", []string{"a", "b"}, nil)
	onlyA := policy("only-a", []string{"a"}, nil)
	withD := policy("with-d", []string{"a", "d"}, nil)
	forPersonA := policy("for-person-a", []string{"a", "b"}, []string{"a"})
	forPersonC := policy("for-person-c", []string{"a"}, []string{"c"})

	tests := []struct {
		name        string
		parent      ceilingLayers
		child       ceilingLayers
		rowNamed    bool
		policyNamed bool
		// wantErr is a substring of the refusal, "" when the child is allowed.
		wantErr string
	}{
		{
			name:     "an open parent allows any child",
			parent:   ceilingLayers{policy: open},
			child:    ceilingLayers{rowScopes: []string{"x", "y"}, policy: open},
			rowNamed: true,
		},
		{
			name:   "an open parent allows an open child",
			parent: ceilingLayers{policy: open},
			child:  ceilingLayers{policy: open},
		},
		{
			name:   "a child that copied both layers equals its parent",
			parent: ceilingLayers{rowScopes: []string{"a", "b"}, policy: open},
			child:  ceilingLayers{rowScopes: []string{"a", "b"}, policy: open},
		},
		{
			name:     "named allowed_scopes within the parent",
			parent:   ceilingLayers{rowScopes: []string{"a", "b"}, policy: open},
			child:    ceilingLayers{rowScopes: []string{"a"}, policy: open},
			rowNamed: true,
		},
		{
			name:     "named allowed_scopes outside the parent names the scope",
			parent:   ceilingLayers{rowScopes: []string{"a", "b"}, policy: open},
			child:    ceilingLayers{rowScopes: []string{"a", "c"}, policy: open},
			rowNamed: true,
			wantErr:  `allowed_scopes lists "c"`,
		},
		{
			name:     "named allowed_scopes is checked against the parent's policy too",
			parent:   ceilingLayers{policy: onlyA},
			child:    ceilingLayers{rowScopes: []string{"a", "b"}, policy: onlyA},
			rowNamed: true,
			wantErr:  `allowed_scopes lists "b"`,
		},
		{
			name:        "a named policy within the parent",
			parent:      ceilingLayers{rowScopes: []string{"a", "b"}, policy: open},
			child:       ceilingLayers{rowScopes: []string{"a", "b"}, policy: onlyA},
			policyNamed: true,
		},
		{
			name:        "a named policy outside the parent names the scope",
			parent:      ceilingLayers{policy: ab},
			child:       ceilingLayers{policy: withD},
			policyNamed: true,
			wantErr:     `credential policy "with-d" lists "d"`,
		},
		{
			name:        "a named policy with no ceiling is refused under a restricted parent",
			parent:      ceilingLayers{rowScopes: []string{"a"}, policy: open},
			child:       ceilingLayers{rowScopes: []string{"a"}, policy: open},
			policyNamed: true,
			wantErr:     `credential policy "open" places no scope ceiling`,
		},
		{
			name:        "a named policy with no ceiling is allowed under an open parent",
			parent:      ceilingLayers{policy: open},
			child:       ceilingLayers{policy: open},
			policyNamed: true,
		},
		{
			// The escape this rule exists to stop: a restricted parent, a child
			// on a policy with no ceiling, and nothing else restricting it.
			name:     "a child left open under a restricted parent is refused",
			parent:   ceilingLayers{rowScopes: []string{"a"}, policy: open},
			child:    ceilingLayers{rowScopes: []string{}, policy: open},
			rowNamed: true,
			wantErr:  "would have no scope ceiling",
		},
		{
			// The parent's own policy lists b, but its allowed_scopes removes
			// it. Copying that policy is fine while the child's allowed_scopes
			// removes b too; clearing allowed_scopes would expose it.
			name:     "a copied policy wider than the parent is caught through the intersection",
			parent:   ceilingLayers{rowScopes: []string{"a"}, policy: ab},
			child:    ceilingLayers{rowScopes: []string{}, policy: ab},
			rowNamed: true,
			wantErr:  `the identity could hold "b"`,
		},
		{
			name:   "a copied policy wider than the parent is fine while allowed_scopes narrows it",
			parent: ceilingLayers{rowScopes: []string{"a"}, policy: ab},
			child:  ceilingLayers{rowScopes: []string{"a"}, policy: ab},
		},
		{
			name:        "named user_grant_scopes outside what the parent may hold for a person",
			parent:      ceilingLayers{policy: forPersonA},
			child:       ceilingLayers{policy: forPersonC},
			policyNamed: true,
			wantErr:     `credential policy "for-person-c" lists "c" in user_grant_scopes`,
		},
		{
			// The child's own authority (a) fits, but with no user_grant_scopes
			// it could hold b for a person, which the parent cannot.
			name:        "a child that could hold more for a person than its parent is refused",
			parent:      ceilingLayers{policy: forPersonA},
			child:       ceilingLayers{rowScopes: []string{"a", "b"}, policy: ab},
			rowNamed:    true,
			policyNamed: true,
			wantErr:     `the identity could hold "b" for a person`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := checkChildCeilings(tc.parent, tc.child, tc.rowNamed, tc.policyNamed)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("want the child allowed, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("want a refusal containing %q, got none", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("refusal %q does not contain %q", err, tc.wantErr)
			}
			// Handlers answer 400 for both.
			if !errors.Is(err, ErrInvalidIdentityField) || !errors.Is(err, ErrExceedsParentCeiling) {
				t.Errorf("refusal %v must wrap ErrInvalidIdentityField and ErrExceedsParentCeiling", err)
			}
		})
	}
}

// TestScopeBound pins the layer semantics the ceiling check relies on: an
// empty layer restricts nothing, and disjoint restricting layers allow none.
func TestScopeBound(t *testing.T) {
	t.Parallel()

	if b := boundOf(nil, []string{}); b.restricted || !b.allows("anything") {
		t.Errorf("no restricting layer must leave the bound open, got %+v", b)
	}
	b := boundOf([]string{"a", "b"}, nil, []string{"b", "c"})
	if !b.restricted || !b.allows("b") || b.allows("a") || b.allows("c") {
		t.Errorf("want the intersection {b}, got %+v", b)
	}
	if b := boundOf([]string{"a"}, []string{"b"}); !b.restricted || b.allows("a") || b.allows("b") {
		t.Errorf("disjoint layers must allow nothing, got %+v", b)
	}

	parent := boundOf([]string{"a", "b"})
	if scope, open := parent.excess(boundOf([]string{"c", "a", "z"})); open || scope != "c" {
		t.Errorf("want the first excess scope in sorted order, c; got %q (open=%v)", scope, open)
	}
	if _, open := parent.excess(boundOf()); !open {
		t.Error("an open child under a restricted parent must report open")
	}
	if scope, open := boundOf().excess(boundOf()); open || scope != "" {
		t.Error("nothing exceeds an open parent")
	}
}

// TestCallerIdentityContext pins the context round trip the embedder's admin
// authentication relies on.
func TestCallerIdentityContext(t *testing.T) {
	t.Parallel()

	if _, ok := CallerIdentityFromContext(context.Background()); ok {
		t.Fatal("a bare context must carry no caller identity")
	}
	want := CallerIdentity{IdentityID: "0b4b4c5e-5b7a-4d36-9a52-1b9f6c0e7d11", WIMSEURI: "spiffe://example.org/a/p/agent/x"}
	got, ok := CallerIdentityFromContext(WithCallerIdentity(context.Background(), want))
	if !ok || got != want {
		t.Fatalf("got %+v (ok=%v), want %+v", got, ok, want)
	}
}

// TestChildCreatedBy pins created_by for a child: the parent's WIMSE URI, or
// its id when the URI would not fit the column.
func TestChildCreatedBy(t *testing.T) {
	t.Parallel()

	parent := &domain.Identity{ID: "0b4b4c5e-5b7a-4d36-9a52-1b9f6c0e7d11", WIMSEURI: "spiffe://example.org/a/p/agent/x"}
	if got := childCreatedBy(parent); got != parent.WIMSEURI {
		t.Errorf("got %q, want the parent's WIMSE URI", got)
	}
	parent.WIMSEURI = "spiffe://example.org/" + strings.Repeat("a", createdByColumnLen)
	if got := childCreatedBy(parent); got != parent.ID {
		t.Errorf("got %q, want the parent's id for a URI longer than the column", got)
	}
}
