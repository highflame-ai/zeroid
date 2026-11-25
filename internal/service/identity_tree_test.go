package service

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

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
			parent:   childLayers(nil, open),
			child:    childLayers([]string{"x", "y"}, open),
			rowNamed: true,
		},
		{
			name:   "an open parent allows an open child",
			parent: childLayers(nil, open),
			child:  childLayers(nil, open),
		},
		{
			name:   "a child that copied both layers equals its parent",
			parent: childLayers([]string{"a", "b"}, open),
			child:  childLayers([]string{"a", "b"}, open),
		},
		{
			name:     "named allowed_scopes within the parent",
			parent:   childLayers([]string{"a", "b"}, open),
			child:    childLayers([]string{"a"}, open),
			rowNamed: true,
		},
		{
			name:     "named allowed_scopes outside the parent names the scope",
			parent:   childLayers([]string{"a", "b"}, open),
			child:    childLayers([]string{"a", "c"}, open),
			rowNamed: true,
			wantErr:  `allowed_scopes lists "c"`,
		},
		{
			name:     "named allowed_scopes is checked against the parent's policy too",
			parent:   childLayers(nil, onlyA),
			child:    childLayers([]string{"a", "b"}, onlyA),
			rowNamed: true,
			wantErr:  `allowed_scopes lists "b"`,
		},
		{
			name:        "a named policy within the parent",
			parent:      childLayers([]string{"a", "b"}, open),
			child:       childLayers([]string{"a", "b"}, onlyA),
			policyNamed: true,
		},
		{
			name:        "a named policy outside the parent names the scope",
			parent:      childLayers(nil, ab),
			child:       childLayers(nil, withD),
			policyNamed: true,
			wantErr:     `credential policy "with-d" lists "d"`,
		},
		{
			name:        "a named policy with no ceiling is refused under a restricted parent",
			parent:      childLayers([]string{"a"}, open),
			child:       childLayers([]string{"a"}, open),
			policyNamed: true,
			wantErr:     `credential policy "open" places no scope ceiling`,
		},
		{
			name:        "a named policy with no ceiling is allowed under an open parent",
			parent:      childLayers(nil, open),
			child:       childLayers(nil, open),
			policyNamed: true,
		},
		{
			// The escape this rule exists to stop: a restricted parent, a child
			// on a policy with no ceiling, and nothing else restricting it.
			name:     "a child left open under a restricted parent is refused",
			parent:   childLayers([]string{"a"}, open),
			child:    childLayers([]string{}, open),
			rowNamed: true,
			wantErr:  "would have no scope ceiling",
		},
		{
			// The parent's own policy lists b, but its allowed_scopes removes
			// it. Copying that policy is fine while the child's allowed_scopes
			// removes b too; clearing allowed_scopes would expose it.
			name:     "a copied policy wider than the parent is caught through the intersection",
			parent:   childLayers([]string{"a"}, ab),
			child:    childLayers([]string{}, ab),
			rowNamed: true,
			wantErr:  `the identity could hold "b"`,
		},
		{
			name:   "a copied policy wider than the parent is fine while allowed_scopes narrows it",
			parent: childLayers([]string{"a"}, ab),
			child:  childLayers([]string{"a"}, ab),
		},
		{
			name:        "named user_grant_scopes outside what the parent may hold for a person",
			parent:      childLayers(nil, forPersonA),
			child:       childLayers(nil, forPersonC),
			policyNamed: true,
			wantErr:     `credential policy "for-person-c" lists "c" in user_grant_scopes`,
		},
		{
			// The child's own authority (a) fits, but with no user_grant_scopes
			// it could hold b for a person, which the parent cannot.
			name:        "a child that could hold more for a person than its parent is refused",
			parent:      childLayers(nil, forPersonA),
			child:       childLayers([]string{"a", "b"}, ab),
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
	want := CallerIdentity{
		IdentityID: "0b4b4c5e-5b7a-4d36-9a52-1b9f6c0e7d11", WIMSEURI: "spiffe://example.org/a/p/agent/x",
		Scopes: []string{"data:read"}, APIKeyID: "5c0f8f8e-1d2b-4c3a-9e8f-7a6b5c4d3e2f",
	}
	got, ok := CallerIdentityFromContext(WithCallerIdentity(context.Background(), want))
	if !ok || !reflect.DeepEqual(got, want) {
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

// TestChildTrustLevel pins the registration rule: a child is registered at
// the level it names, never above its parent's, or at the default capped at
// the parent's.
func TestChildTrustLevel(t *testing.T) {
	t.Parallel()

	const (
		unverified = domain.TrustLevelUnverified
		thirdParty = domain.TrustLevelVerifiedThirdParty
		firstParty = domain.TrustLevelFirstParty
	)
	tests := []struct {
		name                    string
		requested, def, parent  domain.TrustLevel
		want                    domain.TrustLevel
		wantRefused, wantParent bool
	}{
		{name: "above the parent is refused", requested: firstParty, def: unverified, parent: thirdParty, wantRefused: true},
		{name: "equal to the parent", requested: thirdParty, def: unverified, parent: thirdParty, want: thirdParty},
		{name: "below the parent", requested: unverified, def: unverified, parent: firstParty, want: unverified},
		{name: "none gets the default", def: unverified, parent: thirdParty, want: unverified},
		{name: "none gets the default capped at the parent", def: firstParty, parent: unverified, want: unverified},
		{name: "a parent with no valid level is refused", def: unverified, parent: "", wantParent: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := childTrustLevel(tc.requested, tc.def, tc.parent)
			switch {
			case tc.wantRefused:
				if !errors.Is(err, ErrInvalidIdentityField) || !errors.Is(err, ErrExceedsParentTrust) {
					t.Fatalf("want a trust refusal, got level %q, err %v", got, err)
				}
				if !strings.Contains(err.Error(), `trust_level "first_party" is above the parent's "verified_third_party"`) {
					t.Errorf("refusal %q must name trust_level and both levels", err)
				}
			case tc.wantParent:
				if !errors.Is(err, ErrParentIdentityRefused) {
					t.Fatalf("want ErrParentIdentityRefused, got level %q, err %v", got, err)
				}
			default:
				if err != nil || got != tc.want {
					t.Fatalf("got %q, %v; want %q", got, err, tc.want)
				}
			}
		})
	}
}

// TestCheckChildTrustRaise pins the update rule: a change may not raise a
// child above its parent, but may lower it or keep the level it holds.
func TestCheckChildTrustRaise(t *testing.T) {
	t.Parallel()

	const (
		unverified = domain.TrustLevelUnverified
		thirdParty = domain.TrustLevelVerifiedThirdParty
		firstParty = domain.TrustLevelFirstParty
	)
	tests := []struct {
		name                string
		prior, next, parent domain.TrustLevel
		wantRefused         bool
	}{
		{name: "raised above the parent", prior: unverified, next: firstParty, parent: thirdParty, wantRefused: true},
		{name: "raised to the parent", prior: unverified, next: thirdParty, parent: thirdParty},
		{name: "lowered", prior: thirdParty, next: unverified, parent: thirdParty},
		{name: "kept above a parent lowered later", prior: firstParty, next: firstParty, parent: unverified},
		{name: "lowered but still above the parent", prior: firstParty, next: thirdParty, parent: unverified},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := checkChildTrustRaise(tc.prior, tc.next, tc.parent)
			if tc.wantRefused != (err != nil) {
				t.Fatalf("refused = %v (%v), want %v", err != nil, err, tc.wantRefused)
			}
			if err != nil && !errors.Is(err, ErrExceedsParentTrust) {
				t.Errorf("refusal %v must wrap ErrExceedsParentTrust", err)
			}
		})
	}
}

// TestCheckChildPolicy pins the full policy subset check a child's named
// credential policy must pass against its parent's effective policy: same
// scopes but a wider grant type, lifetime, delegation depth, principal, trust
// or attestation requirement, or a later expiry, is refused.
func TestCheckChildPolicy(t *testing.T) {
	t.Parallel()
	soon := time.Now().Add(time.Hour)
	later := soon.Add(time.Hour)
	parentPolicy := func() *domain.CredentialPolicy {
		return &domain.CredentialPolicy{
			ID: "11111111-1111-4111-8111-111111111111", Name: "parent", IsActive: true,
			AllowedScopes:         []string{"read", "write"},
			AllowedGrantTypes:     []string{"api_key"},
			MaxTTLSeconds:         300,
			MaxDelegationDepth:    0,
			RequiredPrincipalType: "user",
			RequiredTrustLevel:    "first_party",
			RequiredAttestation:   "hardware",
			ExpiresAt:             &soon,
		}
	}
	svc := &IdentityService{policySvc: &CredentialPolicyService{}}
	b := &treeBound{identity: &domain.Identity{}}
	b.policy = parentPolicy()

	same := parentPolicy()
	same.ID, same.Name = "22222222-2222-4222-8222-222222222222", "same"
	if err := svc.checkChildPolicy(b, same); err != nil {
		t.Fatalf("an equal policy must pass: %v", err)
	}

	wider := map[string]func(p *domain.CredentialPolicy){
		"grant types": func(p *domain.CredentialPolicy) {
			p.AllowedGrantTypes = append(p.AllowedGrantTypes, "client_credentials")
		},
		"max ttl":       func(p *domain.CredentialPolicy) { p.MaxTTLSeconds = 7776000 },
		"delegation":    func(p *domain.CredentialPolicy) { p.MaxDelegationDepth = 5 },
		"principal":     func(p *domain.CredentialPolicy) { p.RequiredPrincipalType = "" },
		"trust":         func(p *domain.CredentialPolicy) { p.RequiredTrustLevel = "" },
		"attestation":   func(p *domain.CredentialPolicy) { p.RequiredAttestation = "" },
		"later expiry":  func(p *domain.CredentialPolicy) { p.ExpiresAt = &later },
		"no expiry":     func(p *domain.CredentialPolicy) { p.ExpiresAt = nil },
		"another scope": func(p *domain.CredentialPolicy) { p.AllowedScopes = append(p.AllowedScopes, "admin") },
	}
	for name, widen := range wider {
		child := parentPolicy()
		child.ID, child.Name = "33333333-3333-4333-8333-333333333333", "child"
		widen(child)
		err := svc.checkChildPolicy(b, child)
		if !errors.Is(err, ErrExceedsParentPolicy) || !errors.Is(err, ErrInvalidIdentityField) {
			t.Errorf("%s: want ErrExceedsParentPolicy, got %v", name, err)
		}
	}

	inactive := parentPolicy()
	inactive.IsActive = false
	if err := usablePolicy(inactive); err == nil {
		t.Error("an inactive parent policy must refuse")
	}
	expired := parentPolicy()
	past := time.Now().Add(-time.Minute)
	expired.ExpiresAt = &past
	if err := usablePolicy(expired); err == nil {
		t.Error("an expired parent policy must refuse")
	}
}

// TestCheckChildPolicyHeldToBoth pins that a child under a caller that
// presented an API key is held to the caller's own policy as well as the
// key's: a policy within the key's but wider than the identity's (the
// identity was narrowed after the key was made) is refused, and the policy a
// child inherits is the narrower of the two, or none when neither is within
// the other.
func TestCheckChildPolicyHeldToBoth(t *testing.T) {
	t.Parallel()
	mk := func(id, name string, grants []string, ttl int) *domain.CredentialPolicy {
		return &domain.CredentialPolicy{ID: id, Name: name, IsActive: true, AllowedScopes: []string{"read"}, AllowedGrantTypes: grants, MaxTTLSeconds: ttl}
	}
	narrow := mk("11111111-1111-4111-8111-111111111111", "identity", []string{"api_key"}, 300)
	wide := mk("22222222-2222-4222-8222-222222222222", "key", []string{"api_key", "client_credentials"}, 86400)
	svc := &IdentityService{policySvc: &CredentialPolicyService{}}
	b := &treeBound{identity: &domain.Identity{}, identityPolicy: narrow, policy: wide}

	if err := svc.checkChildPolicy(b, wide); !errors.Is(err, ErrExceedsParentPolicy) {
		t.Fatalf("the key's policy, wider than the identity's, must be refused: %v", err)
	}
	if err := svc.checkChildPolicy(b, narrow); err != nil {
		t.Fatalf("a policy within both must pass: %v", err)
	}
	if !svc.policyWithin(narrow, wide) || svc.policyWithin(wide, narrow) {
		t.Fatal("policyWithin must order the two policies")
	}
}

// TestCallerStatusChange pins that a calling identity may lower a child's
// status but never raise it.
func TestCallerStatusChange(t *testing.T) {
	t.Parallel()
	active, suspended := domain.IdentityStatusActive, domain.IdentityStatusSuspended
	deactivated, expired := domain.IdentityStatusDeactivated, domain.IdentityStatusExpired
	for _, tc := range []struct {
		prior, next domain.IdentityStatus
		refused     bool
	}{
		{active, suspended, false},
		{active, deactivated, false},
		{suspended, deactivated, false},
		{active, expired, false},
		{expired, deactivated, false},
		{active, active, false},
		{suspended, active, true},
		{deactivated, active, true},
		{domain.IdentityStatusPending, active, true},
	} {
		err := callerStatusChange(tc.prior, tc.next)
		if (err != nil) != tc.refused {
			t.Errorf("%s to %s: refused = %v (%v), want %v", tc.prior, tc.next, err != nil, err, tc.refused)
		}
		if err != nil && !errors.Is(err, ErrParentIdentityRefused) {
			t.Errorf("%s to %s: %v must wrap ErrParentIdentityRefused", tc.prior, tc.next, err)
		}
	}
}

// TestCheckWithinToken pins the token layer: a child can hold no scope the
// caller's token does not, and a token with no scopes lets it hold none.
func TestCheckWithinToken(t *testing.T) {
	t.Parallel()
	b := &treeBound{identity: &domain.Identity{}, hasToken: true, tokenScopes: []string{"read"}}
	open := policy("open", nil, nil)
	if err := checkWithinToken(b, childLayers([]string{"read"}, open)); err != nil {
		t.Fatalf("a child within the token: %v", err)
	}
	if err := checkWithinToken(b, childLayers([]string{"read", "write"}, open)); !errors.Is(err, ErrExceedsParentCeiling) {
		t.Fatalf("a scope beyond the token: %v", err)
	}
	if err := checkWithinToken(b, childLayers(nil, open)); !errors.Is(err, ErrExceedsParentCeiling) {
		t.Fatalf("an open child under a token: %v", err)
	}
	if err := checkWithinToken(b, childLayers([]string{"read"}, policy("p", nil, []string{"write"}))); err != nil {
		t.Fatalf("user_grant_scopes are bounded by the row, which is within the token: %v", err)
	}
	none := &treeBound{identity: &domain.Identity{}, hasToken: true}
	if err := checkWithinToken(none, childLayers([]string{"read"}, open)); !errors.Is(err, ErrExceedsParentCeiling) {
		t.Fatalf("a token with no scopes: %v", err)
	}
	if s := (&IdentityService{}).inheritedScopes(none); len(s) != 0 {
		t.Fatalf("a token with no scopes leaves nothing to inherit: %v", s)
	}
}

// TestCheckExpiry pins the expiry cap: a child may not outlive the earliest
// expiry above it, and naming none under a cap outlives it.
func TestCheckExpiry(t *testing.T) {
	t.Parallel()
	limit := time.Now().Add(time.Hour)
	b := &treeBound{identity: &domain.Identity{ID: "p"}, expiryCap: &limit}
	before, after := limit.Add(-time.Minute), limit.Add(time.Minute)
	if err := checkExpiry(b, &before); err != nil {
		t.Fatalf("before the cap: %v", err)
	}
	if err := checkExpiry(b, &limit); err != nil {
		t.Fatalf("at the cap: %v", err)
	}
	for name, at := range map[string]*time.Time{"after": &after, "never": nil} {
		if err := checkExpiry(b, at); !errors.Is(err, ErrExceedsParentExpiry) {
			t.Errorf("%s: want ErrExceedsParentExpiry, got %v", name, err)
		}
	}
	if err := checkExpiry(&treeBound{identity: &domain.Identity{}}, nil); err != nil {
		t.Fatalf("no cap: %v", err)
	}
	if got := earliest(&after, &before); !got.Equal(before) {
		t.Fatalf("earliest: %v", got)
	}
}

// TestCeilingLayersWithin pins the "no wider than stored" test a re-sent or
// narrowing write passes.
func TestCeilingLayersWithin(t *testing.T) {
	t.Parallel()
	open := policy("open", nil, nil)
	stored := childLayers([]string{"a", "b"}, open)
	if !stored.within(childLayers([]string{"a", "b"}, open)) || !stored.within(childLayers([]string{"a"}, open)) {
		t.Fatal("equal or narrower must be within")
	}
	if stored.within(childLayers([]string{"a", "c"}, open)) || stored.within(childLayers(nil, open)) {
		t.Fatal("wider or open must not be within")
	}
	if !childLayers(nil, open).within(childLayers([]string{"x"}, open)) {
		t.Fatal("anything is within an open identity")
	}
}

// TestTreeLimitsResolved pins the defaults and the hard depth cap.
func TestTreeLimitsResolved(t *testing.T) {
	t.Parallel()
	got := TreeLimits{}.resolved()
	if got.MaxDepth != DefaultTreeMaxDepth || got.MaxChildren != DefaultTreeMaxChildren {
		t.Fatalf("defaults: %+v", got)
	}
	if got := (TreeLimits{MaxDepth: 1000, MaxChildren: 3}).resolved(); got.MaxDepth != 64 || got.MaxChildren != 3 {
		t.Fatalf("capped: %+v", got)
	}
}
