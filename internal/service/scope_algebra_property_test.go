package service

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwt"
	"pgregory.net/rapid"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/oautherror"
)

// Property tests for the pure scope decisions every grant composes. The
// alphabet is small on purpose, so generated requests and ceilings overlap,
// collide and come out disjoint often enough to reach every branch. Scope
// names carry a digit so a name can be found in a denial's text without
// matching the surrounding prose.

var propScopeAlphabet = []string{"s0", "s1", "s2", "s3", "s4", "s5"}

func propScope() *rapid.Generator[string] {
	return rapid.SampledFrom(propScopeAlphabet)
}

// propScopeList is a scope list as a policy or identity row stores one:
// possibly empty (no restriction), possibly with repeats.
func propScopeList() *rapid.Generator[[]string] {
	return rapid.SliceOfN(propScope(), 0, 5)
}

// propScopeRequest is a raw `scope` parameter: the list joined with any mix of
// the whitespace parseScopeString splits on, so "omitted" also covers "  ".
func propScopeRequest(t *rapid.T, label string) string {
	scopes := rapid.SliceOfN(propScope(), 0, 5).Draw(t, label)
	space := rapid.SampledFrom([]string{" ", "  ", "\t", " \t "})
	var b strings.Builder
	b.WriteString(rapid.SampledFrom([]string{"", " ", "\t"}).Draw(t, label+"-lead"))
	for i, s := range scopes {
		if i > 0 {
			b.WriteString(space.Draw(t, label+"-sep"))
		}
		b.WriteString(s)
	}
	b.WriteString(rapid.SampledFrom([]string{"", " ", "\t "}).Draw(t, label+"-tail"))
	return b.String()
}

func propSet(scopes []string) map[string]bool {
	m := make(map[string]bool, len(scopes))
	for _, s := range scopes {
		m[s] = true
	}
	return m
}

func propSubset(a, b []string) bool {
	in := propSet(b)
	for _, s := range a {
		if !in[s] {
			return false
		}
	}
	return true
}

func propSameSet(a, b []string) bool {
	return propSubset(a, b) && propSubset(b, a)
}

func isInvalidScope(err error) bool {
	var oe *OAuthError
	return errors.As(err, &oe) && oe.Code == oautherror.InvalidScope
}

// propExpectedGrant is the documented grant, computed as sets: the request (or,
// when it is omitted, the first restricting ceiling) intersected with every
// restricting ceiling.
func propExpectedGrant(requestedRaw string, ceilings [][]string) (granted map[string]bool, restricted bool) {
	var restricting [][]string
	for _, c := range ceilings {
		if len(c) > 0 {
			restricting = append(restricting, c)
		}
	}
	base := parseScopeString(requestedRaw)
	if len(base) == 0 && len(restricting) > 0 {
		base = restricting[0]
	}
	granted = propSet(base)
	for _, c := range restricting {
		in := propSet(c)
		for s := range granted {
			if !in[s] {
				delete(granted, s)
			}
		}
	}
	return granted, len(restricting) > 0
}

// TestProperty_GrantScopes_SubsetOfEveryCeiling: a self-mint grant never holds a scope outside the request it named or outside any ceiling that restricts.
func TestProperty_GrantScopes_SubsetOfEveryCeiling(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		requested := propScopeRequest(t, "requested")
		ceilings := rapid.SliceOfN(propScopeList(), 0, 5).Draw(t, "ceilings")

		got, err := grantScopes(requested, ceilings...)
		if err != nil {
			return
		}
		if asked := parseScopeString(requested); len(asked) > 0 && !propSubset(got, asked) {
			t.Fatalf("grant %v holds a scope the request %q did not name", got, requested)
		}
		for i, c := range ceilings {
			if len(c) > 0 && !propSubset(got, c) {
				t.Fatalf("grant %v holds a scope outside ceiling %d %v", got, i, c)
			}
		}
	})
}

// TestProperty_GrantScopes_IsExactlyTheIntersection: a self-mint grant is the request (or the first restricting ceiling) narrowed by every restricting ceiling, and nothing every layer allows is dropped.
func TestProperty_GrantScopes_IsExactlyTheIntersection(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		requested := propScopeRequest(t, "requested")
		ceilings := rapid.SliceOfN(propScopeList(), 0, 5).Draw(t, "ceilings")

		got, err := grantScopes(requested, ceilings...)
		want, restricted := propExpectedGrant(requested, ceilings)
		if restricted && len(want) == 0 {
			return // refused; TestProperty_GrantScopes_EmptyUnderACeilingIsRefused covers it
		}
		if err != nil {
			t.Fatalf("grant refused (%v), want %v", err, want)
		}
		if !propSameSet(got, mapKeys(want)) {
			t.Fatalf("grant %v, want the set %v", got, mapKeys(want))
		}
	})
}

// TestProperty_GrantScopes_EmptyUnderACeilingIsRefused: when any ceiling restricts and nothing survives, the grant is invalid_scope, never an empty grant that would mint a token with no scopes claim.
func TestProperty_GrantScopes_EmptyUnderACeilingIsRefused(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		requested := propScopeRequest(t, "requested")
		ceilings := rapid.SliceOfN(propScopeList(), 0, 5).Draw(t, "ceilings")

		got, err := grantScopes(requested, ceilings...)
		restricted := slices.ContainsFunc(ceilings, func(c []string) bool { return len(c) > 0 })
		if restricted && err == nil && len(got) == 0 {
			t.Fatalf("restricting ceilings %v returned an empty grant with no error", ceilings)
		}
		if err != nil && !isInvalidScope(err) {
			t.Fatalf("refusal is %v, want invalid_scope", err)
		}
		if err != nil && !restricted {
			t.Fatalf("no ceiling restricts, yet the grant was refused: %v", err)
		}
	})
}

// TestProperty_GrantScopes_CeilingOrderIsIrrelevant: permuting the ceilings changes neither the granted set nor whether the grant is refused.
func TestProperty_GrantScopes_CeilingOrderIsIrrelevant(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		requested := propScopeRequest(t, "requested")
		ceilings := rapid.SliceOfN(propScopeList(), 0, 5).Draw(t, "ceilings")
		perm := rapid.Permutation(ceilings).Draw(t, "permuted")

		a, errA := grantScopes(requested, ceilings...)
		b, errB := grantScopes(requested, perm...)
		if (errA == nil) != (errB == nil) {
			t.Fatalf("order %v: err=%v; order %v: err=%v", ceilings, errA, perm, errB)
		}
		if !propSameSet(a, b) {
			t.Fatalf("order %v grants %v; order %v grants %v", ceilings, a, perm, b)
		}
	})
}

// TestProperty_RequireGrantableScope_RefusesExactlyANamedRequestLeftEmpty: requireGrantableScope refuses iff the caller named a scope and nothing was granted.
func TestProperty_RequireGrantableScope_RefusesExactlyANamedRequestLeftEmpty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		requested := propScopeRequest(t, "requested")
		granted := propScopeList().Draw(t, "granted")

		err := requireGrantableScope(requested, granted)
		wantRefused := len(parseScopeString(requested)) > 0 && len(granted) == 0
		if (err != nil) != wantRefused {
			t.Fatalf("requireGrantableScope(%q, %v) = %v, want refused=%v", requested, granted, err, wantRefused)
		}
		if err != nil && !isInvalidScope(err) {
			t.Fatalf("refusal is %v, want invalid_scope", err)
		}
	})
}

// TestProperty_DelegationScopeDenial_AlwaysRefusesAndBlamesTheFirstExcludingTerm: a delegation denial is always invalid_scope, and names each requested scope under the first term that excludes it and no other.
func TestProperty_DelegationScopeDenial_AlwaysRefusesAndBlamesTheFirstExcludingTerm(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		requested := rapid.SliceOfNDistinct(propScope(), 0, 5, rapid.ID[string]).Draw(t, "requested")
		subjectHolds := propSet(propScopeList().Draw(t, "subject"))
		actorPolicy := propScopeList().Draw(t, "actorPolicy")
		actorRow := propScopeList().Draw(t, "actorRow")
		actorRowNone := rapid.Bool().Draw(t, "actorRowNone")
		userGrant := rapid.Bool().Draw(t, "userGrant")

		err := delegationScopeDenial(requested, subjectHolds, actorPolicy, actorRow, actorRowNone, userGrant)
		if !isInvalidScope(err) {
			t.Fatalf("denial is %v, want invalid_scope", err)
		}
		if len(requested) == 0 {
			return
		}
		desc := err.(*OAuthError).Description
		terms := map[string]string{
			"held":       "the subject token does not hold [",
			"permitted":  "does not permit [",
			"registered": "the actor identity is not registered for [",
		}
		blamedUnder := func(term, s string) bool {
			i := strings.Index(desc, terms[term])
			if i < 0 {
				return false
			}
			rest := desc[i+len(terms[term]):]
			return slices.Contains(strings.Fields(rest[:strings.Index(rest, "]")]), s)
		}
		excludes := func(c []string, s string) bool { return len(c) > 0 && !slices.Contains(c, s) }
		for _, s := range requested {
			want := ""
			switch {
			case !subjectHolds[s]:
				want = "held"
			case excludes(actorPolicy, s):
				want = "permitted"
			case actorRowNone || excludes(actorRow, s):
				want = "registered"
			}
			for term := range terms {
				if got := blamedUnder(term, s); got != (term == want) {
					t.Fatalf("scope %s: blamed under %q = %v, want blamed only under %q; denial %q", s, term, got, want, desc)
				}
			}
		}
	})
}

// TestProperty_NarrowScopes_SubsetOfBoth: narrowScopes keeps only scopes of the grant, and only those a restricting ceiling lists.
func TestProperty_NarrowScopes_SubsetOfBoth(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		granted := propScopeList().Draw(t, "granted")
		ceiling := propScopeList().Draw(t, "ceiling")

		got := narrowScopes(granted, ceiling)
		if !propSubset(got, granted) {
			t.Fatalf("narrowScopes(%v, %v) = %v adds a scope the grant lacked", granted, ceiling, got)
		}
		if len(ceiling) > 0 && !propSubset(got, ceiling) {
			t.Fatalf("narrowScopes(%v, %v) = %v keeps a scope the ceiling excludes", granted, ceiling, got)
		}
		if len(ceiling) == 0 && !slices.Equal(got, granted) {
			t.Fatalf("an empty ceiling changed the grant: %v -> %v", granted, got)
		}
		for _, s := range granted {
			if slices.Contains(ceiling, s) && !slices.Contains(got, s) {
				t.Fatalf("narrowScopes(%v, %v) = %v dropped %s, which both allow", granted, ceiling, got, s)
			}
		}
	})
}

// TestProperty_NarrowScopes_Idempotent: narrowing twice by the same ceiling is narrowing once.
func TestProperty_NarrowScopes_Idempotent(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		granted := propScopeList().Draw(t, "granted")
		ceiling := propScopeList().Draw(t, "ceiling")

		once := narrowScopes(granted, ceiling)
		if twice := narrowScopes(once, ceiling); !slices.Equal(once, twice) {
			t.Fatalf("narrowScopes once %v, twice %v", once, twice)
		}
	})
}

// TestProperty_NarrowScopes_Monotone: a smaller grant or a narrower restricting ceiling never yields more scopes, and an empty intermediate result stays empty.
func TestProperty_NarrowScopes_Monotone(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		granted := propScopeList().Draw(t, "granted")
		ceiling := rapid.SliceOfN(propScope(), 1, 5).Draw(t, "ceiling")
		smallerGrant := propDrawSubset(t, granted, "smallerGrant")
		narrowerCeiling := rapid.SliceOfN(rapid.SampledFrom(ceiling), 1, 5).Draw(t, "narrowerCeiling")

		full := narrowScopes(granted, ceiling)
		if got := narrowScopes(smallerGrant, ceiling); !propSubset(got, full) {
			t.Fatalf("grant %v ⊆ %v, yet narrowScopes gave %v ⊄ %v", smallerGrant, granted, got, full)
		}
		if got := narrowScopes(granted, narrowerCeiling); !propSubset(got, full) {
			t.Fatalf("ceiling %v ⊆ %v, yet narrowScopes gave %v ⊄ %v", narrowerCeiling, ceiling, got, full)
		}
		if got := narrowScopes(nil, ceiling); len(got) != 0 {
			t.Fatalf("an empty grant was reset to %v by ceiling %v", got, ceiling)
		}
	})
}

// TestProperty_IntersectScopes_SubsetAndRFC6749Default: intersectScopes keeps only allowed scopes of a named request, grants the whole allowed set to an omitted one, and passes everything through an empty allowed set.
func TestProperty_IntersectScopes_SubsetAndRFC6749Default(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		requested := propScopeList().Draw(t, "requested")
		allowed := propScopeList().Draw(t, "allowed")

		got := intersectScopes(requested, allowed)
		switch {
		case len(allowed) == 0:
			if !slices.Equal(got, requested) {
				t.Fatalf("no restriction, yet %v became %v", requested, got)
			}
		case len(requested) == 0:
			if !slices.Equal(got, allowed) {
				t.Fatalf("an omitted request got %v, want the default %v", got, allowed)
			}
		default:
			if !propSubset(got, requested) || !propSubset(got, allowed) {
				t.Fatalf("intersectScopes(%v, %v) = %v is not within both", requested, allowed, got)
			}
			for _, s := range requested {
				if slices.Contains(allowed, s) && !slices.Contains(got, s) {
					t.Fatalf("intersectScopes(%v, %v) = %v dropped %s", requested, allowed, got, s)
				}
			}
		}
	})
}

// TestProperty_IntersectScopes_IdempotentAndMonotoneWhileNonEmpty: for a named request, intersectScopes is idempotent and monotone as long as its result is non-empty (an empty result is reread as an omitted request, which is why chains use narrowScopes).
func TestProperty_IntersectScopes_IdempotentAndMonotoneWhileNonEmpty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		requested := rapid.SliceOfN(propScope(), 1, 5).Draw(t, "requested")
		allowed := propScopeList().Draw(t, "allowed")
		smaller := rapid.SliceOfN(rapid.SampledFrom(requested), 1, 5).Draw(t, "smaller")

		once := intersectScopes(requested, allowed)
		if len(once) > 0 {
			if twice := intersectScopes(once, allowed); !slices.Equal(once, twice) {
				t.Fatalf("intersectScopes once %v, twice %v", once, twice)
			}
		}
		if got := intersectScopes(smaller, allowed); len(got) > 0 && !propSubset(got, once) {
			t.Fatalf("request %v ⊆ %v, yet intersectScopes gave %v ⊄ %v", smaller, requested, got, once)
		}
	})
}

// TestProperty_IdentityScopeCeilings_KeepsBothLayersApart: identityScopeCeilings returns the policy's and the identity's lists unmerged, and nil for an absent side.
func TestProperty_IdentityScopeCeilings_KeepsBothLayersApart(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		var policy *domain.CredentialPolicy
		if rapid.Bool().Draw(t, "hasPolicy") {
			policy = &domain.CredentialPolicy{AllowedScopes: propScopeList().Draw(t, "policyScopes")}
		}
		var identity *domain.Identity
		if rapid.Bool().Draw(t, "hasIdentity") {
			identity = &domain.Identity{AllowedScopes: propScopeList().Draw(t, "rowScopes")}
		}

		p, r := identityScopeCeilings(policy, identity)
		if policy == nil && p != nil || policy != nil && !slices.Equal(p, policy.AllowedScopes) {
			t.Fatalf("policy layer %v, want %v", p, policy)
		}
		if identity == nil && r != nil || identity != nil && !slices.Equal(r, identity.AllowedScopes) {
			t.Fatalf("identity layer %v, want %v", r, identity)
		}
	})
}

// TestProperty_RevocationLookupOrder_SearchesEveryKindHintFirst: every hint searches both token kinds once each, refresh first only for the refresh_token hint.
func TestProperty_RevocationLookupOrder_SearchesEveryKindHintFirst(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		hint := rapid.OneOf(
			rapid.SampledFrom([]string{"", "access_token", "refresh_token", "Refresh_Token", "refresh_token "}),
			rapid.String(),
		).Draw(t, "hint")

		got := revocationLookupOrder(hint)
		if len(got) != 2 || !slices.Contains(got, revocationKindAccess) || !slices.Contains(got, revocationKindRefresh) {
			t.Fatalf("hint %q searches %v, want both kinds once each", hint, got)
		}
		if (got[0] == revocationKindRefresh) != (hint == "refresh_token") {
			t.Fatalf("hint %q searches %v first", hint, got[0])
		}
	})
}

// TestProperty_MayActPermits_OnlyTheNamedActorUnderOurIssuer: may_act permits exactly an actor whose WIMSE URI is its non-empty string sub, under ZeroID's issuer when it names one.
func TestProperty_MayActPermits_OnlyTheNamedActorUnderOurIssuer(t *testing.T) {
	const issuer = "https://zeroid.test"
	actors := []string{"spiffe://zeroid.test/a/p/agent/b", "spiffe://zeroid.test/a/p/agent/c", ""}
	// Half the draws are the value that would permit, so the other members
	// decide the outcome often enough to be tested.
	claimValue := func(permitting string) *rapid.Generator[any] {
		return rapid.OneOf(
			rapid.Just[any](permitting),
			rapid.Just[any](permitting),
			rapid.Map(rapid.SampledFrom(append(slices.Clone(actors), issuer, "https://elsewhere.test")), func(s string) any { return s }),
			rapid.SampledFrom([]any{nil, 42.0, true, map[string]any{"sub": actors[0]}, []any{actors[0]}}),
		)
	}
	rapid.Check(t, func(t *rapid.T) {
		actor := rapid.SampledFrom(actors).Draw(t, "actor")
		mayAct := map[string]any{}
		if rapid.IntRange(0, 3).Draw(t, "hasSub") > 0 {
			mayAct["sub"] = claimValue(actor).Draw(t, "sub")
		}
		if rapid.Bool().Draw(t, "hasIss") {
			mayAct["iss"] = claimValue(issuer).Draw(t, "iss")
		}

		sub, _ := mayAct["sub"].(string)
		issOK := true
		if v, ok := mayAct["iss"]; ok {
			s, _ := v.(string)
			issOK = s == issuer
		}
		want := sub != "" && sub == actor && issOK
		if got := mayActPermits(mayAct, actor, issuer); got != want {
			t.Fatalf("mayActPermits(%v, %q) = %v, want %v", mayAct, actor, got, want)
		}
	})
}

// TestProperty_PriorActorsOf_RoundTripsTheChainCurrentActorFirst: an rfc8693 token's act chain reads back as its actors in order, cut to MaxActorChainDepth from the deepest end, and a legacy token has none.
func TestProperty_PriorActorsOf_RoundTripsTheChainCurrentActorFirst(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(0, domain.MaxActorChainDepth+8).Draw(t, "depth")
		rfc8693 := rapid.Bool().Draw(t, "rfc8693")
		actors := make([]domain.Actor, n)
		for i := range actors {
			actors[i] = domain.Actor{Sub: fmt.Sprintf("spiffe://zeroid.test/a/p/agent/a%02d", i)}
		}
		tok := jwt.New()
		if rfc8693 {
			_ = tok.Set("principal_type", string(domain.PrincipalUser))
		}
		if n > 0 {
			// Built directly, not through actorChainClaim, so the chain can be
			// longer than the issuance cap and the read side's own cap is tested.
			var act map[string]any
			for i := n - 1; i >= 0; i-- {
				level := map[string]any{"sub": actors[i].Sub}
				if act != nil {
					level["act"] = act
				}
				act = level
			}
			_ = tok.Set("act", act)
		}

		got := priorActorsOf(tok)
		var want []domain.Actor
		if rfc8693 && n > 0 {
			want = actors[:min(n, domain.MaxActorChainDepth)]
		}
		if !slices.Equal(got, want) {
			t.Fatalf("priorActorsOf = %v, want %v", got, want)
		}
		if len(got) > 0 {
			current := &domain.Identity{WIMSEURI: actors[0].Sub}
			if !isCurrentActor(got, current) {
				t.Fatalf("the outermost actor %q is not the current actor", actors[0].Sub)
			}
			if n > 1 && isCurrentActor(got, &domain.Identity{WIMSEURI: actors[1].Sub}) {
				t.Fatalf("a prior actor %q was read as the current actor", actors[1].Sub)
			}
		} else if isCurrentActor(got, &domain.Identity{WIMSEURI: ""}) {
			t.Fatal("an empty chain has a current actor")
		}
	})
}

func mapKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// propDrawSubset draws a sub-multiset of xs, in order.
func propDrawSubset(t *rapid.T, xs []string, label string) []string {
	var out []string
	for i, x := range xs {
		if rapid.Bool().Draw(t, fmt.Sprintf("%s%d", label, i)) {
			out = append(out, x)
		}
	}
	return out
}
