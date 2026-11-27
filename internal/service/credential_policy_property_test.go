package service

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/highflame-ai/zeroid/domain"
)

// Property tests for credential policy enforcement. Generated policies stay
// within what CreatePolicy and UpdatePolicy can store: active, unexpired, a
// positive max_ttl_seconds, valid grant types, trust and attestation levels,
// and a principal requirement of "" or "user".

var (
	propGrantTypes = []string{
		string(domain.GrantTypeClientCredentials), string(domain.GrantTypeJWTBearer),
		string(domain.GrantTypeTokenExchange), string(domain.GrantTypeAPIKey),
	}
	propTrustLevels = []string{
		"", string(domain.TrustLevelUnverified), string(domain.TrustLevelVerifiedThirdParty), string(domain.TrustLevelFirstParty),
	}
	propAttestations = []string{
		"", string(domain.AttestationLevelSoftware), string(domain.AttestationLevelPlatform), string(domain.AttestationLevelHardware),
	}
	propPrincipalRequirements = []string{domain.RequirePrincipalAny, domain.RequirePrincipalUser}
	propPrincipalTypes        = []domain.PrincipalType{"", domain.PrincipalUser, domain.PrincipalWorkload, domain.PrincipalUnknown}

	// The URN a request may name a short grant type by (RFC 7523 §2.1,
	// RFC 8693 §2.1). EnforcePolicy compares the short form.
	propGrantTypeURN = map[string]string{
		string(domain.GrantTypeJWTBearer):     "urn:ietf:params:oauth:grant-type:jwt-bearer",
		string(domain.GrantTypeTokenExchange): "urn:ietf:params:oauth:grant-type:token-exchange",
	}

	// The rank orders, written out rather than read from TrustLevelRank and
	// attestationLevelRank, so a generator that draws "at least as strong" does
	// not inherit a rank bug from the code under test. An unknown trust level
	// ranks below every known one; an unknown attestation level counts as none.
	propTrustRanks = map[string]int{
		string(domain.TrustLevelUnverified): 0, string(domain.TrustLevelVerifiedThirdParty): 1, string(domain.TrustLevelFirstParty): 2,
	}
	propAttestationRanks = map[string]int{
		string(domain.AttestationLevelSoftware): 1, string(domain.AttestationLevelPlatform): 2, string(domain.AttestationLevelHardware): 3,
	}
)

func propTrustRank(level string) int {
	if r, ok := propTrustRanks[level]; ok {
		return r
	}
	return -1
}

func propAttestationRank(level string) int {
	return propAttestationRanks[level]
}

func propPolicy(t *rapid.T, label string) *domain.CredentialPolicy {
	return &domain.CredentialPolicy{
		Name:                  label,
		IsActive:              true,
		MaxTTLSeconds:         rapid.IntRange(1, 7200).Draw(t, label+".max_ttl"),
		AllowedGrantTypes:     rapid.SliceOfNDistinct(rapid.SampledFrom(propGrantTypes), 0, len(propGrantTypes), rapid.ID[string]).Draw(t, label+".grant_types"),
		AllowedScopes:         propScopeList().Draw(t, label+".allowed_scopes"),
		UserGrantScopes:       propScopeList().Draw(t, label+".user_grant_scopes"),
		RequiredTrustLevel:    rapid.SampledFrom(propTrustLevels).Draw(t, label+".trust"),
		RequiredAttestation:   rapid.SampledFrom(propAttestations).Draw(t, label+".attestation"),
		MaxDelegationDepth:    rapid.IntRange(0, 5).Draw(t, label+".depth"),
		RequiredPrincipalType: rapid.SampledFrom(propPrincipalRequirements).Draw(t, label+".principal"),
	}
}

// propNarrowScopeLayer draws a layer no broader than wider: anything when wider
// places no restriction, else a non-empty selection from it (an empty layer
// would place no restriction, which is broader).
func propNarrowScopeLayer(t *rapid.T, wider []string, label string) []string {
	if len(wider) == 0 {
		return propScopeList().Draw(t, label)
	}
	return rapid.SliceOfN(rapid.SampledFrom(wider), 1, 5).Draw(t, label)
}

// propAtLeast draws a level from levels whose rank is at least min's. An empty
// min places no requirement, so any level qualifies.
func propAtLeast(t *rapid.T, levels []string, min string, rank func(string) int, label string) string {
	if min == "" {
		return rapid.SampledFrom(levels).Draw(t, label)
	}
	if rapid.Bool().Draw(t, label+".at_bound") {
		return min
	}
	var ok []string
	for _, l := range levels {
		if l != "" && rank(l) >= rank(min) {
			ok = append(ok, l)
		}
	}
	return rapid.SampledFrom(ok).Draw(t, label)
}

// propJustBelow draws a level ranked one below min's, or one of unknown when
// min is the weakest level. An empty min has nothing below it.
func propJustBelow(t *rapid.T, levels []string, min string, rank func(string) int, unknown []string, label string) string {
	var below []string
	for _, l := range levels {
		if l != "" && rank(l) == rank(min)-1 {
			below = append(below, l)
		}
	}
	if len(below) == 0 {
		below = unknown
	}
	return rapid.SampledFrom(below).Draw(t, label)
}

// propRequestGrantType is gt as a request names it, by its URN half the time
// when it has one.
func propRequestGrantType(t *rapid.T, gt, label string) domain.GrantType {
	if urn, ok := propGrantTypeURN[gt]; ok && rapid.Bool().Draw(t, label+".urn") {
		return domain.GrantType(urn)
	}
	return domain.GrantType(gt)
}

// propNarrowerPolicy draws a policy no broader than wider on any axis.
func propNarrowerPolicy(t *rapid.T, wider *domain.CredentialPolicy) *domain.CredentialPolicy {
	principal := wider.RequiredPrincipalType
	if principal == domain.RequirePrincipalAny {
		principal = rapid.SampledFrom(propPrincipalRequirements).Draw(t, "narrower.principal")
	}
	var grants []string
	for i, gt := range wider.AllowedGrantTypes {
		if rapid.Bool().Draw(t, "narrower.grant"+string(rune('0'+i))) {
			grants = append(grants, gt)
		}
	}
	return &domain.CredentialPolicy{
		Name:                  "narrower",
		IsActive:              true,
		MaxTTLSeconds:         rapid.IntRange(1, wider.MaxTTLSeconds).Draw(t, "narrower.max_ttl"),
		AllowedGrantTypes:     grants,
		AllowedScopes:         propNarrowScopeLayer(t, wider.AllowedScopes, "narrower.allowed_scopes"),
		UserGrantScopes:       propNarrowScopeLayer(t, wider.UserGrantScopes, "narrower.user_grant_scopes"),
		RequiredTrustLevel:    propAtLeast(t, propTrustLevels, wider.RequiredTrustLevel, propTrustRank, "narrower.trust"),
		RequiredAttestation:   propAtLeast(t, propAttestations, wider.RequiredAttestation, propAttestationRank, "narrower.attestation"),
		MaxDelegationDepth:    rapid.IntRange(0, wider.MaxDelegationDepth).Draw(t, "narrower.depth"),
		RequiredPrincipalType: principal,
	}
}

// propPerturbedNarrowing draws a narrowing of wider with, most of the time,
// one axis then redrawn freely or pushed one step past wider's, so
// EnforceSubset sees both policies it must pass and near-misses it must
// refuse, far more often than two independent draws give.
func propPerturbedNarrowing(t *rapid.T, wider *domain.CredentialPolicy) *domain.CredentialPolicy {
	p := propNarrowerPolicy(t, wider)
	free := propPolicy(t, "free")
	switch rapid.IntRange(0, 15).Draw(t, "perturbed_axis") {
	case 0:
		p.MaxTTLSeconds = free.MaxTTLSeconds
	case 1:
		p.AllowedGrantTypes = free.AllowedGrantTypes
	case 2:
		p.AllowedScopes = free.AllowedScopes
	case 3:
		p.UserGrantScopes = free.UserGrantScopes
	case 4:
		p.RequiredTrustLevel = free.RequiredTrustLevel
	case 5:
		p.RequiredAttestation = free.RequiredAttestation
	case 6:
		p.MaxDelegationDepth = free.MaxDelegationDepth
	case 7:
		p.RequiredPrincipalType = free.RequiredPrincipalType
	case 8:
		p.MaxTTLSeconds = wider.MaxTTLSeconds + 1
	case 9:
		p.MaxDelegationDepth = wider.MaxDelegationDepth + 1
	case 10:
		if wider.RequiredTrustLevel != "" {
			p.RequiredTrustLevel = propJustBelow(t, propTrustLevels, wider.RequiredTrustLevel, propTrustRank, []string{""}, "perturbed.trust")
		}
	case 11:
		if wider.RequiredAttestation != "" {
			p.RequiredAttestation = propJustBelow(t, propAttestations, wider.RequiredAttestation, propAttestationRank, []string{""}, "perturbed.attestation")
		}
	case 12:
		p.AllowedScopes = append(slices.Clone(p.AllowedScopes), propScopeNearMiss(t, wider.AllowedScopes, "perturbed.scope"))
	case 13:
		p.AllowedGrantTypes = append(slices.Clone(p.AllowedGrantTypes), rapid.SampledFrom(propGrantTypes).Draw(t, "perturbed.grant_type"))
	}
	return p
}

// propScopeNearMiss draws a scope that is often just outside of: one of its
// members in another case, or with "s" as U+017F, which case folding maps to
// "s". Otherwise, or when of is empty, it draws any scope.
func propScopeNearMiss(t *rapid.T, of []string, label string) string {
	if len(of) == 0 || rapid.Bool().Draw(t, label+".any") {
		return propScope().Draw(t, label)
	}
	s := rapid.SampledFrom(of).Draw(t, label+".of")
	var variants []string
	for _, v := range []string{strings.ToUpper(s), strings.ToLower(s), strings.ReplaceAll(strings.ToLower(s), "s", "ſ")} {
		if v != s {
			variants = append(variants, v)
		}
	}
	return rapid.SampledFrom(variants).Draw(t, label+".variant")
}

func propEnforceRequest(t *rapid.T) EnforcePolicyRequest {
	return EnforcePolicyRequest{
		TTL:              rapid.IntRange(1, 7200).Draw(t, "req.ttl"),
		GrantType:        propRequestGrantType(t, rapid.SampledFrom(propGrantTypes).Draw(t, "req.grant_type"), "req.grant_type"),
		Scopes:           propScopeList().Draw(t, "req.scopes"),
		TrustLevel:       domain.TrustLevel(rapid.SampledFrom(append(propTrustLevels[1:], "", "root", "First_Party")).Draw(t, "req.trust")),
		AttestationLevel: rapid.SampledFrom(append(propAttestations, "tpm", "Hardware")).Draw(t, "req.attestation"),
		DelegationDepth:  rapid.IntRange(0, 6).Draw(t, "req.depth"),
		PrincipalType:    rapid.SampledFrom(propPrincipalTypes).Draw(t, "req.principal"),
		UserGrantBounded: rapid.Bool().Draw(t, "req.user_grant_bounded"),
	}
}

// propUpTo draws from [lo, hi], half the time exactly hi: a bound is where an
// off-by-one or a dropped axis shows.
func propUpTo(t *rapid.T, lo, hi int, label string) int {
	if rapid.Bool().Draw(t, label+".at_bound") {
		return hi
	}
	return rapid.IntRange(lo, hi).Draw(t, label)
}

// propAdmittedRequest draws a request shaped to pass policy on every axis,
// biased to its bounds. A policy with no grant types admits nothing, so its
// request is only shaped on the other axes.
func propAdmittedRequest(t *rapid.T, policy *domain.CredentialPolicy) EnforcePolicyRequest {
	req := propEnforceRequest(t)
	req.TTL = propUpTo(t, 1, policy.MaxTTLSeconds, "admitted.ttl")
	if len(policy.AllowedGrantTypes) > 0 {
		req.GrantType = propRequestGrantType(t, rapid.SampledFrom(policy.AllowedGrantTypes).Draw(t, "admitted.grant_type"), "admitted.grant_type")
	}
	if policy.RequiredPrincipalType == domain.RequirePrincipalUser {
		req.PrincipalType = domain.PrincipalUser
	}
	if ceiling := propScopeCeiling(policy, req); len(ceiling) > 0 {
		req.Scopes = rapid.SliceOfN(rapid.SampledFrom(ceiling), 0, 4).Draw(t, "admitted.scopes")
	}
	if policy.RequiredTrustLevel != "" {
		req.TrustLevel = domain.TrustLevel(propAtLeast(t, propTrustLevels, policy.RequiredTrustLevel, propTrustRank, "admitted.trust"))
	}
	if policy.RequiredAttestation != "" {
		req.AttestationLevel = propAtLeast(t, propAttestations, policy.RequiredAttestation, propAttestationRank, "admitted.attestation")
	}
	req.DelegationDepth = propUpTo(t, 0, policy.MaxDelegationDepth, "admitted.depth")
	return req
}

// propRequestNear mostly draws a request shaped to pass policy, often with
// one axis then redrawn freely or pushed just past its bound, and otherwise a
// free request. Free requests alone are refused on some axis almost always,
// which leaves the properties below with nothing admitted to check.
func propRequestNear(t *rapid.T, policy *domain.CredentialPolicy) EnforcePolicyRequest {
	free := propEnforceRequest(t)
	if rapid.IntRange(0, 3).Draw(t, "near") == 0 {
		return free
	}
	req := propAdmittedRequest(t, policy)
	switch rapid.IntRange(0, 19).Draw(t, "near.perturbed_axis") {
	case 0:
		req.TTL = free.TTL
	case 1:
		req.GrantType = free.GrantType
	case 2:
		req.Scopes = free.Scopes
	case 3:
		req.TrustLevel = free.TrustLevel
	case 4:
		req.AttestationLevel = free.AttestationLevel
	case 5:
		req.DelegationDepth = free.DelegationDepth
	case 6:
		req.PrincipalType = free.PrincipalType
	case 7:
		req.UserGrantBounded = !req.UserGrantBounded
	case 8:
		req.TTL = policy.MaxTTLSeconds + 1
	case 9:
		req.DelegationDepth = policy.MaxDelegationDepth + 1
	case 10:
		if policy.RequiredTrustLevel != "" {
			req.TrustLevel = domain.TrustLevel(propJustBelow(t, propTrustLevels, policy.RequiredTrustLevel, propTrustRank, []string{"", "root", "First_Party"}, "near.trust"))
		}
	case 11:
		if policy.RequiredAttestation != "" {
			req.AttestationLevel = propJustBelow(t, propAttestations, policy.RequiredAttestation, propAttestationRank, []string{"", "tpm", "Hardware"}, "near.attestation")
		}
	case 12:
		req.Scopes = append(slices.Clone(req.Scopes), propScopeNearMiss(t, propScopeCeiling(policy, req), "near.extra_scope"))
	case 13:
		// A level strong enough, but in a case no rank table knows.
		if policy.RequiredTrustLevel != "" {
			req.TrustLevel = domain.TrustLevel(propUpperFirst(propAtLeast(t, propTrustLevels, policy.RequiredTrustLevel, propTrustRank, "near.trust_case")))
		}
	case 14:
		if policy.RequiredAttestation != "" {
			req.AttestationLevel = propUpperFirst(propAtLeast(t, propAttestations, policy.RequiredAttestation, propAttestationRank, "near.attestation_case"))
		}
	}
	return req
}

func propUpperFirst(s string) string {
	return strings.ToUpper(s[:1]) + s[1:]
}

// propScopeCeiling is the ceiling EnforcePolicy's scope check documents (D10):
// user_grant_scopes for a bounded user-subject chain, else allowed_scopes.
func propScopeCeiling(policy *domain.CredentialPolicy, req EnforcePolicyRequest) []string {
	if req.UserGrantBounded && req.PrincipalType == domain.PrincipalUser {
		return policy.UserGrantScopes
	}
	return policy.AllowedScopes
}

// propAdmits is EnforcePolicy's checks as its comments state them, for an
// active, unexpired policy, written without calling EnforcePolicy's helpers.
func propAdmits(policy *domain.CredentialPolicy, req EnforcePolicyRequest) bool {
	gt := string(req.GrantType)
	for short, urn := range propGrantTypeURN {
		if gt == urn {
			gt = short
		}
	}
	ceiling := propScopeCeiling(policy, req)
	switch {
	case req.TTL > policy.MaxTTLSeconds,
		!slices.Contains(policy.AllowedGrantTypes, gt),
		policy.RequiredPrincipalType == domain.RequirePrincipalUser && req.PrincipalType != domain.PrincipalUser,
		len(ceiling) > 0 && !propSubset(req.Scopes, ceiling),
		policy.RequiredTrustLevel != "" && propTrustRank(string(req.TrustLevel)) < propTrustRank(policy.RequiredTrustLevel),
		policy.RequiredAttestation != "" && propAttestationRank(req.AttestationLevel) < propAttestationRank(policy.RequiredAttestation),
		req.DelegationDepth > policy.MaxDelegationDepth:
		return false
	}
	return true
}

// TestProperty_EnforcePolicy_AdmitsExactlyWhatEveryCheckAllows: EnforcePolicy admits a request iff it passes each check its comments list, so a request on a bound is admitted and one a step past it is refused.
func TestProperty_EnforcePolicy_AdmitsExactlyWhatEveryCheckAllows(t *testing.T) {
	svc := &CredentialPolicyService{}
	rapid.Check(t, func(t *rapid.T) {
		policy := propPolicy(t, "policy")
		for range 8 {
			req := propRequestNear(t, policy)
			err := svc.EnforcePolicy(t.Context(), policy, req)
			if want := propAdmits(policy, req); (err == nil) != want {
				t.Fatalf("EnforcePolicy(%+v, %+v) = %v, want admitted=%v", policy, req, err, want)
			}
			if err != nil && !errors.Is(err, ErrPolicyViolation) {
				t.Fatalf("refusal is %v, want ErrPolicyViolation", err)
			}
		}
	})
}

// TestProperty_EnforcePolicy_NeverAdmitsOutsideItsScopeCeiling: an admitted request names only scopes in scopeCeiling, which is user_grant_scopes exactly for a bounded user-subject chain.
func TestProperty_EnforcePolicy_NeverAdmitsOutsideItsScopeCeiling(t *testing.T) {
	svc := &CredentialPolicyService{}
	rapid.Check(t, func(t *rapid.T) {
		policy := propPolicy(t, "policy")
		req := propRequestNear(t, policy)

		ceiling := scopeCeiling(policy, req)
		want := propScopeCeiling(policy, req)
		if !propSameSet(ceiling, want) || len(ceiling) != len(want) {
			t.Fatalf("scopeCeiling = %v, want %v", ceiling, want)
		}
		if err := svc.EnforcePolicy(t.Context(), policy, req); err == nil && len(ceiling) > 0 && !propSubset(req.Scopes, ceiling) {
			t.Fatalf("admitted scopes %v outside the ceiling %v", req.Scopes, ceiling)
		}
	})
}

// TestProperty_EnforcePolicy_MonotoneInThePolicy: a request a policy admits is admitted by every policy at least as broad on every axis.
func TestProperty_EnforcePolicy_MonotoneInThePolicy(t *testing.T) {
	svc := &CredentialPolicyService{}
	rapid.Check(t, func(t *rapid.T) {
		wider := propPolicy(t, "wider")
		narrower := propNarrowerPolicy(t, wider)

		for range 8 {
			req := propRequestNear(t, narrower)
			if svc.EnforcePolicy(t.Context(), narrower, req) != nil {
				continue
			}
			if err := svc.EnforcePolicy(t.Context(), wider, req); err != nil {
				t.Fatalf("narrower %+v admits %+v, wider %+v refuses: %v", narrower, req, wider, err)
			}
		}
	})
}

// TestProperty_EnforceSubset_AcceptsEveryAxisWiseNarrowing: a policy no broader than another on any axis passes EnforceSubset against it.
func TestProperty_EnforceSubset_AcceptsEveryAxisWiseNarrowing(t *testing.T) {
	svc := &CredentialPolicyService{}
	rapid.Check(t, func(t *rapid.T) {
		wider := propPolicy(t, "wider")
		narrower := propNarrowerPolicy(t, wider)

		if err := svc.EnforceSubset(narrower, wider); err != nil {
			t.Fatalf("EnforceSubset(%+v, %+v) = %v", narrower, wider, err)
		}
	})
}

// propNoBroader is EnforceSubset's axis list as its doc comment states it,
// after the principal requirement it checks first (any < user). user_grant_scopes
// is not on the list.
func propNoBroader(narrower, wider *domain.CredentialPolicy) bool {
	principalRank := map[string]int{domain.RequirePrincipalAny: 0, domain.RequirePrincipalUser: 1}
	switch {
	case principalRank[narrower.RequiredPrincipalType] < principalRank[wider.RequiredPrincipalType],
		len(wider.AllowedScopes) > 0 && !propSubset(narrower.AllowedScopes, wider.AllowedScopes),
		!propSubset(narrower.AllowedGrantTypes, wider.AllowedGrantTypes),
		narrower.MaxTTLSeconds > wider.MaxTTLSeconds,
		narrower.MaxDelegationDepth > wider.MaxDelegationDepth,
		wider.RequiredTrustLevel != "" && propTrustRank(narrower.RequiredTrustLevel) < propTrustRank(wider.RequiredTrustLevel),
		wider.RequiredAttestation != "" && propAttestationRank(narrower.RequiredAttestation) < propAttestationRank(wider.RequiredAttestation):
		return false
	}
	return true
}

// TestProperty_EnforceSubset_PassesExactlyTheAxisWiseNarrowings: EnforceSubset passes a policy iff it is no broader than the wider one on every axis its doc comment lists.
func TestProperty_EnforceSubset_PassesExactlyTheAxisWiseNarrowings(t *testing.T) {
	svc := &CredentialPolicyService{}
	rapid.Check(t, func(t *rapid.T) {
		wider := propPolicy(t, "wider")
		for range 8 {
			narrower := propPerturbedNarrowing(t, wider)
			err := svc.EnforceSubset(narrower, wider)
			if want := propNoBroader(narrower, wider); (err == nil) != want {
				t.Fatalf("EnforceSubset(%+v, %+v) = %v, want passed=%v", narrower, wider, err, want)
			}
			if err != nil && !errors.Is(err, ErrPolicySubsetViolation) {
				t.Fatalf("refusal is %v, want ErrPolicySubsetViolation", err)
			}
		}
	})
}

// TestProperty_EnforceSubset_NeverPassesAPolicyThatAdmitsMore: a policy EnforceSubset passes admits no request the wider policy refuses, on the axes EnforceSubset compares.
func TestProperty_EnforceSubset_NeverPassesAPolicyThatAdmitsMore(t *testing.T) {
	svc := &CredentialPolicyService{}
	rapid.Check(t, func(t *rapid.T) {
		wider := propPolicy(t, "wider")
		// Each narrowing perturbs at most one axis, so several per wider
		// policy are drawn: with one, a check whose single axis EnforceSubset
		// skipped went untested on about one run in twenty.
		for range 4 {
			narrower := propPerturbedNarrowing(t, wider)
			// Stated on the axes EnforceSubset's doc comment lists: the
			// narrower policy keeps the wider one's user_grant_scopes, and a
			// scope list wherever the wider one has one.
			narrower.UserGrantScopes = wider.UserGrantScopes
			if len(wider.AllowedScopes) > 0 && len(narrower.AllowedScopes) == 0 {
				narrower.AllowedScopes = wider.AllowedScopes[:1]
			}
			if svc.EnforceSubset(narrower, wider) != nil {
				continue
			}

			for range 8 {
				req := propRequestNear(t, narrower)
				if svc.EnforcePolicy(t.Context(), narrower, req) != nil {
					continue
				}
				if err := svc.EnforcePolicy(t.Context(), wider, req); err != nil {
					t.Fatalf("EnforceSubset passed %+v under %+v, which admits %+v that the wider refuses: %v", narrower, wider, req, err)
				}
			}
		}
	})
}

// TestProperty_EnforcePolicy_UnknownTrustLevelFailsClosed: under any trust requirement, an identity whose trust level is not one of the three known levels is refused.
func TestProperty_EnforcePolicy_UnknownTrustLevelFailsClosed(t *testing.T) {
	svc := &CredentialPolicyService{}
	rapid.Check(t, func(t *rapid.T) {
		policy := propPolicy(t, "policy")
		policy.RequiredTrustLevel = rapid.SampledFrom(propTrustLevels[1:]).Draw(t, "required")
		// A policy with no grant types refuses on that axis first, which would
		// hide whether the trust check ran.
		if len(policy.AllowedGrantTypes) == 0 {
			policy.AllowedGrantTypes = []string{rapid.SampledFrom(propGrantTypes).Draw(t, "grant_type")}
		}
		// Passes every other axis, so the refusal can only be the trust check's.
		req := propAdmittedRequest(t, policy)
		req.TrustLevel = domain.TrustLevel(rapid.OneOf(
			rapid.SampledFrom([]string{"", "root", "First_Party", "first_party ", "verified"}),
			rapid.String(),
		).Filter(func(s string) bool { return propTrustRank(s) < 0 }).Draw(t, "trust"))

		err := svc.EnforcePolicy(t.Context(), policy, req)
		if !errors.Is(err, ErrPolicyViolation) || !strings.Contains(err.Error(), "identity trust level") {
			t.Fatalf("unknown trust level %q under %q: %v, want the trust check's policy violation", req.TrustLevel, policy.RequiredTrustLevel, err)
		}
	})
}

// TestProperty_ClampDefaultTTL_StaysWithinThePolicyAndNeverLengthens: a server-default lifetime comes out min(ttl, max_ttl_seconds) and passes the policy's TTL check, and a requested one is returned unchanged.
func TestProperty_ClampDefaultTTL_StaysWithinThePolicyAndNeverLengthens(t *testing.T) {
	svc := &CredentialPolicyService{}
	rapid.Check(t, func(t *rapid.T) {
		ttl := rapid.IntRange(0, 100000).Draw(t, "ttl")
		requested := rapid.Bool().Draw(t, "requested")
		var policy *domain.CredentialPolicy
		if rapid.Bool().Draw(t, "hasPolicy") {
			policy = propPolicy(t, "policy")
		}

		got := clampDefaultTTLToPolicy(ttl, requested, policy)
		if got < 0 || got > ttl {
			t.Fatalf("clamp(%d) = %d, outside [0, %d]", ttl, got, ttl)
		}
		if requested || policy == nil {
			if got != ttl {
				t.Fatalf("clamp(%d, requested=%v, policy=%v) = %d, want it unchanged", ttl, requested, policy != nil, got)
			}
			return
		}
		if got != min(ttl, policy.MaxTTLSeconds) {
			t.Fatalf("clamp(%d) under max %d = %d", ttl, policy.MaxTTLSeconds, got)
		}
		// Only the TTL axis is under test: let every other axis admit.
		req := EnforcePolicyRequest{TTL: got, GrantType: domain.GrantTypeClientCredentials}
		permissive := &domain.CredentialPolicy{Name: "ttl-only", IsActive: true, MaxTTLSeconds: policy.MaxTTLSeconds, AllowedGrantTypes: []string{string(req.GrantType)}}
		if err := svc.EnforcePolicy(t.Context(), permissive, req); err != nil {
			t.Fatalf("a clamped default %d trips max %d: %v", got, policy.MaxTTLSeconds, err)
		}
	})
}
