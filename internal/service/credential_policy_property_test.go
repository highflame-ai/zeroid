package service

import (
	"errors"
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
)

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
		RequiredTrustLevel:    propAtLeast(t, propTrustLevels, wider.RequiredTrustLevel, domain.TrustLevelRank, "narrower.trust"),
		RequiredAttestation:   propAtLeast(t, propAttestations, wider.RequiredAttestation, attestationLevelRank, "narrower.attestation"),
		MaxDelegationDepth:    rapid.IntRange(0, wider.MaxDelegationDepth).Draw(t, "narrower.depth"),
		RequiredPrincipalType: principal,
	}
}

// propPerturbedNarrowing draws a narrowing of wider with one axis then
// redrawn freely, so EnforceSubset sees both policies it must pass and
// near-misses it must refuse, far more often than two independent draws give.
func propPerturbedNarrowing(t *rapid.T, wider *domain.CredentialPolicy) *domain.CredentialPolicy {
	p := propNarrowerPolicy(t, wider)
	free := propPolicy(t, "free")
	switch rapid.IntRange(0, 8).Draw(t, "perturbed_axis") {
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
	}
	return p
}

func propEnforceRequest(t *rapid.T) EnforcePolicyRequest {
	return EnforcePolicyRequest{
		TTL:              rapid.IntRange(1, 7200).Draw(t, "req.ttl"),
		GrantType:        domain.GrantType(rapid.SampledFrom(propGrantTypes).Draw(t, "req.grant_type")),
		Scopes:           propScopeList().Draw(t, "req.scopes"),
		TrustLevel:       domain.TrustLevel(rapid.SampledFrom(append(propTrustLevels[1:], "", "root")).Draw(t, "req.trust")),
		AttestationLevel: rapid.SampledFrom(append(propAttestations, "tpm")).Draw(t, "req.attestation"),
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
		req.GrantType = domain.GrantType(rapid.SampledFrom(policy.AllowedGrantTypes).Draw(t, "admitted.grant_type"))
	}
	if policy.RequiredPrincipalType == domain.RequirePrincipalUser {
		req.PrincipalType = domain.PrincipalUser
	}
	if ceiling := scopeCeiling(policy, req); len(ceiling) > 0 {
		req.Scopes = rapid.SliceOfN(rapid.SampledFrom(ceiling), 0, 4).Draw(t, "admitted.scopes")
	}
	if policy.RequiredTrustLevel != "" {
		req.TrustLevel = domain.TrustLevel(propAtLeast(t, propTrustLevels, policy.RequiredTrustLevel, domain.TrustLevelRank, "admitted.trust"))
	}
	if policy.RequiredAttestation != "" {
		req.AttestationLevel = propAtLeast(t, propAttestations, policy.RequiredAttestation, attestationLevelRank, "admitted.attestation")
	}
	req.DelegationDepth = propUpTo(t, 0, policy.MaxDelegationDepth, "admitted.depth")
	return req
}

// propRequestNear mostly draws a request shaped to pass policy, often with
// one axis then redrawn freely, and otherwise a free request. Free requests
// alone are refused on some axis almost always, which leaves the properties
// below with nothing admitted to check.
func propRequestNear(t *rapid.T, policy *domain.CredentialPolicy) EnforcePolicyRequest {
	free := propEnforceRequest(t)
	if rapid.IntRange(0, 3).Draw(t, "near") == 0 {
		return free
	}
	req := propAdmittedRequest(t, policy)
	switch rapid.IntRange(0, 15).Draw(t, "near.perturbed_axis") {
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
	}
	return req
}

// TestProperty_EnforcePolicy_NeverAdmitsOutsideItsScopeCeiling: an admitted request names only scopes in scopeCeiling, which is user_grant_scopes exactly for a bounded user-subject chain.
func TestProperty_EnforcePolicy_NeverAdmitsOutsideItsScopeCeiling(t *testing.T) {
	svc := &CredentialPolicyService{}
	rapid.Check(t, func(t *rapid.T) {
		policy := propPolicy(t, "policy")
		req := propRequestNear(t, policy)

		ceiling := scopeCeiling(policy, req)
		want := policy.AllowedScopes
		if req.UserGrantBounded && req.PrincipalType == domain.PrincipalUser {
			want = policy.UserGrantScopes
		}
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

// TestProperty_EnforceSubset_NeverPassesAPolicyThatAdmitsMore: a policy EnforceSubset passes admits no request the wider policy refuses, on the axes EnforceSubset compares.
func TestProperty_EnforceSubset_NeverPassesAPolicyThatAdmitsMore(t *testing.T) {
	svc := &CredentialPolicyService{}
	rapid.Check(t, func(t *rapid.T) {
		wider := propPolicy(t, "wider")
		narrower := propPerturbedNarrowing(t, wider)
		// EnforceSubset does not compare user_grant_scopes, and reads an empty
		// narrower allowed_scopes as a subset of any list. Callers hold both
		// with the identity-tree ceiling checks (ceilingLayers) and by
		// enforcing every policy at issuance, so here both are taken as given.
		narrower.UserGrantScopes = wider.UserGrantScopes
		if len(wider.AllowedScopes) > 0 && len(narrower.AllowedScopes) == 0 {
			narrower.AllowedScopes = wider.AllowedScopes[:1]
		}
		if svc.EnforceSubset(narrower, wider) != nil {
			return
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
	})
}

// TestProperty_EnforcePolicy_UnknownTrustLevelFailsClosed: under any trust requirement, an identity whose trust level is not one of the three known levels is refused.
func TestProperty_EnforcePolicy_UnknownTrustLevelFailsClosed(t *testing.T) {
	svc := &CredentialPolicyService{}
	rapid.Check(t, func(t *rapid.T) {
		policy := propPolicy(t, "policy")
		policy.RequiredTrustLevel = rapid.SampledFrom(propTrustLevels[1:]).Draw(t, "required")
		// Passes every other axis, so the refusal can only be the trust check's.
		req := propAdmittedRequest(t, policy)
		req.TrustLevel = domain.TrustLevel(rapid.OneOf(
			rapid.SampledFrom([]string{"", "root", "First_Party", "first_party ", "verified"}),
			rapid.String(),
		).Filter(func(s string) bool { return domain.TrustLevelRank(s) < 0 }).Draw(t, "trust"))

		if err := svc.EnforcePolicy(t.Context(), policy, req); !errors.Is(err, ErrPolicyViolation) {
			t.Fatalf("unknown trust level %q under %q: %v, want a policy violation", req.TrustLevel, policy.RequiredTrustLevel, err)
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
