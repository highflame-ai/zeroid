package domain

import (
	"testing"

	"pgregory.net/rapid"
)

// lifecycleEdge is one status transition.
type lifecycleEdge struct{ from, to IdentityStatus }

// documentedTransitions is the transition relation as docs/identity-lifecycle.md
// states it: the "Transitions" list, the "Archived" row of the state table
// (deactivated → active) and the diagram's decommission arrow out of
// suspended.
var documentedTransitions = map[lifecycleEdge]bool{
	{IdentityStatusDiscovered, IdentityStatusPending}:     true, // adopt
	{IdentityStatusDiscovered, IdentityStatusDeactivated}: true, // dismiss
	{IdentityStatusDiscovered, IdentityStatusActive}:      true, // direct activation
	{IdentityStatusPending, IdentityStatusDiscovered}:     true, // dismiss reverts adoption
	{IdentityStatusPending, IdentityStatusActive}:         true,
	{IdentityStatusActive, IdentityStatusSuspended}:       true,
	{IdentityStatusActive, IdentityStatusDeactivated}:     true,
	{IdentityStatusActive, IdentityStatusExpired}:         true,
	{IdentityStatusSuspended, IdentityStatusActive}:       true,
	{IdentityStatusSuspended, IdentityStatusDeactivated}:  true, // diagram
	{IdentityStatusSuspended, IdentityStatusExpired}:      true, // diagram
	{IdentityStatusDeactivated, IdentityStatusActive}:     true, // reactivation
}

// undocumentedTransitions are allowed by CanTransitionTo and described in its
// comment in identity.go, but docs/identity-lifecycle.md names them only as
// the "…" of its "all existing transitions" line.
var undocumentedTransitions = map[lifecycleEdge]bool{
	{IdentityStatusPending, IdentityStatusDeactivated}: true, // registration rejected
	{IdentityStatusExpired, IdentityStatusDeactivated}: true,
}

var propStatuses = []IdentityStatus{
	IdentityStatusDiscovered, IdentityStatusPending, IdentityStatusActive,
	IdentityStatusSuspended, IdentityStatusDeactivated, IdentityStatusExpired,
}

// propStatus is mostly one of the six statuses, so a run covers most of the
// 36 valid pairs, and otherwise a near-miss or arbitrary string.
func propStatus() *rapid.Generator[IdentityStatus] {
	valid := rapid.SampledFrom(propStatuses)
	return rapid.OneOf(
		valid, valid, valid, valid,
		rapid.Map(rapid.SampledFrom([]string{"", "Active", "active ", "revoked", "archived"}), func(s string) IdentityStatus { return IdentityStatus(s) }),
		rapid.Map(rapid.String(), func(s string) IdentityStatus { return IdentityStatus(s) }),
	)
}

// TestProperty_IdentityStatus_OnlyActiveIsUsable: IsUsable holds for active and for no other status, valid or not.
func TestProperty_IdentityStatus_OnlyActiveIsUsable(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		s := propStatus().Draw(t, "status")
		if got := s.IsUsable(); got != (s == IdentityStatusActive) {
			t.Fatalf("%q.IsUsable() = %v", s, got)
		}
	})
}

// TestProperty_IdentityStatus_TransitionsMatchTheLifecycleDoc: CanTransitionTo allows exactly the documented transitions plus the two the doc leaves to its "…", and nothing from or to an invalid status.
func TestProperty_IdentityStatus_TransitionsMatchTheLifecycleDoc(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		e := lifecycleEdge{propStatus().Draw(t, "from"), propStatus().Draw(t, "to")}
		want := documentedTransitions[e] || undocumentedTransitions[e]
		if got := e.from.CanTransitionTo(e.to); got != want {
			t.Fatalf("%q.CanTransitionTo(%q) = %v, want %v", e.from, e.to, got, want)
		}
	})
}

// TestProperty_TrustLevelRank_OrdersTheKnownLevelsAndRanksTheRestBelow: the three trust levels rank 0 < 1 < 2 and every other string ranks -1, below all of them, so a policy's ">= required" check fails closed on an unknown level.
func TestProperty_TrustLevelRank_OrdersTheKnownLevelsAndRanksTheRestBelow(t *testing.T) {
	known := map[string]int{
		string(TrustLevelUnverified): 0, string(TrustLevelVerifiedThirdParty): 1, string(TrustLevelFirstParty): 2,
	}
	rapid.Check(t, func(t *rapid.T) {
		level := rapid.OneOf(
			rapid.SampledFrom([]string{string(TrustLevelUnverified), string(TrustLevelVerifiedThirdParty), string(TrustLevelFirstParty)}),
			rapid.SampledFrom([]string{"", "First_Party", "first_party ", "verified", "root"}),
			rapid.String(),
		).Draw(t, "level")
		want, ok := known[level]
		if !ok {
			want = -1
		}
		if got := TrustLevelRank(level); got != want {
			t.Fatalf("TrustLevelRank(%q) = %d, want %d", level, got, want)
		}
	})
}
