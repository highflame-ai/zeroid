package service

import (
	"testing"

	"github.com/highflame-ai/zeroid/domain"
)

// These tests pin the CAP-DSC-004 owner-attribution contract on the discovered
// reconcile path. The stakes: owner_user_id on a discovered row is the link
// into the tenant's stable user-id space — the id the INV-IDN-010 offboarding
// cascade keys on — and trust_level=verified_third_party must be EARNED by
// directory verification, never left behind stale or asserted by a connector.

func discoveredIdentity(status domain.IdentityStatus, owner string, trust domain.TrustLevel) *domain.Identity {
	return &domain.Identity{
		Status:      status,
		OwnerUserID: owner,
		TrustLevel:  trust,
	}
}

func TestApplyDiscoveredOwnerAttribution_VerifiedLink(t *testing.T) {
	t.Parallel()

	id := discoveredIdentity(domain.IdentityStatusDiscovered, "", domain.TrustLevelUnverified)
	applyDiscoveredOwnerAttribution(id, DiscoveredIdentityRequest{
		OwnerResolved: true,
		OwnerUserID:   "user_alice",
		TrustLevel:    domain.TrustLevelVerifiedThirdParty,
	})

	if id.OwnerUserID != "user_alice" || id.TrustLevel != domain.TrustLevelVerifiedThirdParty {
		t.Fatalf("verified attribution not applied: owner=%q trust=%q", id.OwnerUserID, id.TrustLevel)
	}
}

func TestApplyDiscoveredOwnerAttribution_ClearsStaleVerification(t *testing.T) {
	t.Parallel()
	// The owner left the tenant (SCIM offboarding): the next definitive sync
	// clears the link AND the earned trust — an empty trust level normalizes
	// to unverified so verified_third_party can never survive its own
	// justification.
	id := discoveredIdentity(domain.IdentityStatusDiscovered, "user_alice", domain.TrustLevelVerifiedThirdParty)
	applyDiscoveredOwnerAttribution(id, DiscoveredIdentityRequest{
		OwnerResolved: true,
		OwnerUserID:   "",
		TrustLevel:    "",
	})

	if id.OwnerUserID != "" {
		t.Fatalf("stale owner link survived a definitive clear: %q", id.OwnerUserID)
	}

	if id.TrustLevel != domain.TrustLevelUnverified {
		t.Fatalf("stale trust survived: %q, want unverified", id.TrustLevel)
	}
}

func TestApplyDiscoveredOwnerAttribution_NoAttestationPreserves(t *testing.T) {
	t.Parallel()
	// A sync whose directory resolve failed sends NO attestation — the prior
	// verification state must be preserved, never flapped by an outage.
	id := discoveredIdentity(domain.IdentityStatusDiscovered, "user_alice", domain.TrustLevelVerifiedThirdParty)
	applyDiscoveredOwnerAttribution(id, DiscoveredIdentityRequest{
		OwnerResolved: false,
		OwnerUserID:   "",
		TrustLevel:    "",
	})

	if id.OwnerUserID != "user_alice" || id.TrustLevel != domain.TrustLevelVerifiedThirdParty {
		t.Fatalf("attribution changed without attestation: owner=%q trust=%q", id.OwnerUserID, id.TrustLevel)
	}
}

func TestApplyDiscoveredOwnerAttribution_AdoptedRowsUntouched(t *testing.T) {
	t.Parallel()
	// Adoption assigns the accountable human; from then on connector syncs
	// must never rewrite ownership or trust — even with the attestation.
	for _, status := range []domain.IdentityStatus{
		domain.IdentityStatusPending,
		domain.IdentityStatusActive,
		domain.IdentityStatusSuspended,
		domain.IdentityStatusDeactivated,
	} {
		id := discoveredIdentity(status, "user_owner", domain.TrustLevelVerifiedThirdParty)
		applyDiscoveredOwnerAttribution(id, DiscoveredIdentityRequest{
			OwnerResolved: true,
			OwnerUserID:   "user_hijacker",
			TrustLevel:    domain.TrustLevelUnverified,
		})

		if id.OwnerUserID != "user_owner" || id.TrustLevel != domain.TrustLevelVerifiedThirdParty {
			t.Fatalf("status %s: connector rewrote a human-assigned owner: owner=%q trust=%q",
				status, id.OwnerUserID, id.TrustLevel)
		}
	}
}

func TestUpsertDiscoveredIdentity_RejectsFirstParty(t *testing.T) {
	t.Parallel()
	// Connector-sourced trust tops out at verified_third_party (CAP-DSC-004);
	// the guard must fire before any repository access (nil deps would panic).
	svc := &IdentityService{}

	_, _, err := svc.UpsertDiscoveredIdentity(t.Context(), DiscoveredIdentityRequest{
		AccountID:  "acct",
		ProjectID:  "proj",
		ExternalID: "ext-1",
		Origin:     domain.Origin("entra"),
		TrustLevel: domain.TrustLevelFirstParty,
	})
	if err == nil {
		t.Fatal("first_party from the discovery path must be rejected")
	}
}
