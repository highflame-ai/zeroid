package service

import (
	"testing"

	"github.com/highflame-ai/zeroid/domain"
)

// TestIdentityToAgentResponse_SurfacesOwner is a regression guard: the agent DTO
// must surface the identity's owner_user_id. It was previously omitted, so an
// adopted agent (which has an owner but no creator) rendered as "ownerless" in
// downstream UIs even though an accountable owner was assigned.
func TestIdentityToAgentResponse_SurfacesOwner(t *testing.T) {
	resp := identityToAgentResponse(&domain.Identity{
		ID:          "id-1",
		OwnerUserID: "user_123",
		CreatedBy:   "user_creator",
	}, "hf_sk_prefix")

	if resp.OwnerUserID != "user_123" {
		t.Errorf("AgentResponse.OwnerUserID = %q, want %q", resp.OwnerUserID, "user_123")
	}
	// created_by stays populated too — the two are distinct (creator vs owner).
	if resp.CreatedBy != "user_creator" {
		t.Errorf("AgentResponse.CreatedBy = %q, want %q", resp.CreatedBy, "user_creator")
	}
}
