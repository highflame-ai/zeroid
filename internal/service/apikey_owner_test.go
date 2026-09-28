package service

import (
	"testing"

	"github.com/highflame-ai/zeroid/domain"
)

// TestAPIKeyOwnerOverride pins who carries the owner_user_id claim for an
// api_key-minted credential.
//
// The regression this guards: keys created with no identity_id share one
// placeholder service identity per (account, project, product), whose
// owner_user_id is written once at first creation. Without the override every
// key for a product reports the FIRST creator as owner, no matter who made it,
// and Shield routes @step_up_required("self") approvals to that person.
func TestAPIKeyOwnerOverride(t *testing.T) {
	tests := []struct {
		name     string
		identity *domain.Identity
		key      *domain.APIKey
		want     string
	}{
		{
			name:     "shared service placeholder: key creator wins over frozen owner",
			identity: &domain.Identity{IdentityType: domain.IdentityTypeService, OwnerUserID: "user_first_creator"},
			key:      &domain.APIKey{CreatedBy: "user_this_creator"},
			want:     "user_this_creator",
		},
		{
			name:     "registered agent: registered owner is kept",
			identity: &domain.Identity{IdentityType: domain.IdentityTypeAgent, OwnerUserID: "user_registrant"},
			key:      &domain.APIKey{CreatedBy: "user_key_minter"},
			want:     "",
		},
		{
			name:     "registered application: registered owner is kept",
			identity: &domain.Identity{IdentityType: domain.IdentityTypeApplication, OwnerUserID: "user_registrant"},
			key:      &domain.APIKey{CreatedBy: "user_key_minter"},
			want:     "",
		},
		{
			name:     "rotated key: system actor never becomes the owner",
			identity: &domain.Identity{IdentityType: domain.IdentityTypeService, OwnerUserID: "user_first_creator"},
			key:      &domain.APIKey{CreatedBy: "system:key_rotation"},
			want:     "",
		},
		{
			name:     "padded creator is not a usable human",
			identity: &domain.Identity{IdentityType: domain.IdentityTypeService, OwnerUserID: "user_first_creator"},
			key:      &domain.APIKey{CreatedBy: " user_padded"},
			want:     "",
		},
		{
			name:     "system prefix is rejected whatever the case",
			identity: &domain.Identity{IdentityType: domain.IdentityTypeService, OwnerUserID: "user_first_creator"},
			key:      &domain.APIKey{CreatedBy: "System:key_rotation"},
			want:     "",
		},
		{
			name:     "nil key",
			identity: &domain.Identity{IdentityType: domain.IdentityTypeService},
			key:      nil,
			want:     "",
		},
		{
			name:     "no creator recorded: fall back to the identity",
			identity: &domain.Identity{IdentityType: domain.IdentityTypeService, OwnerUserID: "user_first_creator"},
			key:      &domain.APIKey{CreatedBy: ""},
			want:     "",
		},
		{
			name:     "unlinked key: synthetic identity carries no type",
			identity: &domain.Identity{},
			key:      &domain.APIKey{CreatedBy: "user_this_creator"},
			want:     "",
		},
		{
			name:     "nil identity",
			identity: nil,
			key:      &domain.APIKey{CreatedBy: "user_this_creator"},
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := apiKeyOwnerOverride(tt.identity, tt.key); got != tt.want {
				t.Errorf("apiKeyOwnerOverride() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestAPIKeyOwnerOverrideDistinguishesCreators is the property that actually
// broke: two people creating keys for the same product must not end up sharing
// one owner claim.
func TestAPIKeyOwnerOverrideDistinguishesCreators(t *testing.T) {
	shared := &domain.Identity{
		IdentityType: domain.IdentityTypeService,
		ExternalID:   "sentry",
		OwnerUserID:  "user_first_creator",
	}

	a := apiKeyOwnerOverride(shared, &domain.APIKey{CreatedBy: "user_alice"})
	b := apiKeyOwnerOverride(shared, &domain.APIKey{CreatedBy: "user_bob"})

	if a == b {
		t.Fatalf("two creators on the same shared identity resolved to the same owner: %q", a)
	}
	if a != "user_alice" || b != "user_bob" {
		t.Errorf("owner did not follow the key creator: got (%q, %q)", a, b)
	}
}
