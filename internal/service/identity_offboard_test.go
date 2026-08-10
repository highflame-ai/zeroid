package service

import (
	"context"
	"strings"
	"testing"
)

// TestOffboardOwner_RejectsEmptyOwnerAndAccount pins the argument guard on the
// human-offboarding composition (INV-IDN-010 / ADR 0028 D5), mirroring the
// guard on RevokeAllActiveForOwner: identities.owner_user_id is NOT NULL, so
// ownerless identities store the empty string, and a blank owner would match
// every ownerless identity in the account — turning "offboard one departing
// human" into a tenant-wide deactivation of exactly the workloads nobody
// watches. The realistic trigger is the intended caller: a SCIM deactivation
// event whose user-id field arrives blank.
//
// The receiver is built with nil repo and nil credentialSvc ON PURPOSE. The
// guard must short-circuit before any repository or credential-service call,
// so a nil-pointer panic here is a real failure signal: it means the guard did
// not fire and execution reached a dependency.
func TestOffboardOwner_RejectsEmptyOwnerAndAccount(t *testing.T) {
	t.Parallel()

	svc := &IdentityService{} // deps intentionally nil — see doc comment
	ctx := context.Background()

	tests := []struct {
		name      string
		ownerUser string
		accountID string
	}{
		{"empty owner", "", "acct-123"},
		{"empty account", "user-42", ""},
		{"both empty", "", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			result, err := svc.OffboardOwner(ctx, tc.ownerUser, tc.accountID, "owner_deactivated")

			if err == nil {
				t.Fatalf("expected an error for owner=%q account=%q; a blank owner must never "+
					"reach the offboarding sweep — it matches every ownerless identity in the account",
					tc.ownerUser, tc.accountID)
			}
			if result != nil {
				t.Errorf("result = %+v, want nil — nothing may be reported as applied on the reject path", result)
			}
		})
	}
}

// TestOffboardOwner_GuardPrecedesReasonDefault documents ordering: the argument
// guard runs before the reason default, so a caller passing an empty reason AND
// an empty owner still gets the argument error rather than having the blank
// owner silently carried forward with a defaulted reason.
func TestOffboardOwner_GuardPrecedesReasonDefault(t *testing.T) {
	t.Parallel()

	svc := &IdentityService{} // nil deps: reaching them would panic
	if _, err := svc.OffboardOwner(context.Background(), "", "", ""); err == nil {
		t.Fatal("expected an error when owner, account and reason are all empty")
	}
}

// TestOffboardOwner_GuardErrorNamesTheFootgun pins that the guard error
// explains WHY a blank owner is rejected, so an operator staring at a SCIM
// worker's retry log understands the failure is a malformed event, not a
// transient outage to wait out.
func TestOffboardOwner_GuardErrorNamesTheFootgun(t *testing.T) {
	t.Parallel()

	svc := &IdentityService{}
	_, err := svc.OffboardOwner(context.Background(), "", "acct-123", "owner_deactivated")
	if err == nil {
		t.Fatal("expected an error for empty owner")
	}
	if !strings.Contains(err.Error(), "ownerless") {
		t.Errorf("guard error should name the ownerless-identity footgun; got: %v", err)
	}
}
