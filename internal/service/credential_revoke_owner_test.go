package service

import (
	"context"
	"testing"
)

// TestRevokeAllActiveForOwner_RejectsEmptyOwner pins the guard that keeps a
// blank owner from cascade-revoking every ownerless identity in an account.
//
// Why this matters: identities.owner_user_id is VARCHAR(255) NOT NULL, so an
// ownerless identity stores the empty string rather than NULL — and ownerless is a documented
// posture for `discovered` identities, not an anomaly. Migration 041's seed
// predicate is a plain equality on that column, so an empty owner selects every
// one of them and walks each delegation subtree. The realistic trigger is an IdP
// offboarding webhook whose user-id field arrives blank.
//
// The receiver is built with a nil repo ON PURPOSE. The guard must short-circuit
// before any repository call, so a nil-pointer panic here is a real failure
// signal: it means the guard did not fire and execution reached the DB layer.
func TestRevokeAllActiveForOwner_RejectsEmptyOwner(t *testing.T) {
	t.Parallel()

	svc := &CredentialService{} // repo intentionally nil — see doc comment
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

			n, err := svc.RevokeAllActiveForOwner(ctx, tc.ownerUser, tc.accountID, "owner_deactivated")

			if err == nil {
				t.Fatalf("expected an error for owner=%q account=%q; a blank owner must never "+
					"reach the cascade — it matches every ownerless identity in the account",
					tc.ownerUser, tc.accountID)
			}
			if n != 0 {
				t.Errorf("revoked count = %d, want 0 — nothing may be revoked on the reject path", n)
			}
		})
	}
}

// TestRevokeAllActiveForOwner_GuardPrecedesReasonDefault documents ordering: the
// argument guard runs before the reason default, so a caller passing an empty
// reason AND an empty owner still gets the argument error rather than having the
// blank owner silently carried into the query with a defaulted reason.
func TestRevokeAllActiveForOwner_GuardPrecedesReasonDefault(t *testing.T) {
	t.Parallel()

	svc := &CredentialService{} // nil repo: reaching it would panic
	if _, err := svc.RevokeAllActiveForOwner(context.Background(), "", "", ""); err == nil {
		t.Fatal("expected an error when owner, account and reason are all empty")
	}
}
