// Coverage for the owner-scoped cascade revocation SQL (migrations 041/042).
//
// Migration 041 shipped with no test at all — a recursive CTE with CYCLE
// detection, a depth cap, and a data-modifying CTE with RETURNING, whose first
// execution in anger would also have been its first execution ever. Migration
// 042 adds the empty-owner guard. This file covers both.
//
// The bug 042 closes (issue #275): identities.owner_user_id is VARCHAR(255)
// NOT NULL, so an ownerless identity stores '' rather than NULL. Ownerless is
// a documented posture for `discovered` identities, not an anomaly. 041's seed
// predicate is a plain equality on that column, so calling it with an empty
// owner selected EVERY ownerless identity in the account and cascade-revoked
// each one's whole delegation subtree — a tenant-wide outage triggered by, say,
// an IdP offboarding webhook with a blank user-id field.

package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/domain"
)

// seedIdentityWithCredential inserts an identity (owned or ownerless) plus one
// live credential, and returns the identity id and the credential's JTI.
//
// ownerUserID is written verbatim — passing "" produces exactly the ownerless
// row shape the production `discovered` path creates, which is the whole point
// of this file.
func seedIdentityWithCredential(t *testing.T, ownerUserID, label string) (identityID, jti string) {
	t.Helper()
	ctx := context.Background()

	identityID = uuidV4(t)
	ident := &domain.Identity{
		ID:           identityID,
		AccountID:    testAccountID,
		ProjectID:    testProjectID,
		ExternalID:   label,
		Name:         label,
		WIMSEURI:     "spiffe://zeroid.test/" + testAccountID + "/" + testProjectID + "/agent/" + label,
		IdentityType: domain.IdentityTypeAgent,
		TrustLevel:   domain.TrustLevelFirstParty,
		Status:       domain.IdentityStatusActive,
		OwnerUserID:  ownerUserID,
		// allowed_scopes is NOT NULL; bun sends NULL for a nil slice.
		AllowedScopes: []string{},
	}
	_, err := testDB.NewInsert().Model(ident).Exec(ctx)
	require.NoError(t, err, "insert identity %q", label)

	jti = seedOwnedCredential(t, identityID, label+"-jti", "")
	return identityID, jti
}

// seedOwnedCredential inserts one live credential for an identity. parentJTI wires
// the delegation edge the recursive walk follows; empty means a root.
func seedOwnedCredential(t *testing.T, identityID, jti, parentJTI string) string {
	t.Helper()

	cred := &domain.IssuedCredential{
		ID:         uuidV4(t),
		IdentityID: &identityID,
		AccountID:  testAccountID,
		ProjectID:  testProjectID,
		JTI:        jti,
		Subject:    "spiffe://zeroid.test/subject/" + jti,
		IssuedAt:   time.Now().Add(-time.Minute),
		ExpiresAt:  time.Now().Add(time.Hour), // live: the UPDATE requires expires_at > now
		TTLSeconds: 3600,
		IsRevoked:  false,
		GrantType:  domain.GrantTypeClientCredentials,
		ParentJTI:  parentJTI,
		// scopes is NOT NULL; bun sends NULL for a nil slice.
		Scopes: []string{},
	}
	_, err := testDB.NewInsert().Model(cred).Exec(context.Background())
	require.NoError(t, err, "insert credential %q", jti)
	return jti
}

// callRevokeByOwner invokes the SQL function directly, bypassing the service
// guard, so this exercises the in-database backstop specifically.
func callRevokeByOwner(t *testing.T, ownerUserID, accountID, reason string) ([]string, error) {
	t.Helper()

	var revoked []string
	err := testDB.NewRaw(
		"SELECT jti FROM revoke_credentials_by_owner(?, ?, ?, ?)",
		ownerUserID, accountID, time.Now(), reason,
	).Scan(context.Background(), &revoked)
	return revoked, err
}

func credentialIsRevoked(t *testing.T, jti string) bool {
	t.Helper()

	var isRevoked bool
	err := testDB.NewSelect().
		Model((*domain.IssuedCredential)(nil)).
		Column("is_revoked").
		Where("jti = ?", jti).
		Scan(context.Background(), &isRevoked)
	require.NoError(t, err, "read is_revoked for %q", jti)
	return isRevoked
}

// TestRevokeByOwner_EmptyOwnerIsRejected is the issue #275 regression.
//
// Without migration 042 this call revokes every ownerless identity's
// credentials in the account. With it, the function raises and touches nothing.
func TestRevokeByOwner_EmptyOwnerIsRejected(t *testing.T) {
	// Two ownerless identities — the production shape for `discovered` ones.
	_, ownerlessA := seedIdentityWithCredential(t, "", "ownerless-a-"+shortID(t))
	_, ownerlessB := seedIdentityWithCredential(t, "", "ownerless-b-"+shortID(t))

	// A delegated child under one of them, so a cascade would reach further
	// than the seed rows themselves.
	childOfA := seedOwnedCredential(t, mustIdentityOf(t, ownerlessA), "ownerless-a-child-"+shortID(t), ownerlessA)

	revoked, err := callRevokeByOwner(t, "", testAccountID, "owner_deactivated")

	require.Error(t, err,
		"an empty owner must be rejected by the function — it matches every ownerless "+
			"identity in the account (owner_user_id is NOT NULL, so ownerless rows store '')")
	assert.Empty(t, revoked, "nothing may be returned on the reject path")

	for _, jti := range []string{ownerlessA, ownerlessB, childOfA} {
		assert.False(t, credentialIsRevoked(t, jti),
			"issue #275: credential %q belongs to an OWNERLESS identity and must survive "+
				"a blank-owner call; revoked credentials cannot be un-revoked", jti)
	}
}

// TestRevokeByOwner_EmptyAccountIsRejected covers the tenant-scope half of the
// guard. An empty account would drop the only tenant boundary the function has.
func TestRevokeByOwner_EmptyAccountIsRejected(t *testing.T) {
	owner := "user-empty-acct-" + shortID(t)
	_, jti := seedIdentityWithCredential(t, owner, "empty-acct-"+shortID(t))

	revoked, err := callRevokeByOwner(t, owner, "", "owner_deactivated")

	require.Error(t, err, "an empty account_id must be rejected — tenant scope is required")
	assert.Empty(t, revoked)
	assert.False(t, credentialIsRevoked(t, jti))
}

// TestRevokeByOwner_RevokesOwnedAndDescendants is migration 041's happy path,
// previously untested: a real owner revokes their own identities' credentials
// AND the delegated subtree, while other owners and ownerless identities in the
// same account are untouched.
func TestRevokeByOwner_RevokesOwnedAndDescendants(t *testing.T) {
	owner := "user-offboard-" + shortID(t)
	otherOwner := "user-stays-" + shortID(t)

	// The departing human's agent, plus a sub-agent it delegated to, plus a
	// grandchild — the chain the recursive walk must follow.
	ownedID, ownedJTI := seedIdentityWithCredential(t, owner, "owned-"+shortID(t))
	childJTI := seedOwnedCredential(t, ownedID, "owned-child-"+shortID(t), ownedJTI)
	grandchildJTI := seedOwnedCredential(t, ownedID, "owned-grandchild-"+shortID(t), childJTI)

	// Bystanders that must NOT be touched.
	_, otherJTI := seedIdentityWithCredential(t, otherOwner, "other-"+shortID(t))
	_, ownerlessJTI := seedIdentityWithCredential(t, "", "bystander-ownerless-"+shortID(t))

	revoked, err := callRevokeByOwner(t, owner, testAccountID, "owner_deactivated")
	require.NoError(t, err)

	assert.ElementsMatch(t, []string{ownedJTI, childJTI, grandchildJTI}, revoked,
		"the owner's credential and its whole delegation subtree must be returned exactly once each")

	for _, jti := range []string{ownedJTI, childJTI, grandchildJTI} {
		assert.True(t, credentialIsRevoked(t, jti), "%q should be revoked", jti)
	}
	assert.False(t, credentialIsRevoked(t, otherJTI),
		"another owner's credential must be untouched")
	assert.False(t, credentialIsRevoked(t, ownerlessJTI),
		"an ownerless identity must be untouched when a real owner is offboarded")
}

// mustIdentityOf resolves the identity_id behind a JTI so a test can attach a
// delegated child to the same identity.
func mustIdentityOf(t *testing.T, jti string) string {
	t.Helper()

	var id string
	err := testDB.NewSelect().
		Model((*domain.IssuedCredential)(nil)).
		Column("identity_id").
		Where("jti = ?", jti).
		Scan(context.Background(), &id)
	require.NoError(t, err)
	return id
}

// shortID keeps seeded external_id / jti values unique across tests sharing the
// one postgres container. Derived from a fresh UUID rather than a timestamp so
// two seeds in the same nanosecond cannot collide on the jti unique index.
func shortID(t *testing.T) string {
	t.Helper()
	return uuidV4(t)[:8]
}
