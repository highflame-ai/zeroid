package integration_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// TestPostgresWithTxRollbackPersistsNothing pins the foundational invariant
// behind the #98 transaction wrap in AttestationService.VerifyAttestation:
// when a closure passed to bun.RunInTx returns a non-nil error, every
// participating repo write rolls back. Without this guarantee, the
// attestation atomicity claim collapses — Step 1's IssueCredential could
// commit even when Step 2 or 3 fails inside the closure.
//
// This test exercises the WithTx + dbOrTx mechanism end-to-end against
// the real Postgres testcontainer, separately from the higher-level
// VerifyAttestation flow that uses it. We run an Identity insert + an
// IssuedCredential insert inside a tx, force an error after both writes,
// and confirm neither row landed in the DB.
func TestPostgresWithTxRollbackPersistsNothing(t *testing.T) {
	ctx := context.Background()
	identityRepo := postgres.NewIdentityRepository(testDB)
	credRepo := postgres.NewCredentialRepository(testDB)

	identityID := uuid.NewString()
	credID := uuid.NewString()
	jti := "tx-rollback-" + uuid.NewString()

	rollbackErr := errors.New("force rollback")

	txErr := testDB.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		ctx = postgres.WithTx(ctx, tx)

		identity := &domain.Identity{
			ID:            identityID,
			AccountID:     testAccountID,
			ProjectID:     testProjectID,
			ExternalID:    "tx-rollback-id-" + identityID[:8],
			Name:          "tx rollback fixture",
			IdentityType:  domain.IdentityTypeAgent,
			TrustLevel:    domain.TrustLevelUnverified,
			Status:        domain.IdentityStatusActive,
			WIMSEURI:      "spiffe://test/" + identityID,
			AllowedScopes: []string{},
			Capabilities:  []byte("{}"),
			Labels:        []byte("{}"),
			Metadata:      []byte("{}"),
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}
		if err := identityRepo.Create(ctx, identity); err != nil {
			return err
		}

		cred := &domain.IssuedCredential{
			ID:         credID,
			IdentityID: &identityID,
			AccountID:  testAccountID,
			ProjectID:  testProjectID,
			JTI:        jti,
			Subject:    identity.WIMSEURI,
			Scopes:     []string{},
			IssuedAt:   time.Now(),
			ExpiresAt:  time.Now().Add(time.Hour),
			TTLSeconds: 3600,
			GrantType:  domain.GrantTypeClientCredentials,
		}
		if err := credRepo.Create(ctx, cred); err != nil {
			return err
		}

		return rollbackErr
	})

	require.Error(t, txErr)
	require.ErrorIs(t, txErr, rollbackErr,
		"the closure's error must surface to the caller — RunInTx should not swallow it")

	// Foundational claim: nothing committed.
	identityCount, err := testDB.NewSelect().
		Table("identities").
		Where("id = ?", identityID).
		Count(ctx)
	require.NoError(t, err)
	assert.Zero(t, identityCount, "identity row must not exist after rollback")

	credCount, err := testDB.NewSelect().
		Table("issued_credentials").
		Where("id = ?", credID).
		Count(ctx)
	require.NoError(t, err)
	assert.Zero(t, credCount, "credential row must not exist after rollback")
}

// TestGetByIDForUpdateRequiresTx pins the contract that GetByIDForUpdate
// fails fast when called without a postgres.WithTx context. Without this
// guard, a future caller that forgets to open a transaction would
// silently downgrade to a per-statement implicit tx — the SELECT FOR
// UPDATE acquires the lock and immediately releases it on the implicit
// commit, providing no useful serialization. The bug only manifests
// under concurrent load. Loud failure here = caught at code-review time
// instead of in production.
func TestGetByIDForUpdateRequiresTx(t *testing.T) {
	repo := postgres.NewAttestationRepository(testDB)
	_, err := repo.GetByIDForUpdate(context.Background(), uuid.NewString(), testAccountID, testProjectID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be called inside",
		"the contract violation message must name the missing WithTx so a future debugger sees the cause")
}

// TestPostgresWithoutTxFallsBackToAutoCommit pins the other half of the
// dbOrTx contract: when no tx is attached to ctx, repo writes use the
// repo's default *bun.DB handle and auto-commit per statement, exactly
// as before the transaction work was introduced. Without this property,
// every existing call site of these repos would have changed behavior.
func TestPostgresWithoutTxFallsBackToAutoCommit(t *testing.T) {
	ctx := context.Background()
	identityRepo := postgres.NewIdentityRepository(testDB)

	identityID := uuid.NewString()
	identity := &domain.Identity{
		ID:            identityID,
		AccountID:     testAccountID,
		ProjectID:     testProjectID,
		ExternalID:    "tx-fallback-id-" + identityID[:8],
		Name:          "tx fallback fixture",
		IdentityType:  domain.IdentityTypeAgent,
		TrustLevel:    domain.TrustLevelUnverified,
		Status:        domain.IdentityStatusActive,
		WIMSEURI:      "spiffe://test-fallback/" + identityID,
		AllowedScopes: []string{},
		Capabilities:  []byte("{}"),
		Labels:        []byte("{}"),
		Metadata:      []byte("{}"),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	require.NoError(t, identityRepo.Create(ctx, identity),
		"Create with no tx in ctx must succeed via auto-commit")

	count, err := testDB.NewSelect().
		Table("identities").
		Where("id = ?", identityID).
		Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "identity row must be persisted by the auto-commit path")

	// Tidy. No tx so this also auto-commits.
	require.NoError(t, identityRepo.Delete(ctx, identityID, testAccountID, testProjectID))
}
