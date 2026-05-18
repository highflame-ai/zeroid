package service

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/uptrace/bun"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/attestation"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// ErrAttestationRejected is returned when a submitted proof fails verification.
// Distinguished from infrastructure errors so the handler can respond 400 rather
// than 500 — rejection is a client/config problem, not a server fault.
var ErrAttestationRejected = errors.New("attestation proof rejected")

// AttestationService handles attestation submission and verification. The
// verifier registry and attestation-policy service together implement the
// fail-closed contract: no policy + no verifier = no trust promotion.
//
// When allowUnsafeDevStub is true (sourced from
// cfg.Attestation.AllowUnsafeDevStub at construction time), VerifyAttestation
// permits a transitional bypass: if the tenant has no AttestationPolicy
// configured but the verifier IS registered, the service synthesises a
// stub-shape Result and continues. The verifier itself is not invoked in
// that case (the OIDC verifier requires a non-empty policy config to mean
// anything; the stub doesn't read config). A loud WARN logs every such
// bypass so operators can prioritise migrating those tenants to a real
// policy before the flag is flipped off.
type AttestationService struct {
	repo          *postgres.AttestationRepository
	credentialSvc *CredentialService
	identitySvc   *IdentityService
	verifiers     *attestation.Registry
	policySvc     *attestation.PolicyService
	// db is the *bun.DB handle used to open transactions in
	// VerifyAttestation. The repo methods themselves participate via
	// postgres.WithTx(ctx, tx); the service owns the tx lifecycle.
	db *bun.DB

	// permissive is the runtime-mutable form of cfg.Attestation.AllowUnsafeDevStub.
	// Stored as int32 so SetPermissive can flip it without a mutex —
	// integration tests need to toggle the bypass mid-suite.
	permissive atomic.Bool
}

// NewAttestationService creates a new AttestationService. verifiers and
// policySvc are required: VerifyAttestation fails closed when no verifier
// is registered for a proof type or no tenant policy exists, unless
// allowUnsafeDevStub is true (transitional bypass). db is required so the
// three writes in VerifyAttestation (issue credential, promote trust,
// mark record verified) can be wrapped in a single transaction.
func NewAttestationService(
	repo *postgres.AttestationRepository,
	credentialSvc *CredentialService,
	identitySvc *IdentityService,
	verifiers *attestation.Registry,
	policySvc *attestation.PolicyService,
	db *bun.DB,
	allowUnsafeDevStub bool,
) *AttestationService {
	s := &AttestationService{
		repo:          repo,
		credentialSvc: credentialSvc,
		identitySvc:   identitySvc,
		verifiers:     verifiers,
		policySvc:     policySvc,
		db:            db,
	}
	s.permissive.Store(allowUnsafeDevStub)
	return s
}

// SetPermissive flips the missing-policy bypass at runtime. Production
// code should not call this; it exists so integration tests can exercise
// both modes without standing up a second server. Server.SetAttestationPermissive
// is the public surface.
func (s *AttestationService) SetPermissive(enabled bool) {
	s.permissive.Store(enabled)
}

// SubmitAttestation records a new attestation proof.
func (s *AttestationService) SubmitAttestation(ctx context.Context, identityID, accountID, projectID string, level domain.AttestationLevel, proofType domain.ProofType, proofValue string) (*domain.AttestationRecord, error) {
	hash := sha256.Sum256([]byte(proofValue))
	proofHash := fmt.Sprintf("%x", hash)

	record := &domain.AttestationRecord{
		ID:         uuid.New().String(),
		IdentityID: identityID,
		AccountID:  accountID,
		ProjectID:  projectID,
		Level:      level,
		ProofType:  proofType,
		ProofValue: proofValue,
		ProofHash:  proofHash,
		IsVerified: false,
		CreatedAt:  time.Now(),
	}

	if err := s.repo.Create(ctx, record); err != nil {
		return nil, fmt.Errorf("failed to submit attestation: %w", err)
	}

	return record, nil
}

// VerifyAttestationResult holds the attestation record and the auto-issued credential.
type VerifyAttestationResult struct {
	Record      *domain.AttestationRecord
	AccessToken *domain.AccessToken
	Credential  *domain.IssuedCredential
}

// ErrAttestationAlreadyVerified is returned when VerifyAttestation is called
// on a record that is already marked verified. Re-verification is rejected
// so a partial-failure retry cannot mint a second credential against the
// same proof.
var ErrAttestationAlreadyVerified = errors.New("attestation already verified")

// VerifyAttestation runs the proof through the registered Verifier for its
// ProofType, using the caller's tenant policy. On success it issues a
// credential, promotes the identity's trust level, and commits the record
// update with the credential link and the verified issuer/subject/expiry.
//
// Fail-closed contract:
//   - No Verifier registered for the proof type → ErrAttestationRejected.
//   - No AttestationPolicy AND permissive bypass disabled → ErrAttestationRejected.
//   - No AttestationPolicy AND permissive bypass enabled → synthesised Result
//     (transitional; logs WARN per request).
//   - Verifier.Verify returns an error → ErrAttestationRejected.
//   - Record already verified → ErrAttestationAlreadyVerified (rejects retries).
//
// Atomicity + serialization: the three side-effecting writes run inside a
// single bun.RunInTx whose first statement is SELECT ... FOR UPDATE on the
// attestation row, so concurrent /verify calls on the same record
// serialize. See the inline comments at the RunInTx site for the full
// commentary on lock order, the in-tx guard, and why the closure-scoped
// locals are assigned to the outer return values exactly once on success.
func (s *AttestationService) VerifyAttestation(ctx context.Context, id, accountID, projectID string) (*VerifyAttestationResult, error) {
	record, err := s.repo.GetByID(ctx, id, accountID, projectID)
	if err != nil {
		return nil, err
	}
	// Pre-tx fast-fail. The authoritative check happens inside the tx
	// with the row locked; this one rejects the obvious already-done
	// case before we run the verifier, open another DB connection for
	// the tx, etc. Real saving on retry storms — failing here is one
	// SELECT, failing inside the tx is BEGIN + SELECT FOR UPDATE +
	// ROLLBACK plus everything between this point and the lock.
	if record.IsVerified || record.CredentialID != "" {
		return nil, fmt.Errorf("%w: record %s", ErrAttestationAlreadyVerified, record.ID)
	}

	// Gate 1: verifier must be registered for this proof type. This stays
	// strict in permissive mode too — a typo'd or unsupported proof type
	// shouldn't auto-accept just because the dev-stub flag is on.
	verifier, err := s.verifiers.Get(record.ProofType)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAttestationRejected, err)
	}

	// Gate 2: tenant policy. Permissive mode bypasses this gate by
	// synthesising a stub-shape Result instead of running the verifier
	// (OIDC requires a policy to mean anything; the stub doesn't read
	// config). Logged WARN per request so operators can find tenants
	// that still need a real policy.
	var result *attestation.Result
	policy, policyErr := s.policySvc.GetPolicy(ctx, accountID, projectID, record.ProofType)
	switch {
	case errors.Is(policyErr, postgres.ErrAttestationPolicyNotFound):
		if !s.permissive.Load() {
			return nil, fmt.Errorf("%w: no attestation policy configured for proof type %s", ErrAttestationRejected, record.ProofType)
		}
		log.Warn().
			Str("identity_id", record.IdentityID).
			Str("account_id", accountID).
			Str("project_id", projectID).
			Str("proof_type", string(record.ProofType)).
			Str("attestation_id", record.ID).
			Msg("ATTESTATION: accepting proof with no AttestationPolicy because allow_unsafe_dev_stub=true. Configure a policy for this tenant + proof_type to switch to real verification.")
		expires := time.Now().Add(24 * time.Hour)
		result = &attestation.Result{
			Subject:   record.ProofValue,
			Issuer:    "dev-stub-no-policy",
			ExpiresAt: &expires,
		}
	case policyErr != nil:
		return nil, policyErr
	default:
		result, err = verifier.Verify(ctx, record, policy.Config)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrAttestationRejected, err)
		}
	}

	// All side-effects below happen inside RunInTx. Local closure-scoped
	// vars hold the result; the outer return values are assigned exactly
	// once on commit, so a rollback can't leave a partially-mutated
	// record visible to the caller.
	//
	// Isolation: nil TxOptions means Postgres default (READ COMMITTED).
	// That's sufficient because we serialize the only contended row with
	// SELECT ... FOR UPDATE; we don't need REPEATABLE READ semantics
	// across the whole transaction.
	//
	// GrantType is fixed to client_credentials regardless of how the
	// identity will subsequently authenticate. Verified attestation is a
	// workload-bootstrap event: the identity has just proven its
	// runtime properties (image hash, OIDC claims, TPM quote) and the
	// returned token represents that boot-time trust, not a user-driven
	// session. Downstream flows can still token-exchange / jwt-bearer
	// against this credential; the bootstrap shape just doesn't change.
	var (
		accessToken    *domain.AccessToken
		cred           *domain.IssuedCredential
		verifiedRecord *domain.AttestationRecord
	)
	txErr := s.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		ctx = postgres.WithTx(ctx, tx)

		// Re-fetch with row lock. Concurrent verifies on the same record
		// queue here; the second one re-reads the row after the first
		// commits, sees CredentialID set, and bails out below.
		//
		// Lock-order note: this acquires the attestation_records row
		// lock FIRST, then implicitly the identities row lock (via
		// UpdateIdentity's UPDATE below). Any future code path that
		// needs to hold both locks should acquire them in the same order
		// to avoid deadlocks. Postgres detects deadlocks (40P01) and
		// aborts one tx, so the worst case is a transient retry, not
		// silent corruption — but cleaner to keep the order consistent.
		//
		// The repo method's error already names what failed; no outer
		// wrap so the operator-visible message stays accurate even when
		// the inner error is the WithTx contract violation rather than
		// a runtime DB problem.
		locked, err := s.repo.GetByIDForUpdate(ctx, id, accountID, projectID)
		if err != nil {
			return err
		}
		if locked.IsVerified || locked.CredentialID != "" {
			return fmt.Errorf("%w: record %s", ErrAttestationAlreadyVerified, locked.ID)
		}

		// Re-load the identity inside the tx so we don't act on a stale
		// snapshot from before someone deactivated it. With READ COMMITTED
		// this read sees committed state as of the statement, so a
		// concurrent UpdateIdentity that already finished will be visible.
		identity, err := s.identitySvc.GetIdentity(ctx, locked.IdentityID, accountID, projectID)
		if err != nil {
			return fmt.Errorf("failed to load identity for verified attestation: %w", err)
		}
		// Fail-fast on time-bound authority before any signing work. The
		// chokepoint inside IssueCredential is the authoritative gate, but
		// catching expired identities here gives operators a precise
		// "identity_expired" error rather than a generic post-attestation
		// issuance failure.
		if !identity.Status.IsUsable() {
			return fmt.Errorf("%w (status: %s)", domain.ErrIdentityNotUsable, identity.Status)
		}
		if identity.IsExpired() {
			return fmt.Errorf("%w: identity %s expired at %s", domain.ErrIdentityExpired, identity.ID, identity.ExpiresAt.Format(time.RFC3339))
		}

		issued, issuedCred, err := s.credentialSvc.IssueCredential(ctx, IssueRequest{
			Identity:  identity,
			GrantType: domain.GrantTypeClientCredentials,
		})
		if err != nil {
			return fmt.Errorf("failed to issue post-attestation credential: %w", err)
		}

		promotedTrust := trustLevelForAttestation(locked.Level)
		if _, err := s.identitySvc.UpdateIdentity(ctx, locked.IdentityID, accountID, projectID, UpdateIdentityRequest{
			TrustLevel: promotedTrust,
		}); err != nil {
			return fmt.Errorf("failed to promote identity trust level: %w", err)
		}

		now := time.Now()
		locked.IsVerified = true
		locked.VerifiedAt = &now
		if result.ExpiresAt != nil {
			locked.ExpiresAt = result.ExpiresAt
		}
		locked.CredentialID = issuedCred.ID
		if err := s.repo.Update(ctx, locked); err != nil {
			return fmt.Errorf("failed to update attestation record: %w", err)
		}

		// Promote local-success values to the outer scope. Last step in
		// the closure so a return-error path above never assigns a
		// partial result.
		accessToken = issued
		cred = issuedCred
		verifiedRecord = locked
		return nil
	})
	if txErr != nil {
		return nil, txErr
	}

	return &VerifyAttestationResult{
		Record:      verifiedRecord,
		AccessToken: accessToken,
		Credential:  cred,
	}, nil
}

// GetAttestation retrieves an attestation record by ID.
func (s *AttestationService) GetAttestation(ctx context.Context, id, accountID, projectID string) (*domain.AttestationRecord, error) {
	return s.repo.GetByID(ctx, id, accountID, projectID)
}

// trustLevelForAttestation maps an attestation level to the promoted trust level.
//
//	software  -> verified_third_party
//	platform  -> verified_third_party
//	hardware  -> first_party
func trustLevelForAttestation(level domain.AttestationLevel) domain.TrustLevel {
	switch level {
	case domain.AttestationLevelHardware:
		return domain.TrustLevelFirstParty
	default:
		return domain.TrustLevelVerifiedThirdParty
	}
}
