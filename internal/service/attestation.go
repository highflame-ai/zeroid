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

	// permissive is the runtime-mutable form of cfg.Attestation.AllowUnsafeDevStub.
	// Stored as int32 so SetPermissive can flip it without a mutex —
	// integration tests need to toggle the bypass mid-suite.
	permissive atomic.Bool
}

// NewAttestationService creates a new AttestationService. verifiers and
// policySvc are required: VerifyAttestation fails closed when no verifier
// is registered for a proof type or no tenant policy exists, unless
// allowUnsafeDevStub is true (transitional bypass).
func NewAttestationService(
	repo *postgres.AttestationRepository,
	credentialSvc *CredentialService,
	identitySvc *IdentityService,
	verifiers *attestation.Registry,
	policySvc *attestation.PolicyService,
	allowUnsafeDevStub bool,
) *AttestationService {
	s := &AttestationService{
		repo:          repo,
		credentialSvc: credentialSvc,
		identitySvc:   identitySvc,
		verifiers:     verifiers,
		policySvc:     policySvc,
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
// Write ordering rationale: credential issuance runs BEFORE identity trust
// promotion, so the most common failure (IssueCredential) leaves nothing
// committed. Trust promotion and record update run last, in that order, so
// a failure between them leaves trust promoted (harmless — backed by a
// valid proof) with the record unmarked. The re-verify guard prevents a
// second IssueCredential call in that retry window.
func (s *AttestationService) VerifyAttestation(ctx context.Context, id, accountID, projectID string) (*VerifyAttestationResult, error) {
	record, err := s.repo.GetByID(ctx, id, accountID, projectID)
	if err != nil {
		return nil, err
	}
	if record.IsVerified {
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

	// Load the identity without promoting yet — IssueCredential needs a
	// valid, non-nil, usable identity and re-fetching guarantees we see
	// the current state (another request might have deactivated it).
	identity, err := s.identitySvc.GetIdentity(ctx, record.IdentityID, accountID, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to load identity for verified attestation: %w", err)
	}

	// Step 1: issue the credential. This is the most likely failure point
	// (policy checks, scope derivation, signing). Running it first means
	// a failure leaves no partial state behind.
	//
	// GrantType is fixed to client_credentials regardless of how the
	// identity will subsequently authenticate. Verified attestation is a
	// workload-bootstrap event: the identity has just proven its
	// runtime properties (image hash, OIDC claims, TPM quote) and the
	// returned token represents that boot-time trust, not a user-driven
	// session. Downstream flows can still token-exchange / jwt-bearer
	// against this credential; the bootstrap shape just doesn't change.
	accessToken, cred, err := s.credentialSvc.IssueCredential(ctx, IssueRequest{
		Identity:  identity,
		GrantType: domain.GrantTypeClientCredentials,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to issue post-attestation credential: %w", err)
	}

	// Step 2: promote trust level. Backed by the just-verified proof.
	promotedTrust := trustLevelForAttestation(record.Level)
	if _, err := s.identitySvc.UpdateIdentity(ctx, record.IdentityID, accountID, projectID, UpdateIdentityRequest{
		TrustLevel: promotedTrust,
	}); err != nil {
		return nil, fmt.Errorf("failed to promote identity trust level: %w", err)
	}

	// Step 3: commit the record with verified flag, audit fields, and
	// credential link in a single write.
	now := time.Now()
	record.IsVerified = true
	record.VerifiedAt = &now
	if result.ExpiresAt != nil {
		record.ExpiresAt = result.ExpiresAt
	}
	record.CredentialID = cred.ID
	if err := s.repo.Update(ctx, record); err != nil {
		return nil, fmt.Errorf("failed to update attestation record: %w", err)
	}

	return &VerifyAttestationResult{
		Record:      record,
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
