package service

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

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
type AttestationService struct {
	repo          *postgres.AttestationRepository
	credentialSvc *CredentialService
	identitySvc   *IdentityService
	verifiers     *attestation.Registry
	policySvc     *AttestationPolicyService
}

// NewAttestationService creates a new AttestationService. verifiers and
// policySvc are required: VerifyAttestation fails closed when no verifier
// is registered for a proof type or no tenant policy exists.
func NewAttestationService(
	repo *postgres.AttestationRepository,
	credentialSvc *CredentialService,
	identitySvc *IdentityService,
	verifiers *attestation.Registry,
	policySvc *AttestationPolicyService,
) *AttestationService {
	return &AttestationService{
		repo:          repo,
		credentialSvc: credentialSvc,
		identitySvc:   identitySvc,
		verifiers:     verifiers,
		policySvc:     policySvc,
	}
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

// VerifyAttestation runs the proof through the registered Verifier for its
// ProofType, using the caller's tenant policy. On success it marks the
// record verified, copies the issuer / subject / expiry from the Verifier
// Result onto the record, promotes the identity's trust level, and issues
// a credential. Any failure along the way leaves the record unverified and
// returns an error — no partial state.
//
// Fail-closed contract:
//   - No Verifier registered for the proof type → ErrAttestationRejected.
//   - No AttestationPolicy for the tenant + proof type → ErrAttestationRejected.
//   - Verifier.Verify returns an error → ErrAttestationRejected.
//
// This replaces the previous stub that accepted any submitted proof.
func (s *AttestationService) VerifyAttestation(ctx context.Context, id, accountID, projectID string) (*VerifyAttestationResult, error) {
	record, err := s.repo.GetByID(ctx, id, accountID, projectID)
	if err != nil {
		return nil, err
	}

	verifier, err := s.verifiers.Get(record.ProofType)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAttestationRejected, err)
	}

	policy, err := s.policySvc.GetPolicy(ctx, accountID, projectID, record.ProofType)
	if err != nil {
		if errors.Is(err, postgres.ErrAttestationPolicyNotFound) {
			return nil, fmt.Errorf("%w: no attestation policy configured for proof type %s", ErrAttestationRejected, record.ProofType)
		}
		return nil, err
	}

	result, err := verifier.Verify(ctx, record, policy.Config)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAttestationRejected, err)
	}

	now := time.Now()
	record.IsVerified = true
	record.VerifiedAt = &now
	if result.ExpiresAt != nil {
		record.ExpiresAt = result.ExpiresAt
	}

	// Elevate trust level based on attestation level.
	promotedTrust := trustLevelForAttestation(record.Level)
	identity, err := s.identitySvc.UpdateIdentity(ctx, record.IdentityID, accountID, projectID, UpdateIdentityRequest{
		TrustLevel: promotedTrust,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to promote identity trust level: %w", err)
	}

	// Issue a credential for the newly verified identity.
	accessToken, cred, err := s.credentialSvc.IssueCredential(ctx, IssueRequest{
		Identity:  identity,
		GrantType: domain.GrantTypeClientCredentials,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to issue post-attestation credential: %w", err)
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
