package service

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// AttestationService handles attestation submission and verification.
type AttestationService struct {
	repo          *postgres.AttestationRepository
	credentialSvc *CredentialService
	identitySvc   *IdentityService
}

// NewAttestationService creates a new AttestationService.
func NewAttestationService(repo *postgres.AttestationRepository, credentialSvc *CredentialService, identitySvc *IdentityService) *AttestationService {
	return &AttestationService{
		repo:          repo,
		credentialSvc: credentialSvc,
		identitySvc:   identitySvc,
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

// VerifyAttestation validates an attestation, marks it as verified, elevates the identity's
// trust level to match the attestation level, and auto-issues a credential.
// TODO: replace the stub proof check with real verification (image hash, OIDC, TPM).
func (s *AttestationService) VerifyAttestation(ctx context.Context, id, accountID, projectID string) (*VerifyAttestationResult, error) {
	record, err := s.repo.GetByID(ctx, id, accountID, projectID)
	if err != nil {
		return nil, err
	}

	// --- stub: mark as verified (replace with real proof validation) ---
	now := time.Now()
	record.IsVerified = true
	record.VerifiedAt = &now

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
