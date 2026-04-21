package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// ErrIdentityAlreadyExists is returned when (account_id, project_id, external_id) already exists.
var ErrIdentityAlreadyExists = errors.New("identity already exists")

// IdentityService handles identity lifecycle operations.
type IdentityService struct {
	repo          *postgres.IdentityRepository
	policySvc     *CredentialPolicyService
	wimseDomain   string
}

// NewIdentityService creates a new IdentityService. policySvc must be non-nil —
// every identity is assigned the tenant's default credential policy at
// registration time if the caller does not choose a specific one, so the
// service cannot function without a policy resolver.
func NewIdentityService(repo *postgres.IdentityRepository, policySvc *CredentialPolicyService, wimseDomain string) *IdentityService {
	return &IdentityService{repo: repo, policySvc: policySvc, wimseDomain: wimseDomain}
}

// validateECPublicKeyPEM ensures the provided PEM string is a valid EC P-256 public key.
// Returns nil if keyPEM is empty (the field is optional).
func validateECPublicKeyPEM(keyPEM string) error {
	if keyPEM == "" {
		return nil
	}
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil || block.Type != "PUBLIC KEY" {
		return errors.New("invalid public_key_pem: must be a PEM block of type PUBLIC KEY")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("invalid public_key_pem: %w", err)
	}
	ecKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("invalid public_key_pem: not an ECDSA key")
	}
	if ecKey.Curve.Params().Name != "P-256" {
		return fmt.Errorf("invalid public_key_pem: must use P-256 curve, got %s", ecKey.Curve.Params().Name)
	}
	return nil
}

// RegisterIdentityRequest holds parameters for identity registration.
type RegisterIdentityRequest struct {
	AccountID     string
	ProjectID     string
	ExternalID    string
	Name          string
	TrustLevel    domain.TrustLevel
	IdentityType  domain.IdentityType
	SubType       domain.SubType
	OwnerUserID   string
	AllowedScopes []string // Deprecated: set scope ceiling on the identity's credential policy.
	PublicKeyPEM  string
	Framework     string
	Version       string
	Publisher     string
	Description   string
	Capabilities  json.RawMessage
	Labels        json.RawMessage
	Metadata      json.RawMessage
	CreatedBy     string
	// CredentialPolicyID is the identity policy — the authority ceiling for
	// every credential this identity can hold. If empty, the tenant's default
	// policy is assigned. Must exist within the caller's tenant; cross-tenant
	// IDs are rejected with ErrPolicyNotFound.
	CredentialPolicyID string
}

// RegisterIdentity creates a new identity with a WIMSE URI.
func (s *IdentityService) RegisterIdentity(ctx context.Context, req RegisterIdentityRequest) (*domain.Identity, error) {
	if req.AccountID == "" || req.ProjectID == "" || req.ExternalID == "" {
		return nil, fmt.Errorf("accountID, projectID, and externalID are required")
	}
	if req.OwnerUserID == "" {
		return nil, fmt.Errorf("owner_user_id is required")
	}
	if req.TrustLevel == "" {
		req.TrustLevel = domain.TrustLevelUnverified
	}
	if req.IdentityType == "" {
		req.IdentityType = domain.IdentityTypeAgent
	}
	if !req.IdentityType.Valid() {
		return nil, fmt.Errorf("invalid identity_type: %s", req.IdentityType)
	}
	if req.SubType == "" && req.IdentityType == domain.IdentityTypeAgent {
		req.SubType = domain.SubTypeToolAgent
	}
	if !req.SubType.ValidForIdentityType(req.IdentityType) {
		return nil, fmt.Errorf("invalid sub_type: %s", req.SubType)
	}
	if req.AllowedScopes == nil {
		req.AllowedScopes = []string{}
	}
	if req.Capabilities == nil {
		req.Capabilities = json.RawMessage("[]")
	}
	if req.Labels == nil {
		req.Labels = json.RawMessage("{}")
	}
	if req.Metadata == nil {
		req.Metadata = json.RawMessage("{}")
	}
	if err := validateECPublicKeyPEM(req.PublicKeyPEM); err != nil {
		return nil, err
	}

	// Resolve the identity policy: a caller-supplied policy ID must be
	// tenant-scoped (IDOR guard via GetPolicy). When absent, assign the
	// tenant's default policy so every identity has a non-null authority
	// ceiling from the moment it is created.
	policyID, err := s.resolveIdentityPolicyID(ctx, req.AccountID, req.ProjectID, req.CredentialPolicyID)
	if err != nil {
		return nil, err
	}

	identity := &domain.Identity{
		ID:                 uuid.New().String(),
		AccountID:          req.AccountID,
		ProjectID:          req.ProjectID,
		ExternalID:         req.ExternalID,
		Name:               req.Name,
		WIMSEURI:           domain.BuildWIMSEURI(s.wimseDomain, req.AccountID, req.ProjectID, req.IdentityType, req.ExternalID),
		IdentityType:       req.IdentityType,
		SubType:            req.SubType,
		TrustLevel:         req.TrustLevel,
		Status:             domain.IdentityStatusActive,
		OwnerUserID:        req.OwnerUserID,
		CredentialPolicyID: policyID,
		AllowedScopes:      req.AllowedScopes,
		PublicKeyPEM:       req.PublicKeyPEM,
		Framework:          req.Framework,
		Version:            req.Version,
		Publisher:          req.Publisher,
		Description:        req.Description,
		Capabilities:       req.Capabilities,
		Labels:             req.Labels,
		Metadata:           req.Metadata,
		CreatedBy:          req.CreatedBy,
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}

	if err := s.repo.Create(ctx, identity); err != nil {
		if isDuplicateKeyError(err) {
			return nil, ErrIdentityAlreadyExists
		}
		return nil, fmt.Errorf("failed to register identity: %w", err)
	}

	log.Info().
		Str("identity_id", identity.ID).
		Str("external_id", req.ExternalID).
		Str("identity_type", string(req.IdentityType)).
		Str("sub_type", string(req.SubType)).
		Str("wimse_uri", identity.WIMSEURI).
		Msg("Identity registered")

	return identity, nil
}

// GetIdentity retrieves an identity by ID.
func (s *IdentityService) GetIdentity(ctx context.Context, id, accountID, projectID string) (*domain.Identity, error) {
	return s.repo.GetByID(ctx, id, accountID, projectID)
}

// GetIdentityByExternalID retrieves an identity by its external_id within a tenant.
func (s *IdentityService) GetIdentityByExternalID(ctx context.Context, externalID, accountID, projectID string) (*domain.Identity, error) {
	return s.repo.GetByExternalID(ctx, externalID, accountID, projectID)
}

// ListIdentities returns identities for a tenant, optionally filtered by identity_type(s) and label.
func (s *IdentityService) ListIdentities(ctx context.Context, accountID, projectID string, identityTypes []string, label, trustLevel, isActive, search string, limit, offset int) ([]*domain.Identity, int, error) {
	return s.repo.List(ctx, accountID, projectID, identityTypes, label, trustLevel, isActive, search, limit, offset)
}

// UpdateIdentityRequest holds parameters for identity updates.
// Zero-value fields are left unchanged. Pointer fields distinguish "not set" from "clear."
type UpdateIdentityRequest struct {
	Name          string
	TrustLevel    domain.TrustLevel
	IdentityType  domain.IdentityType
	SubType       domain.SubType
	OwnerUserID   string
	AllowedScopes []string
	PublicKeyPEM  string
	Framework     *string
	Version       *string
	Publisher     *string
	Description   *string
	Capabilities  json.RawMessage
	Labels        json.RawMessage
	Metadata      json.RawMessage
	Status        *domain.IdentityStatus
	// CredentialPolicyID changes the identity policy — the authority ceiling
	// for this identity. Pointer so callers can distinguish "not set" from
	// "clear to tenant default". A non-empty value must exist in the caller's
	// tenant; an empty string reassigns the tenant default.
	CredentialPolicyID *string
}

// UpdateIdentity updates mutable fields of an existing identity.
func (s *IdentityService) UpdateIdentity(ctx context.Context, id, accountID, projectID string, req UpdateIdentityRequest) (*domain.Identity, error) {
	identity, err := s.repo.GetByID(ctx, id, accountID, projectID)
	if err != nil {
		return nil, err
	}
	if req.Name != "" {
		identity.Name = req.Name
	}
	if req.TrustLevel != "" {
		identity.TrustLevel = req.TrustLevel
	}
	if req.IdentityType != "" {
		if !req.IdentityType.Valid() {
			return nil, fmt.Errorf("invalid identity_type: %s", req.IdentityType)
		}
		identity.IdentityType = req.IdentityType
	}
	if req.SubType != "" {
		if !req.SubType.ValidForIdentityType(identity.IdentityType) {
			return nil, fmt.Errorf("invalid sub_type: %s", req.SubType)
		}
		identity.SubType = req.SubType
	}
	if req.OwnerUserID != "" {
		identity.OwnerUserID = req.OwnerUserID
	}
	if req.AllowedScopes != nil {
		identity.AllowedScopes = req.AllowedScopes
	}
	if req.PublicKeyPEM != "" {
		if err := validateECPublicKeyPEM(req.PublicKeyPEM); err != nil {
			return nil, err
		}
		identity.PublicKeyPEM = req.PublicKeyPEM
	}
	if req.Framework != nil {
		identity.Framework = *req.Framework
	}
	if req.Version != nil {
		identity.Version = *req.Version
	}
	if req.Publisher != nil {
		identity.Publisher = *req.Publisher
	}
	if req.Description != nil {
		identity.Description = *req.Description
	}
	if req.Capabilities != nil {
		identity.Capabilities = req.Capabilities
	}
	if req.Labels != nil {
		identity.Labels = req.Labels
	}
	if req.Metadata != nil {
		identity.Metadata = req.Metadata
	}
	if req.Status != nil {
		if !identity.Status.CanTransitionTo(*req.Status) {
			return nil, fmt.Errorf("invalid status transition: %s → %s", identity.Status, *req.Status)
		}
		identity.Status = *req.Status
	}
	if req.CredentialPolicyID != nil {
		policyID, err := s.resolveIdentityPolicyID(ctx, identity.AccountID, identity.ProjectID, *req.CredentialPolicyID)
		if err != nil {
			return nil, err
		}
		identity.CredentialPolicyID = policyID
	}
	identity.UpdatedAt = time.Now()
	if err := s.repo.Update(ctx, identity); err != nil {
		return nil, err
	}
	return identity, nil
}

// EnsureServiceIdentity returns the service identity for a given external ID within a tenant,
// creating it if it doesn't exist. Used to guarantee every API key has an identity.
func (s *IdentityService) EnsureServiceIdentity(ctx context.Context, accountID, projectID, externalID, createdBy string) (*domain.Identity, error) {
	existing, err := s.repo.GetByExternalID(ctx, externalID, accountID, projectID)
	if err == nil && existing != nil {
		return existing, nil
	}

	identity, err := s.RegisterIdentity(ctx, RegisterIdentityRequest{
		AccountID:    accountID,
		ProjectID:    projectID,
		ExternalID:   externalID,
		Name:         externalID,
		IdentityType: domain.IdentityTypeService,
		OwnerUserID:  createdBy,
	})
	if err != nil {
		// Race condition — another request created it concurrently.
		if errors.Is(err, ErrIdentityAlreadyExists) {
			existing, err = s.repo.GetByExternalID(ctx, externalID, accountID, projectID)
			if err == nil && existing != nil {
				return existing, nil
			}
		}
		return nil, fmt.Errorf("failed to ensure service identity for %s: %w", externalID, err)
	}

	log.Info().
		Str("identity_id", identity.ID).
		Str("external_id", externalID).
		Str("account_id", accountID).
		Str("project_id", projectID).
		Msg("Service identity auto-created")

	return identity, nil
}

// DeleteIdentity permanently removes an identity and cascades to related records.
func (s *IdentityService) DeleteIdentity(ctx context.Context, id, accountID, projectID string) error {
	return s.repo.Delete(ctx, id, accountID, projectID)
}

// resolveIdentityPolicyID picks the policy to attach to an identity. When the
// caller supplies an explicit ID, it is validated against the tenant (IDOR
// guard via GetPolicy). When empty, the tenant's default policy is ensured
// and its ID is returned. Never returns an empty string on success.
func (s *IdentityService) resolveIdentityPolicyID(ctx context.Context, accountID, projectID, suppliedID string) (string, error) {
	if s.policySvc == nil {
		return "", fmt.Errorf("identity service is missing credential policy dependency")
	}
	if suppliedID == "" {
		p, err := s.policySvc.EnsureDefaultPolicy(ctx, accountID, projectID)
		if err != nil {
			return "", fmt.Errorf("failed to ensure default credential policy: %w", err)
		}
		return p.ID, nil
	}
	if _, err := s.policySvc.GetPolicy(ctx, suppliedID, accountID, projectID); err != nil {
		return "", fmt.Errorf("credential policy %s: %w", suppliedID, err)
	}
	return suppliedID, nil
}

// ResolveCredentialPolicy returns the credential policy that governs this
// identity. Callers use it as the authority ceiling for scope, TTL, grant
// type, delegation depth, trust level, and attestation checks.
//
// Dual-read: if the identity has a CredentialPolicyID the policy is
// returned directly. Legacy identities written before migration 008 may
// still have a NULL column; we lazily fall back to the tenant default in
// that case so the OAuth flows never observe a policy-less identity.
func (s *IdentityService) ResolveCredentialPolicy(ctx context.Context, identity *domain.Identity) (*domain.CredentialPolicy, error) {
	if s.policySvc == nil {
		return nil, fmt.Errorf("identity service is missing credential policy dependency")
	}
	if identity == nil {
		return nil, fmt.Errorf("nil identity")
	}
	if identity.CredentialPolicyID != "" {
		return s.policySvc.GetPolicy(ctx, identity.CredentialPolicyID, identity.AccountID, identity.ProjectID)
	}
	return s.policySvc.EnsureDefaultPolicy(ctx, identity.AccountID, identity.ProjectID)
}
