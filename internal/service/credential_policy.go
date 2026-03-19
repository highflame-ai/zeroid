package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// ErrPolicyNotFound is returned when a credential policy does not exist.
var ErrPolicyNotFound = errors.New("credential policy not found")

// ErrPolicyViolation is returned when a credential issuance request violates the policy.
var ErrPolicyViolation = errors.New("credential policy violation")

// ErrPolicyNameConflict is returned when a policy with the same name already exists in the tenant.
var ErrPolicyNameConflict = errors.New("credential policy with this name already exists")

// CredentialPolicyService handles credential policy lifecycle and enforcement.
type CredentialPolicyService struct {
	repo *postgres.CredentialPolicyRepository
}

// NewCredentialPolicyService creates a new CredentialPolicyService.
func NewCredentialPolicyService(repo *postgres.CredentialPolicyRepository) *CredentialPolicyService {
	return &CredentialPolicyService{repo: repo}
}

// EnsureDefaultPolicy returns the tenant's default credential policy, creating it if it doesn't exist.
// This is called during agent registration to guarantee every agent has a policy from day one.
func (s *CredentialPolicyService) EnsureDefaultPolicy(ctx context.Context, accountID, projectID string) (*domain.CredentialPolicy, error) {
	existing, err := s.repo.GetDefaultByTenant(ctx, accountID, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to check for default policy: %w", err)
	}
	if existing != nil {
		return existing, nil
	}

	// Create the tenant's default policy with sensible production defaults.
	policy, err := s.CreatePolicy(ctx, CreatePolicyRequest{
		AccountID:          accountID,
		ProjectID:          projectID,
		Name:               domain.DefaultPolicyName,
		Description:        domain.DefaultPolicyDescription,
		MaxTTLSeconds:      domain.DefaultMaxTTLSeconds,
		AllowedGrantTypes:  domain.DefaultAllowedGrantTypes(),
		MaxDelegationDepth: domain.DefaultMaxDelegationDepth,
	})
	if err != nil {
		// Handle race condition — another request may have created it concurrently.
		if errors.Is(err, ErrPolicyNameConflict) {
			existing, err = s.repo.GetDefaultByTenant(ctx, accountID, projectID)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve concurrently-created default policy: %w", err)
			}
			if existing != nil {
				return existing, nil
			}
		}
		return nil, fmt.Errorf("failed to create default credential policy: %w", err)
	}

	log.Info().
		Str("policy_id", policy.ID).
		Str("account_id", accountID).
		Str("project_id", projectID).
		Msg("Default credential policy created for tenant")

	return policy, nil
}

// CreatePolicyRequest holds parameters for creating a credential policy.
type CreatePolicyRequest struct {
	AccountID           string
	ProjectID           string
	Name                string
	Description         string
	MaxTTLSeconds       int
	AllowedGrantTypes   []string
	AllowedScopes       []string
	RequiredTrustLevel  string
	RequiredAttestation string
	MaxDelegationDepth  int
}

// CreatePolicy creates a new credential policy.
func (s *CredentialPolicyService) CreatePolicy(ctx context.Context, req CreatePolicyRequest) (*domain.CredentialPolicy, error) {
	if req.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if req.MaxTTLSeconds <= 0 {
		req.MaxTTLSeconds = 3600
	}
	if len(req.AllowedGrantTypes) == 0 {
		req.AllowedGrantTypes = []string{"client_credentials"}
	}
	// Normalize URN grant types to canonical short forms before validation and storage.
	req.AllowedGrantTypes = normalizeGrantTypes(req.AllowedGrantTypes)
	for _, gt := range req.AllowedGrantTypes {
		if !isValidGrantType(gt) {
			return nil, fmt.Errorf("invalid grant type: %s", gt)
		}
	}
	if req.RequiredTrustLevel != "" && domain.TrustLevelRank(req.RequiredTrustLevel) < 0 {
		return nil, fmt.Errorf("invalid required_trust_level: %s", req.RequiredTrustLevel)
	}
	if req.RequiredAttestation != "" && !domain.AttestationLevel(req.RequiredAttestation).Valid() {
		return nil, fmt.Errorf("invalid required_attestation: %s", req.RequiredAttestation)
	}

	policy := &domain.CredentialPolicy{
		ID:                  uuid.New().String(),
		AccountID:           req.AccountID,
		ProjectID:           req.ProjectID,
		Name:                req.Name,
		Description:         req.Description,
		MaxTTLSeconds:       req.MaxTTLSeconds,
		AllowedGrantTypes:   req.AllowedGrantTypes,
		AllowedScopes:       req.AllowedScopes,
		RequiredTrustLevel:  req.RequiredTrustLevel,
		RequiredAttestation: req.RequiredAttestation,
		MaxDelegationDepth:  req.MaxDelegationDepth,
		IsActive:            true,
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
	}

	if err := s.repo.Create(ctx, policy); err != nil {
		if isDuplicateKeyError(err) {
			return nil, ErrPolicyNameConflict
		}
		return nil, fmt.Errorf("failed to create credential policy: %w", err)
	}

	log.Info().
		Str("policy_id", policy.ID).
		Str("name", policy.Name).
		Int("max_ttl", policy.MaxTTLSeconds).
		Msg("Credential policy created")

	return policy, nil
}

// GetPolicy retrieves a credential policy by ID.
func (s *CredentialPolicyService) GetPolicy(ctx context.Context, id, accountID, projectID string) (*domain.CredentialPolicy, error) {
	policy, err := s.repo.GetByID(ctx, id, accountID, projectID)
	if err != nil {
		return nil, ErrPolicyNotFound
	}
	return policy, nil
}

// ListPolicies returns all credential policies for a tenant.
func (s *CredentialPolicyService) ListPolicies(ctx context.Context, accountID, projectID string) ([]*domain.CredentialPolicy, error) {
	return s.repo.List(ctx, accountID, projectID)
}

// UpdatePolicyRequest holds parameters for updating a credential policy.
type UpdatePolicyRequest struct {
	Name                string
	Description         *string
	MaxTTLSeconds       *int
	AllowedGrantTypes   []string
	AllowedScopes       []string
	RequiredTrustLevel  *string
	RequiredAttestation *string
	MaxDelegationDepth  *int
	IsActive            *bool
}

// UpdatePolicy updates mutable fields of an existing credential policy.
func (s *CredentialPolicyService) UpdatePolicy(ctx context.Context, id, accountID, projectID string, req UpdatePolicyRequest) (*domain.CredentialPolicy, error) {
	policy, err := s.repo.GetByID(ctx, id, accountID, projectID)
	if err != nil {
		return nil, ErrPolicyNotFound
	}

	if req.Name != "" {
		policy.Name = req.Name
	}
	if req.Description != nil {
		policy.Description = *req.Description
	}
	if req.MaxTTLSeconds != nil {
		if *req.MaxTTLSeconds <= 0 {
			return nil, fmt.Errorf("max_ttl_seconds must be positive")
		}
		policy.MaxTTLSeconds = *req.MaxTTLSeconds
	}
	if req.AllowedGrantTypes != nil {
		normalized := normalizeGrantTypes(req.AllowedGrantTypes)
		for _, gt := range normalized {
			if !isValidGrantType(gt) {
				return nil, fmt.Errorf("invalid grant type: %s", gt)
			}
		}
		policy.AllowedGrantTypes = normalized
	}
	if req.AllowedScopes != nil {
		policy.AllowedScopes = req.AllowedScopes
	}
	if req.RequiredTrustLevel != nil {
		if *req.RequiredTrustLevel != "" && domain.TrustLevelRank(*req.RequiredTrustLevel) < 0 {
			return nil, fmt.Errorf("invalid required_trust_level: %s", *req.RequiredTrustLevel)
		}
		policy.RequiredTrustLevel = *req.RequiredTrustLevel
	}
	if req.RequiredAttestation != nil {
		if *req.RequiredAttestation != "" && !domain.AttestationLevel(*req.RequiredAttestation).Valid() {
			return nil, fmt.Errorf("invalid required_attestation: %s", *req.RequiredAttestation)
		}
		policy.RequiredAttestation = *req.RequiredAttestation
	}
	if req.MaxDelegationDepth != nil {
		policy.MaxDelegationDepth = *req.MaxDelegationDepth
	}
	if req.IsActive != nil {
		policy.IsActive = *req.IsActive
	}

	policy.UpdatedAt = time.Now()
	if err := s.repo.Update(ctx, policy); err != nil {
		return nil, err
	}

	return policy, nil
}

// DeletePolicy deletes a credential policy if no identities reference it.
func (s *CredentialPolicyService) DeletePolicy(ctx context.Context, id, accountID, projectID string) error {
	return s.repo.Delete(ctx, id, accountID, projectID)
}

// EnforcePolicy checks all six credential policy constraints against an issuance request.
// Returns nil if the request passes all checks or if no policy is assigned.
func (s *CredentialPolicyService) EnforcePolicy(ctx context.Context, policy *domain.CredentialPolicy, req EnforcePolicyRequest) error {
	if policy == nil {
		return nil
	}
	if !policy.IsActive {
		return fmt.Errorf("%w: policy %q is inactive", ErrPolicyViolation, policy.Name)
	}

	// 1. TTL <= policy.max_ttl_seconds
	if req.TTL > policy.MaxTTLSeconds {
		return fmt.Errorf("%w: requested TTL %ds exceeds policy maximum %ds", ErrPolicyViolation, req.TTL, policy.MaxTTLSeconds)
	}

	// 2. Grant type in policy.allowed_grant_types (normalize for comparison)
	normalizedGT := string(domain.NormalizeGrantType(string(req.GrantType)))
	if !containsString(policy.AllowedGrantTypes, normalizedGT) {
		return fmt.Errorf("%w: grant type %q is not permitted by policy (allowed: %v)", ErrPolicyViolation, req.GrantType, policy.AllowedGrantTypes)
	}

	// 3. Scopes subset of policy.allowed_scopes (if policy defines scope restrictions)
	if len(policy.AllowedScopes) > 0 && len(req.Scopes) > 0 {
		policyScopes := make(map[string]bool, len(policy.AllowedScopes))
		for _, s := range policy.AllowedScopes {
			policyScopes[s] = true
		}
		for _, requested := range req.Scopes {
			if !policyScopes[requested] {
				return fmt.Errorf("%w: scope %q is not permitted by policy", ErrPolicyViolation, requested)
			}
		}
	}

	// 4. Trust level >= policy.required_trust_level
	if policy.RequiredTrustLevel != "" {
		requiredRank := domain.TrustLevelRank(policy.RequiredTrustLevel)
		actualRank := domain.TrustLevelRank(string(req.TrustLevel))
		if actualRank < requiredRank {
			return fmt.Errorf("%w: identity trust level %q does not meet required level %q", ErrPolicyViolation, req.TrustLevel, policy.RequiredTrustLevel)
		}
	}

	// 5. Attestation level >= policy.required_attestation
	if policy.RequiredAttestation != "" {
		requiredRank := attestationLevelRank(policy.RequiredAttestation)
		actualRank := attestationLevelRank(req.AttestationLevel)
		if actualRank < requiredRank {
			return fmt.Errorf("%w: attestation level %q does not meet required level %q", ErrPolicyViolation, req.AttestationLevel, policy.RequiredAttestation)
		}
	}

	// 6. Delegation depth <= policy.max_delegation_depth
	if req.DelegationDepth > policy.MaxDelegationDepth {
		return fmt.Errorf("%w: delegation depth %d exceeds policy maximum %d", ErrPolicyViolation, req.DelegationDepth, policy.MaxDelegationDepth)
	}

	return nil
}

// EnforcePolicyRequest holds the parameters checked against a credential policy.
type EnforcePolicyRequest struct {
	TTL              int
	GrantType        domain.GrantType
	Scopes           []string
	TrustLevel       domain.TrustLevel
	AttestationLevel string
	DelegationDepth  int
}

// attestationLevelRank returns a numeric rank for attestation levels.
// Higher rank = stronger attestation.
func attestationLevelRank(level string) int {
	switch domain.AttestationLevel(level) {
	case domain.AttestationLevelSoftware:
		return 1
	case domain.AttestationLevelPlatform:
		return 2
	case domain.AttestationLevelHardware:
		return 3
	default:
		return 0 // no attestation
	}
}

func isValidGrantType(gt string) bool {
	return domain.IsValidGrantType(gt)
}

// normalizeGrantTypes converts all grant types to their canonical short forms
// so that both URN and short forms are stored consistently.
func normalizeGrantTypes(gts []string) []string {
	out := make([]string, len(gts))
	for i, gt := range gts {
		out[i] = string(domain.NormalizeGrantType(gt))
	}
	return out
}

func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
