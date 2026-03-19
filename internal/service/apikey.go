package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// APIKeyService handles CRUD operations for API keys (zid_sk_* keys).
type APIKeyService struct {
	repo                *postgres.APIKeyRepository
	credentialPolicySvc *CredentialPolicyService
	identitySvc         *IdentityService
}

// NewAPIKeyService creates a new APIKeyService.
func NewAPIKeyService(repo *postgres.APIKeyRepository, credentialPolicySvc *CredentialPolicyService, identitySvc *IdentityService) *APIKeyService {
	return &APIKeyService{
		repo:                repo,
		credentialPolicySvc: credentialPolicySvc,
		identitySvc:         identitySvc,
	}
}

// CreateAPIKeyRequest holds the parameters for creating a new API key.
type CreateAPIKeyRequest struct {
	AccountID          string
	ProjectID          string
	CreatedBy          string
	Name               string
	Description        string
	IdentityID         string
	CredentialPolicyID string // Optional — if empty, the tenant's default policy is assigned.
	Scopes             []string
	Environment        string
	ExpiresInDays      *int
	Metadata           json.RawMessage
}

// CreateAPIKeyResponse is returned once on creation — contains the full key (shown once).
type CreateAPIKeyResponse struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	FullKey     string     `json:"key"`
	KeyPrefix   string     `json:"key_prefix"`
	Environment string     `json:"environment"`
	Scopes      []string   `json:"scopes"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// CreateKey generates a new API key, hashes it, stores the hash, and returns the full key once.
// Every key is linked to an identity and assigned a credential policy.
// If IdentityID is empty, no identity link is set.
// If CredentialPolicyID is empty, the tenant's default policy is auto-created and assigned.
func (s *APIKeyService) CreateKey(ctx context.Context, req CreateAPIKeyRequest) (*CreateAPIKeyResponse, error) {
	// Ensure the key has a credential policy.
	policyID := req.CredentialPolicyID
	if policyID == "" {
		defaultPolicy, err := s.credentialPolicySvc.EnsureDefaultPolicy(ctx, req.AccountID, req.ProjectID)
		if err != nil {
			return nil, fmt.Errorf("failed to ensure default credential policy: %w", err)
		}
		policyID = defaultPolicy.ID
	}

	rawKey, keyHash, displayPrefix, err := generateAPIKey(domain.APIKeyPrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	env := "live"
	if req.Environment != "" {
		env = req.Environment
	}

	var expiresAt *time.Time
	if req.ExpiresInDays != nil && *req.ExpiresInDays > 0 {
		t := time.Now().AddDate(0, 0, *req.ExpiresInDays)
		expiresAt = &t
	}

	scopes := req.Scopes
	if scopes == nil {
		scopes = []string{}
	}

	metadata := req.Metadata
	if metadata == nil {
		metadata = json.RawMessage("{}")
	}

	sk := &domain.APIKey{
		ID:                 uuid.New().String(),
		Name:               req.Name,
		Description:        req.Description,
		KeyPrefix:          displayPrefix,
		KeyHash:            keyHash,
		KeyVersion:         1,
		AccountID:          req.AccountID,
		ProjectID:          req.ProjectID,
		IdentityID:         req.IdentityID,
		CreatedBy:          req.CreatedBy,
		CredentialPolicyID: policyID,
		Scopes:             scopes,
		Environment:        env,
		ExpiresAt:          expiresAt,
		State:              domain.APIKeyStateActive,
		Metadata:           metadata,
	}

	if err := s.repo.Create(ctx, sk); err != nil {
		return nil, fmt.Errorf("failed to store API key: %w", err)
	}

	log.Info().
		Str("key_id", sk.ID).
		Str("account_id", sk.AccountID).
		Str("project_id", sk.ProjectID).
		Msg("API key created")

	return &CreateAPIKeyResponse{
		ID:          sk.ID,
		Name:        sk.Name,
		Description: sk.Description,
		FullKey:     rawKey,
		KeyPrefix:   displayPrefix,
		Environment: env,
		Scopes:      scopes,
		ExpiresAt:   expiresAt,
		CreatedAt:   sk.CreatedAt,
	}, nil
}

// ListKeys returns paginated API keys for an account/project.
func (s *APIKeyService) ListKeys(ctx context.Context, accountID, projectID, applicationID, product string, page, limit int) ([]*domain.APIKey, int, error) {
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 20
	}
	offset := (page - 1) * limit

	return s.repo.ListByAccountProject(ctx, accountID, projectID, applicationID, product, limit, offset)
}

// GetKey returns an API key by ID.
func (s *APIKeyService) GetKey(ctx context.Context, id string) (*domain.APIKey, error) {
	return s.repo.GetByID(ctx, id)
}

// RevokeKey revokes an API key by ID.
func (s *APIKeyService) RevokeKey(ctx context.Context, id, revokedBy, reason string) error {
	return s.repo.Revoke(ctx, id, revokedBy, reason)
}

// generateAPIKey creates a cryptographically random API key with the given prefix.
// Format: <prefix>_<base64url(24 random bytes)>
func generateAPIKey(prefix string) (rawKey string, keyHash string, displayPrefix string, err error) {
	b := make([]byte, domain.APIKeyByteLength)
	if _, err := rand.Read(b); err != nil {
		return "", "", "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	rawKey = prefix + "_" + base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(rawKey))
	keyHash = hex.EncodeToString(h[:])

	displayPrefix = rawKey
	if len(rawKey) > 16 {
		displayPrefix = rawKey[:16]
	}

	return rawKey, keyHash, displayPrefix, nil
}
