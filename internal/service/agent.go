package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// AgentService handles agent registration (atomic identity + API key creation).
type AgentService struct {
	identitySvc *IdentityService
	apiKeySvc   *APIKeyService
	apiKeyRepo  *postgres.APIKeyRepository
}

// NewAgentService creates a new AgentService.
func NewAgentService(identitySvc *IdentityService, apiKeySvc *APIKeyService, apiKeyRepo *postgres.APIKeyRepository) *AgentService {
	return &AgentService{
		identitySvc: identitySvc,
		apiKeySvc:   apiKeySvc,
		apiKeyRepo:  apiKeyRepo,
	}
}

// RegisterAgentRequest holds the parameters for registering a new identity.
type RegisterAgentRequest struct {
	AccountID    string
	ProjectID    string
	Name         string
	ExternalID   string
	IdentityType domain.IdentityType // Defaults to "agent" if empty.
	SubType      domain.SubType
	TrustLevel   domain.TrustLevel
	Framework    string
	Version      string
	Publisher    string
	Description  string
	Capabilities json.RawMessage
	Labels       json.RawMessage
	Metadata     json.RawMessage
	CreatedBy    string
	PublicKeyPEM string
}

// AgentResponse is the API response for a single agent identity.
type AgentResponse struct {
	ID           string                `json:"id"`
	AccountID    string                `json:"account_id"`
	ProjectID    string                `json:"project_id"`
	Name         string                `json:"name"`
	ExternalID   string                `json:"external_id"`
	WIMSEURI     string                `json:"wimse_uri"`
	APIKeyPrefix string                `json:"api_key_prefix"`
	IdentityType domain.IdentityType   `json:"identity_type"`
	SubType      domain.SubType        `json:"sub_type"`
	TrustLevel   domain.TrustLevel     `json:"trust_level"`
	Status       domain.IdentityStatus `json:"status"`
	Framework    string                `json:"framework"`
	Version      string                `json:"version"`
	Publisher    string                `json:"publisher"`
	Description  string                `json:"description"`
	Capabilities json.RawMessage       `json:"capabilities"`
	Labels       json.RawMessage       `json:"labels"`
	Metadata     json.RawMessage       `json:"metadata"`
	CreatedAt    time.Time             `json:"created_at"`
	CreatedBy    string                `json:"created_by"`
	UpdatedAt    time.Time             `json:"updated_at"`
}

// AgentRegistrationResponse is returned on agent creation — includes plaintext API key.
type AgentRegistrationResponse struct {
	Identity AgentResponse `json:"identity"`
	APIKey   string        `json:"api_key"`
}

// AgentListResponse is the paginated list response.
type AgentListResponse struct {
	Agents []AgentResponse `json:"agents"`
	Total  int             `json:"total"`
	Limit  int             `json:"limit"`
	Offset int             `json:"offset"`
}

// UpdateAgentRequest holds PATCH fields for updating an agent.
type UpdateAgentRequest struct {
	Name         *string         `json:"name,omitempty"`
	SubType      *string         `json:"sub_type,omitempty"`
	TrustLevel   *string         `json:"trust_level,omitempty"`
	Framework    *string         `json:"framework,omitempty"`
	Version      *string         `json:"version,omitempty"`
	Publisher    *string         `json:"publisher,omitempty"`
	Description  *string         `json:"description,omitempty"`
	Capabilities json.RawMessage `json:"capabilities,omitempty"`
	Labels       json.RawMessage `json:"labels,omitempty"`
	Metadata     json.RawMessage `json:"metadata,omitempty"`
	Status       *string         `json:"status,omitempty"`
}

// RegisterAgent atomically creates an identity and linked API key.
func (s *AgentService) RegisterAgent(ctx context.Context, req RegisterAgentRequest) (*AgentRegistrationResponse, error) {
	// Default identity_type to agent if not specified.
	identityType := req.IdentityType
	if identityType == "" {
		identityType = domain.IdentityTypeAgent
	}

	// 1. Create identity.
	identity, err := s.identitySvc.RegisterIdentity(ctx, RegisterIdentityRequest{
		AccountID:    req.AccountID,
		ProjectID:    req.ProjectID,
		ExternalID:   req.ExternalID,
		Name:         req.Name,
		TrustLevel:   req.TrustLevel,
		IdentityType: identityType,
		SubType:      req.SubType,
		OwnerUserID:  req.CreatedBy,
		Framework:    req.Framework,
		Version:      req.Version,
		Publisher:    req.Publisher,
		Description:  req.Description,
		Capabilities: req.Capabilities,
		Labels:       req.Labels,
		Metadata:     req.Metadata,
		CreatedBy:    req.CreatedBy,
		PublicKeyPEM: req.PublicKeyPEM,
	})
	if err != nil {
		return nil, err
	}

	// 2. Create linked API key.
	skResp, err := s.apiKeySvc.CreateKey(ctx, CreateAPIKeyRequest{
		AccountID:  req.AccountID,
		ProjectID:  req.ProjectID,
		CreatedBy:  req.CreatedBy,
		Name:       fmt.Sprintf("Agent: %s", req.Name),
		IdentityID: identity.ID,
	})
	if err != nil {
		// Compensating action — deactivate the identity if key creation fails.
		_ = s.identitySvc.DeleteIdentity(ctx, identity.ID, req.AccountID, req.ProjectID)
		return nil, fmt.Errorf("failed to create API key: %w", err)
	}

	log.Info().
		Str("external_id", req.ExternalID).
		Str("identity_id", identity.ID).
		Str("name", req.Name).
		Msg("Agent registered with API key")

	return &AgentRegistrationResponse{
		Identity: identityToAgentResponse(identity, skResp.KeyPrefix),
		APIKey: skResp.FullKey,
	}, nil
}

// GetAgent retrieves an agent by identity ID with tenant scoping.
func (s *AgentService) GetAgent(ctx context.Context, id, accountID, projectID string) (*AgentResponse, error) {
	identity, err := s.identitySvc.GetIdentity(ctx, id, accountID, projectID)
	if err != nil {
		return nil, err
	}

	keyPrefix := s.getKeyPrefix(ctx, identity.ID)
	resp := identityToAgentResponse(identity, keyPrefix)
	return &resp, nil
}

// ListAgents lists agents for a tenant, optionally filtered by identity_type(s) and label.
func (s *AgentService) ListAgents(ctx context.Context, accountID, projectID string, identityTypes []string, label, trustLevel, isActive, search string, limit, offset int) (*AgentListResponse, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}

	identities, total, err := s.identitySvc.ListIdentities(ctx, accountID, projectID, identityTypes, label, trustLevel, isActive, search, limit, offset)
	if err != nil {
		return nil, err
	}

	agents := make([]AgentResponse, len(identities))
	for i, id := range identities {
		keyPrefix := s.getKeyPrefix(ctx, id.ID)
		agents[i] = identityToAgentResponse(id, keyPrefix)
	}

	return &AgentListResponse{
		Agents: agents,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	}, nil
}

// UpdateAgent updates an agent identity with PATCH semantics.
func (s *AgentService) UpdateAgent(ctx context.Context, id, accountID, projectID string, req UpdateAgentRequest) (*AgentResponse, error) {
	var subType domain.SubType
	if req.SubType != nil {
		subType = domain.SubType(*req.SubType)
	}
	var trustLevel domain.TrustLevel
	if req.TrustLevel != nil {
		trustLevel = domain.TrustLevel(*req.TrustLevel)
	}

	var status *domain.IdentityStatus
	if req.Status != nil {
		s := domain.IdentityStatus(*req.Status)
		status = &s
	}

	identity, err := s.identitySvc.UpdateIdentity(ctx, id, accountID, projectID, UpdateIdentityRequest{
		Name:         derefStr(req.Name),
		SubType:      subType,
		TrustLevel:   trustLevel,
		Framework:    req.Framework,
		Version:      req.Version,
		Publisher:    req.Publisher,
		Description:  req.Description,
		Capabilities: req.Capabilities,
		Labels:       req.Labels,
		Metadata:     req.Metadata,
		Status:       status,
	})
	if err != nil {
		return nil, err
	}

	keyPrefix := s.getKeyPrefix(ctx, identity.ID)
	resp := identityToAgentResponse(identity, keyPrefix)
	return &resp, nil
}

// DeleteAgent deactivates an agent and revokes its keys.
func (s *AgentService) DeleteAgent(ctx context.Context, id, accountID, projectID string) (*AgentResponse, error) {
	identity, err := s.identitySvc.GetIdentity(ctx, id, accountID, projectID)
	if err != nil {
		return nil, err
	}

	// Hard delete — cascades to api_keys, credentials, etc. via FK ON DELETE CASCADE.
	if err := s.identitySvc.DeleteIdentity(ctx, id, accountID, projectID); err != nil {
		return nil, err
	}

	resp := identityToAgentResponse(identity, "")
	return &resp, nil
}

// ActivateAgent enables a previously deactivated agent.
func (s *AgentService) ActivateAgent(ctx context.Context, id, accountID, projectID string) (*AgentResponse, error) {
	status := domain.IdentityStatusActive
	identity, err := s.identitySvc.UpdateIdentity(ctx, id, accountID, projectID, UpdateIdentityRequest{
		Status: &status,
	})
	if err != nil {
		return nil, err
	}

	keyPrefix := s.getKeyPrefix(ctx, identity.ID)
	resp := identityToAgentResponse(identity, keyPrefix)
	return &resp, nil
}

// DeactivateAgent disables an agent without deleting it.
func (s *AgentService) DeactivateAgent(ctx context.Context, id, accountID, projectID string) (*AgentResponse, error) {
	status := domain.IdentityStatusDeactivated
	identity, err := s.identitySvc.UpdateIdentity(ctx, id, accountID, projectID, UpdateIdentityRequest{
		Status: &status,
	})
	if err != nil {
		return nil, err
	}

	keyPrefix := s.getKeyPrefix(ctx, identity.ID)
	resp := identityToAgentResponse(identity, keyPrefix)
	return &resp, nil
}

// RotateKey revokes the old key and creates a new one.
func (s *AgentService) RotateKey(ctx context.Context, id, accountID, projectID string) (*AgentRegistrationResponse, error) {
	identity, err := s.identitySvc.GetIdentity(ctx, id, accountID, projectID)
	if err != nil {
		return nil, err
	}

	// Revoke existing keys.
	s.revokeKeysByIdentity(ctx, identity.ID)

	// Create new key.
	skResp, err := s.apiKeySvc.CreateKey(ctx, CreateAPIKeyRequest{
		AccountID:  identity.AccountID,
		ProjectID:  identity.ProjectID,
		CreatedBy:  "system:key_rotation",
		Name:       fmt.Sprintf("Agent: %s", identity.Name),
		IdentityID: identity.ID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create rotated key: %w", err)
	}

	log.Info().
		Str("external_id", identity.ExternalID).
		Str("identity_id", identity.ID).
		Msg("Agent API key rotated")

	return &AgentRegistrationResponse{
		Identity: identityToAgentResponse(identity, skResp.KeyPrefix),
		APIKey: skResp.FullKey,
	}, nil
}

// -- helpers --

func identityToAgentResponse(identity *domain.Identity, keyPrefix string) AgentResponse {
	caps := identity.Capabilities
	if caps == nil || string(caps) == "null" {
		caps = json.RawMessage("[]")
	}
	labels := identity.Labels
	if labels == nil || string(labels) == "null" {
		labels = json.RawMessage("{}")
	}
	metadata := identity.Metadata
	if metadata == nil || string(metadata) == "null" {
		metadata = json.RawMessage("{}")
	}

	return AgentResponse{
		ID:           identity.ID,
		AccountID:    identity.AccountID,
		ProjectID:    identity.ProjectID,
		Name:         identity.Name,
		ExternalID:   identity.ExternalID,
		WIMSEURI:     identity.WIMSEURI,
		APIKeyPrefix: keyPrefix,
		IdentityType: identity.IdentityType,
		SubType:      identity.SubType,
		TrustLevel:   identity.TrustLevel,
		Status:       identity.Status,
		Framework:    identity.Framework,
		Version:      identity.Version,
		Publisher:    identity.Publisher,
		Description:  identity.Description,
		Capabilities: caps,
		Labels:       labels,
		Metadata:     metadata,
		CreatedAt:    identity.CreatedAt,
		CreatedBy:    identity.CreatedBy,
		UpdatedAt:    identity.UpdatedAt,
	}
}

func (s *AgentService) getKeyPrefix(ctx context.Context, identityID string) string {
	sk, err := s.apiKeyRepo.GetActiveByIdentityID(ctx, identityID)
	if err != nil {
		return ""
	}
	return sk.KeyPrefix
}

func (s *AgentService) revokeKeysByIdentity(ctx context.Context, identityID string) {
	if err := s.apiKeyRepo.RevokeByIdentityID(ctx, identityID); err != nil {
		log.Warn().Err(err).Str("identity_id", identityID).Msg("Failed to revoke keys for identity")
	}
}

func derefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
