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
	identitySvc   *IdentityService
	apiKeySvc     *APIKeyService
	apiKeyRepo    *postgres.APIKeyRepository
	credentialSvc *CredentialService
	signalSvc     *SignalService
}

// NewAgentService creates a new AgentService.
func NewAgentService(
	identitySvc *IdentityService,
	apiKeySvc *APIKeyService,
	apiKeyRepo *postgres.APIKeyRepository,
	credentialSvc *CredentialService,
	signalSvc *SignalService,
) *AgentService {
	return &AgentService{
		identitySvc:   identitySvc,
		apiKeySvc:     apiKeySvc,
		apiKeyRepo:    apiKeyRepo,
		credentialSvc: credentialSvc,
		signalSvc:     signalSvc,
	}
}

// RegisterAgentRequest holds the parameters for registering a new identity.
type RegisterAgentRequest struct {
	AccountID     string
	ProjectID     string
	Name          string
	ExternalID    string
	IdentityType  domain.IdentityType // Defaults to "agent" if empty.
	SubType       domain.SubType
	TrustLevel    domain.TrustLevel
	Framework     string
	Version       string
	Publisher     string
	Description   string
	Capabilities  json.RawMessage
	Labels        json.RawMessage
	Metadata      json.RawMessage
	AllowedScopes []string // Deprecated: set scope ceiling on the identity's credential policy.
	CreatedBy     string
	PublicKeyPEM  string
	// CredentialPolicyID is the identity policy — the authority ceiling for
	// the new identity. Also applied to the auto-created API key unless
	// APIKeyCredentialPolicyID is provided. Must exist in the caller's
	// tenant. If empty, the tenant default policy is assigned.
	CredentialPolicyID string
	// APIKeyCredentialPolicyID optionally scopes the auto-created API key
	// to a narrower policy than the identity's. Must be a subset of the
	// identity policy on every axis (scopes, TTL, grant types, delegation
	// depth, trust level, attestation); the subset invariant is enforced
	// inside APIKeyService.CreateKey. When empty, the API key inherits the
	// identity policy verbatim (common case).
	APIKeyCredentialPolicyID string
}

// AgentResponse is the API response for a single agent identity.
type AgentResponse struct {
	ID                 string                `json:"id"`
	AccountID          string                `json:"account_id"`
	ProjectID          string                `json:"project_id"`
	Name               string                `json:"name"`
	ExternalID         string                `json:"external_id"`
	WIMSEURI           string                `json:"wimse_uri"`
	APIKeyPrefix       string                `json:"api_key_prefix"`
	IdentityType       domain.IdentityType   `json:"identity_type"`
	SubType            domain.SubType        `json:"sub_type"`
	TrustLevel         domain.TrustLevel     `json:"trust_level"`
	Status             domain.IdentityStatus `json:"status"`
	CredentialPolicyID string                `json:"credential_policy_id,omitempty"`
	Framework          string                `json:"framework"`
	Version            string                `json:"version"`
	Publisher          string                `json:"publisher"`
	Description        string                `json:"description"`
	Capabilities       json.RawMessage       `json:"capabilities"`
	Labels             json.RawMessage       `json:"labels"`
	Metadata           json.RawMessage       `json:"metadata"`
	CreatedAt          time.Time             `json:"created_at"`
	CreatedBy          string                `json:"created_by"`
	UpdatedAt          time.Time             `json:"updated_at"`
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

	// 1. Create identity. CredentialPolicyID is the identity policy —
	// attached at registration so the authority ceiling is fixed before
	// any credential is issued for this identity.
	identity, err := s.identitySvc.RegisterIdentity(ctx, RegisterIdentityRequest{
		AccountID:          req.AccountID,
		ProjectID:          req.ProjectID,
		ExternalID:         req.ExternalID,
		Name:               req.Name,
		TrustLevel:         req.TrustLevel,
		IdentityType:       identityType,
		SubType:            req.SubType,
		OwnerUserID:        req.CreatedBy,
		Framework:          req.Framework,
		Version:            req.Version,
		Publisher:          req.Publisher,
		Description:        req.Description,
		Capabilities:       req.Capabilities,
		Labels:             req.Labels,
		Metadata:           req.Metadata,
		AllowedScopes:      req.AllowedScopes,
		CreatedBy:          req.CreatedBy,
		PublicKeyPEM:       req.PublicKeyPEM,
		CredentialPolicyID: req.CredentialPolicyID,
	})
	if err != nil {
		return nil, err
	}

	// 2. Create linked API key. Defaults to inheriting the identity policy;
	// the caller may supply a narrower APIKeyCredentialPolicyID to scope the
	// bootstrap key tighter than the identity ceiling. The subset invariant
	// is enforced inside CreateKey — broader-than-identity policies are
	// rejected with ErrPolicySubsetViolation.
	apiKeyPolicyID := req.APIKeyCredentialPolicyID
	if apiKeyPolicyID == "" {
		apiKeyPolicyID = req.CredentialPolicyID
	}
	skResp, err := s.apiKeySvc.CreateKey(ctx, CreateAPIKeyRequest{
		AccountID:          req.AccountID,
		ProjectID:          req.ProjectID,
		CreatedBy:          req.CreatedBy,
		Name:               fmt.Sprintf("Agent: %s", req.Name),
		IdentityID:         identity.ID,
		CredentialPolicyID: apiKeyPolicyID,
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
		APIKey:   skResp.FullKey,
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

// DeactivateAgent disables an agent without deleting it. Flips the identity's
// status AND fully stops any further token use:
//
//   - revokes every linked API key (so the api_key grant rejects the key);
//   - revokes every active issued credential, cascading to delegated
//     descendants via the parent_jti chain (so tokens already in flight
//     become inactive on next introspection);
//   - emits a high-severity CAE retirement signal so federated subscribers
//     (edge gateways, external SIEM, CAE-aware relying parties) pick up the
//     deactivation in near real time rather than on their next introspection.
//
// Each of these is best-effort: a failure on one step is logged and the
// method continues. The status flip is the authoritative outcome; the
// secondary revocations make the effect visible quickly rather than waiting
// for TTL expiry. The issuance paths also gate on identity.Status.IsUsable(),
// so new token requests are blocked regardless of whether these cleanup
// steps succeed.
func (s *AgentService) DeactivateAgent(ctx context.Context, id, accountID, projectID string) (*AgentResponse, error) {
	status := domain.IdentityStatusDeactivated
	identity, err := s.identitySvc.UpdateIdentity(ctx, id, accountID, projectID, UpdateIdentityRequest{
		Status: &status,
	})
	if err != nil {
		return nil, err
	}

	// Revoke linked API keys so the api_key grant stops accepting them.
	if err := s.apiKeyRepo.RevokeByIdentityID(ctx, identity.ID); err != nil {
		log.Warn().Err(err).Str("identity_id", identity.ID).Msg("deactivate: failed to revoke linked API keys")
	}

	// Revoke active issued credentials (cascades to delegated descendants).
	if s.credentialSvc != nil {
		if n, err := s.credentialSvc.RevokeAllActiveForIdentity(ctx, identity.ID, "identity_deactivated"); err != nil {
			log.Warn().Err(err).Str("identity_id", identity.ID).Msg("deactivate: failed to revoke active credentials")
		} else if n > 0 {
			log.Info().Str("identity_id", identity.ID).Int64("count", n).Msg("deactivate: revoked active credentials (cascade)")
		}
	}

	// Emit CAE signal so federated subscribers pick up the deactivation.
	if s.signalSvc != nil {
		_, err := s.signalSvc.IngestSignal(
			ctx,
			accountID,
			projectID,
			identity.ID,
			domain.SignalTypeRetirement,
			domain.SignalSeverityHigh,
			"agent_deactivation",
			map[string]any{"reason": "identity_deactivated"},
		)
		if err != nil {
			log.Warn().Err(err).Str("identity_id", identity.ID).Msg("deactivate: failed to emit CAE signal")
		}
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
		APIKey:   skResp.FullKey,
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
		ID:                 identity.ID,
		AccountID:          identity.AccountID,
		ProjectID:          identity.ProjectID,
		Name:               identity.Name,
		ExternalID:         identity.ExternalID,
		WIMSEURI:           identity.WIMSEURI,
		APIKeyPrefix:       keyPrefix,
		IdentityType:       identity.IdentityType,
		SubType:            identity.SubType,
		TrustLevel:         identity.TrustLevel,
		Status:             identity.Status,
		CredentialPolicyID: identity.CredentialPolicyID,
		Framework:          identity.Framework,
		Version:            identity.Version,
		Publisher:          identity.Publisher,
		Description:        identity.Description,
		Capabilities:       caps,
		Labels:             labels,
		Metadata:           metadata,
		CreatedAt:          identity.CreatedAt,
		CreatedBy:          identity.CreatedBy,
		UpdatedAt:          identity.UpdatedAt,
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
