package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/middleware"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// AgentService handles agent registration (atomic identity + API key creation)
// and self-service actor-key enrollment/rotation.
type AgentService struct {
	identitySvc *IdentityService
	apiKeySvc   *APIKeyService
	apiKeyRepo  *postgres.APIKeyRepository
	// keyProofReplay records single-use jtis for actor-key-change proofs.
	keyProofReplay keyProofReplayGuard
	// issuer is this server's token issuer URL; the audience a self-service key
	// proof must target is derived from it (see keyProofAudience).
	issuer        string
	delegationSvc *DelegationService
}

// NewAgentService creates a new AgentService. keyProofReplay backs single-use
// enforcement of actor-key-change proofs; issuer is the token issuer URL used to
// derive the expected proof audience.
func NewAgentService(
	identitySvc *IdentityService,
	apiKeySvc *APIKeyService,
	apiKeyRepo *postgres.APIKeyRepository,
	keyProofReplay keyProofReplayGuard,
	issuer string,
	delegationSvc *DelegationService,
) *AgentService {
	return &AgentService{
		identitySvc:    identitySvc,
		apiKeySvc:      apiKeySvc,
		apiKeyRepo:     apiKeyRepo,
		keyProofReplay: keyProofReplay,
		issuer:         issuer,
		delegationSvc:  delegationSvc,
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
	// ExpiresAt time-bounds both the identity and (if non-nil) the auto-
	// created API key. Nil means "no expiry".
	ExpiresAt *time.Time
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
	Origin             domain.Origin         `json:"origin"`
	OwnerUserID        string                `json:"owner_user_id,omitempty"`
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
	DelegationDepth    int                   `json:"delegation_depth"`
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
	// Parents holds parent agents hydrated for sub-agents on this page whose parent
	// is not itself on the page, so a paginated caller can nest them. Context only
	// — NOT counted in Total/Limit/Offset.
	Parents []AgentResponse `json:"parents,omitempty"`
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
	// PublicKeyPEM, when non-nil, force-sets the identity's actor-assertion key.
	// This is the admin recovery path: it is reachable only on the secret-gated
	// management route (no proof-of-possession), so a tenant admin can replace a
	// key the agent can no longer prove control of. Self-service rotation (with
	// proof-of-possession) goes through SetPublicKey instead.
	PublicKeyPEM *string `json:"public_key_pem,omitempty"`
}

// SetPublicKeyRequest carries a self-service actor-key enrollment or rotation.
type SetPublicKeyRequest struct {
	// NewPublicKeyPEM is the SPKI EC P-256 public key to enroll.
	NewPublicKeyPEM string
	// NewKeyProof is a compact ES256 JWS signed by the NEW private key, proving
	// the caller controls the key being registered. Required for both first-set
	// and rotation.
	NewKeyProof string
	// CurrentKeyProof is a compact ES256 JWS signed by the identity's CURRENT
	// private key, authorizing the rotation (proof-of-possession, bound to the
	// new key). Required only when the identity already has a key; ignored on
	// first-set (trust-on-first-use).
	CurrentKeyProof string
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
		ExpiresAt:          req.ExpiresAt,
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
		ExpiresAt:          req.ExpiresAt,
	})
	if err != nil {
		// Compensating action — hard-purge the half-created identity if key
		// creation fails. Purge (not deactivate) is correct here: registration
		// did not complete, so no deactivated ghost should linger holding the
		// external_id. Safe against the service_keys FK because CreateKey
		// persists its row last — a failure never leaves a service key behind.
		_ = s.identitySvc.PurgeIdentity(ctx, identity.ID, req.AccountID, req.ProjectID)
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
	if s.delegationSvc != nil {
		depths, err := s.delegationSvc.IdentityDepths(ctx, []string{identity.ID}, accountID, projectID)
		if err != nil {
			log.Warn().Err(err).Str("identity_id", identity.ID).Msg("failed to fetch delegation depth for agent")
		} else if len(depths) > 0 {
			resp.DelegationDepth = depths[0].MaxDepth
		}
	}
	return &resp, nil
}

// ListAgents lists agents for a tenant, optionally filtered by identity_type(s),
// label, and metadata (key presence or key:value).
func (s *AgentService) ListAgents(ctx context.Context, accountID, projectID string, identityTypes []string, label string, trustLevels []string, isActive, search, metadata, identityClass, origin string, statuses []string, ownerUserID, ownerless string, limit, offset int, includeParents bool) (*AgentListResponse, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}

	// origin/status surface the unified native∪discovered inventory through the
	// agent registry list endpoint — the same filters the identities list exposes.
	identities, total, err := s.identitySvc.ListIdentities(ctx, accountID, projectID, identityTypes, label, trustLevels, isActive, search, metadata, identityClass, origin, statuses, ownerUserID, ownerless, limit, offset)
	if err != nil {
		return nil, err
	}

	// Batch-fetch delegation depths for all returned identities.
	identityIDs := make([]string, len(identities))
	for i, id := range identities {
		identityIDs[i] = id.ID
	}
	depthMap := make(map[string]int)
	if s.delegationSvc != nil && len(identityIDs) > 0 {
		depths, err := s.delegationSvc.IdentityDepths(ctx, identityIDs, accountID, projectID)
		if err != nil {
			log.Warn().Err(err).Msg("failed to fetch delegation depths, continuing without")
		} else {
			for _, d := range depths {
				depthMap[d.IdentityID] = d.MaxDepth
			}
		}
	}

	prefixes := s.keyPrefixesFor(ctx, identities)
	agents := make([]AgentResponse, len(identities))
	for i, id := range identities {
		agents[i] = identityToAgentResponse(id, prefixes[id.ID])
		agents[i].DelegationDepth = depthMap[id.ID]
	}

	var parents []AgentResponse
	if includeParents {
		parents = s.hydrateParents(ctx, accountID, projectID, identities)
	}

	return &AgentListResponse{
		Agents:  agents,
		Total:   total,
		Limit:   limit,
		Offset:  offset,
		Parents: parents,
	}, nil
}

// GetIdentityFacets returns grouped counts for each filterable identity dimension.
func (s *AgentService) GetIdentityFacets(ctx context.Context, accountID, projectID string) (*postgres.IdentityFacets, error) {
	return s.identitySvc.GetFacets(ctx, accountID, projectID)
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
		// Admin force-set of the actor key (admin recovery path) — validated and
		// applied in the same update (UpdateIdentity validates PublicKeyPEM when
		// non-empty). derefStr(nil) is "", which UpdateIdentity treats as "leave
		// unchanged". Only the secret-gated management route reaches UpdateAgent,
		// so this is authorized by admin authority with no proof-of-possession;
		// self-service rotation (with proofs) goes through SetPublicKey instead.
		PublicKeyPEM: derefStr(req.PublicKeyPEM),
	})
	if err != nil {
		return nil, err
	}

	keyPrefix := s.getKeyPrefix(ctx, identity.ID)
	resp := identityToAgentResponse(identity, keyPrefix)
	return &resp, nil
}

// keyProofAudience is the aud value a self-service actor-key proof must carry.
// Bound to the issuer + the public-key endpoint path so a proof minted for this
// operation cannot be replayed against a different audience.
func (s *AgentService) keyProofAudience() string {
	return s.issuer + "/agents/self/public-key"
}

// SetPublicKey enrolls or rotates the actor-assertion public key for the
// authenticated identity (self-service). identityID/accountID/projectID come
// from the agent's own access-token claims — never from caller-supplied input —
// so an agent can only set its own key.
//
//   - First-set (identity has no key): trust-on-first-use, authorized by the
//     agent's access token. NewKeyProof proves control of the new key.
//   - Rotation (identity already has a key): additionally requires
//     CurrentKeyProof — proof-of-possession of the current key, bound to the new
//     key (RFC 8555 §7.3.5), so a stolen access token alone (no current private
//     key) cannot rotate an enrolled key.
func (s *AgentService) SetPublicKey(ctx context.Context, identityID, accountID, projectID string, req SetPublicKeyRequest) (*AgentResponse, error) {
	if req.NewPublicKeyPEM == "" {
		return nil, fmt.Errorf("%w: new_public_key_pem is required", ErrInvalidIdentityField)
	}
	newKey, err := parseECPublicKeyPEM(req.NewPublicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("%w: new_public_key_pem: %v", ErrInvalidIdentityField, err)
	}
	if req.NewKeyProof == "" {
		return nil, fmt.Errorf("%w: new_key_proof is required", ErrKeyProofInvalid)
	}

	identity, err := s.identitySvc.GetIdentity(ctx, identityID, accountID, projectID)
	if err != nil {
		return nil, err
	}
	if !identity.Status.IsUsable() {
		return nil, fmt.Errorf("%w (status: %s)", domain.ErrIdentityNotUsable, identity.Status)
	}
	if identity.IsExpired() {
		return nil, fmt.Errorf("%w: identity %s", domain.ErrIdentityExpired, identity.ID)
	}

	aud := s.keyProofAudience()

	// Always prove control of the NEW key (prevents binding a key the caller
	// does not control).
	if err := verifyActorKeyProof(ctx, req.NewKeyProof, newKey, aud, identity.WIMSEURI, "", s.keyProofReplay); err != nil {
		return nil, fmt.Errorf("%w: new_key_proof: %v", ErrKeyProofInvalid, err)
	}

	// Rotation: an enrolled key may only be replaced by also proving possession
	// of the current key, bound to this specific new key.
	if identity.PublicKeyPEM != "" {
		if req.CurrentKeyProof == "" {
			return nil, fmt.Errorf("%w: current_key_proof is required to rotate an enrolled key", ErrKeyProofInvalid)
		}
		currentKey, err := parseECPublicKeyPEM(identity.PublicKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("stored public key is invalid: %w", err)
		}
		nkt, err := newKeyThumbprint(req.NewPublicKeyPEM)
		if err != nil {
			return nil, err
		}
		if err := verifyActorKeyProof(ctx, req.CurrentKeyProof, currentKey, aud, identity.WIMSEURI, nkt, s.keyProofReplay); err != nil {
			return nil, fmt.Errorf("%w: current_key_proof: %v", ErrKeyProofInvalid, err)
		}
	}

	updated, err := s.identitySvc.SetPublicKey(ctx, identityID, accountID, projectID, req.NewPublicKeyPEM)
	if err != nil {
		return nil, err
	}
	keyPrefix := s.getKeyPrefix(ctx, updated.ID)
	resp := identityToAgentResponse(updated, keyPrefix)
	return &resp, nil
}

// DeleteAgent soft-deletes an agent. DELETE on the registry deactivates the
// identity rather than issuing a hard DELETE — matching the endpoint's "soft
// delete" contract and the platform "never hard DELETE" convention.
// Deactivation sweeps the agent's API keys, cascade-revokes active
// credentials, and emits the retirement CAE signal (see DeactivateAgent /
// IdentityService.runDeactivationCleanup), so it is behaviourally the same as
// POST /agents/registry/{id}/deactivate.
//
// A hard delete here previously returned 500 for any agent that had a service
// key, because service_keys carries a non-cascading FK to identities on
// existing deployments (authn#109). Deactivation sidesteps that entirely and
// keeps the audit trail. Idempotent: deleting an already-deactivated agent is
// a no-op success (DeactivateIdentity short-circuits the status-transition
// guard).
func (s *AgentService) DeleteAgent(ctx context.Context, id, accountID, projectID string) (*AgentResponse, error) {
	identity, err := s.identitySvc.DeactivateIdentity(ctx, id, accountID, projectID)
	if err != nil {
		return nil, err
	}

	keyPrefix := s.getKeyPrefix(ctx, identity.ID)
	resp := identityToAgentResponse(identity, keyPrefix)

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

// DeactivateAgent disables an agent without deleting it. The underlying
// IdentityService.UpdateIdentity sweeps linked API keys, cascade-revokes
// active credentials, and emits a retirement CAE signal on any fresh
// transition into the deactivated status — so this endpoint, a direct
// PUT /identities/{id} with status=deactivated, and any programmatic
// caller all produce the same end state.
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

// RotateKey revokes the old key and creates a new one. Inherits the
// identity's expires_at so a rotated key on a time-bound agent expires
// alongside its parent — without this, rotation silently extends the
// key's lifetime past the agent's authority window.
//
// The new key also inherits a human in CreatedBy, because the api_key
// grant copies that field into the token's act.sub (see oauth.go's
// apiKeyGrant, ActingUserID: sk.CreatedBy). Rotation changes the secret,
// not who is accountable, so stamping the rotation subsystem there
// severed the human→agent audit chain for the rotated credential and
// every identity delegated from it (#281). See rotationAttribution for
// which human the new key names, and why it is not the operator who
// performed the rotation.
func (s *AgentService) RotateKey(ctx context.Context, id, accountID, projectID string) (*AgentRegistrationResponse, error) {
	identity, err := s.identitySvc.GetIdentity(ctx, id, accountID, projectID)
	if err != nil {
		return nil, err
	}
	if !identity.Status.IsUsable() {
		return nil, fmt.Errorf("%w (status: %s)", domain.ErrIdentityNotUsable, identity.Status)
	}
	if identity.IsExpired() {
		return nil, fmt.Errorf("%w: identity %s expired at %s", domain.ErrIdentityExpired, identity.ID, identity.ExpiresAt.Format(time.RFC3339))
	}

	// Revoke existing keys.
	s.revokeKeysByIdentity(ctx, identity.ID)

	createdBy := rotationAttribution(identity, middleware.GetCallerName(ctx))

	// Create new key. ExpiresAt propagates from the identity so the
	// rotated key inherits the parent's time-bound window.
	skResp, err := s.apiKeySvc.CreateKey(ctx, CreateAPIKeyRequest{
		AccountID:  identity.AccountID,
		ProjectID:  identity.ProjectID,
		CreatedBy:  createdBy,
		Name:       fmt.Sprintf("Agent: %s", identity.Name),
		IdentityID: identity.ID,
		ExpiresAt:  identity.ExpiresAt,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create rotated key: %w", err)
	}

	log.Info().
		Str("external_id", identity.ExternalID).
		Str("identity_id", identity.ID).
		Str("created_by", createdBy).
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
		Origin:             identity.Origin,
		OwnerUserID:        identity.OwnerUserID,
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

// agentMeta is the subset of an agent's opaque metadata this service reads to
// resolve agent → sub-agent hierarchy: a sub-agent points at its parent agent via
// the parent_external_id key.
type agentMeta struct {
	ParentExternalID string `json:"parent_external_id"`
}

// hydrateParents returns the parent agents of any sub-agents in page whose parent
// is not itself on the page — an agent is treated as a sub-agent when its metadata
// carries a parent_external_id. It walks the ancestor chain so nested sub-agents
// also resolve. Parents are fetched by external_id regardless of status/filter, so
// a sub-agent whose parent is on another page — or filtered out (e.g. deactivated)
// — can still be nested under it by a paginated caller.
func (s *AgentService) hydrateParents(ctx context.Context, accountID, projectID string, page []*domain.Identity) []AgentResponse {
	present := make(map[string]bool, len(page))
	for _, id := range page {
		present[id.ExternalID] = true
	}

	missing := missingParentExternalIDs(page, present)
	var hydrated []AgentResponse

	// Ancestor chains are shallow; cap rounds so a pathological/cyclic
	// parent_external_id can never loop forever.
	const maxRounds = 8
	for round := 0; round < maxRounds && len(missing) > 0; round++ {
		fetched, err := s.identitySvc.ListByExternalIDs(ctx, accountID, projectID, missing)
		if err != nil {
			log.Warn().Err(err).Msg("failed to hydrate parent agents, continuing without")

			break
		}
		if len(fetched) == 0 {
			break
		}
		prefixes := s.keyPrefixesFor(ctx, fetched)
		for _, id := range fetched {
			present[id.ExternalID] = true
			hydrated = append(hydrated, identityToAgentResponse(id, prefixes[id.ID]))
		}
		missing = missingParentExternalIDs(fetched, present)
	}

	return hydrated
}

// missingParentExternalIDs collects the distinct parent_external_id of every
// sub-agent in ids (an agent whose metadata sets parent_external_id) whose parent
// is not already in present.
func missingParentExternalIDs(ids []*domain.Identity, present map[string]bool) []string {
	seen := make(map[string]bool)

	var out []string

	for _, id := range ids {
		if len(id.Metadata) == 0 {
			continue
		}

		var meta agentMeta
		if err := json.Unmarshal(id.Metadata, &meta); err != nil {
			continue
		}
		if meta.ParentExternalID == "" {
			continue
		}
		if present[meta.ParentExternalID] || seen[meta.ParentExternalID] {
			continue
		}

		seen[meta.ParentExternalID] = true
		out = append(out, meta.ParentExternalID)
	}

	return out
}

// keyPrefixesFor returns identity ID → active API-key prefix for a batch of
// identities in one query — the batched form of getKeyPrefix. Identities
// without an active key (or the whole batch, on a lookup error) are absent
// from the map, yielding the same "" a getKeyPrefix miss produces.
func (s *AgentService) keyPrefixesFor(ctx context.Context, identities []*domain.Identity) map[string]string {
	ids := make([]string, len(identities))
	for i, id := range identities {
		ids[i] = id.ID
	}
	keys, err := s.apiKeyRepo.ListActiveByIdentityIDs(ctx, ids)
	if err != nil {
		log.Warn().Err(err).Msg("failed to batch-fetch API key prefixes, continuing without")
		return nil
	}
	prefixes := make(map[string]string, len(keys))
	for _, k := range keys {
		prefixes[k.IdentityID] = k.KeyPrefix
	}
	return prefixes
}

func (s *AgentService) getKeyPrefix(ctx context.Context, identityID string) string {
	sk, err := s.apiKeyRepo.GetActiveByIdentityID(ctx, identityID)
	if err != nil {
		return ""
	}
	return sk.KeyPrefix
}

// maxAttributionLen bounds a human identifier written to service_keys.created_by,
// which is VARCHAR(255) (migrations/006_service_keys.up.sql). RotateKey revokes
// the outgoing keys BEFORE it creates the replacement, so an over-long value
// would fail the INSERT and leave the identity with no usable key at all. A
// caller-supplied header must never be able to reach that state.
const maxAttributionLen = 255

// usableHuman returns v as an attribution value, or "" when v cannot serve as
// one. It rejects, rather than repairs, three shapes:
//
//   - padded or blank. A padded id matches nothing stored unpadded, so it is a
//     silent audit break rather than a near-miss. IdentityService.OffboardOwner
//     rejects the same shape for the same reason.
//   - the reserved system: prefix, in any case. TenantContextMiddleware already
//     drops this from X-User-ID, but identity.OwnerUserID and identity.CreatedBy
//     reach us from columns that no write path filters — POST /agents/register
//     takes created_by straight from the request body. Filtering at the point of
//     use covers every source, not just the HTTP header.
//   - longer than the destination column.
//
// Rejecting falls through to the next source in rotationAttribution, so a
// malformed value degrades attribution instead of failing the rotation.
func usableHuman(v string) string {
	if v == "" || strings.TrimSpace(v) != v {
		return ""
	}
	if len(v) > maxAttributionLen {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(v), middleware.SystemCallerPrefix) {
		return ""
	}
	return v
}

// rotationAttribution picks the human that a rotated API key names in
// CreatedBy, which the api_key grant copies into the token's act.sub.
//
// Precedence, and why the rotation operator is not first:
//
//  1. identity.OwnerUserID — the human accountable for what this agent does.
//     act.sub means "the end user the principal acts on behalf of"
//     (IssueRequest.ActingUserID), and the key mints tokens for the whole of
//     its remaining life. An SRE who rotates a key after a leak scare is not
//     who the agent subsequently acts for, and naming them would leave every
//     token disagreeing with its own owner_user_id claim — a divergence that
//     never occurs for a freshly registered agent, where RegisterAgent sets
//     both from one value.
//  2. identity.CreatedBy — the same fallback the identity store already uses
//     to answer "who is the human for this identity"
//     (COALESCE(NULLIF(owner_user_id, ”), created_by), see the created_by
//     facet in store/postgres/identity.go). Covers rows predating the
//     ownership invariant, and deployer-imported rows.
//  3. callerName — a human performed this rotation and the row names nobody.
//     Better than a subsystem, and the last human available.
//  4. The system principal. Nothing names a human, and saying so is the
//     honest answer.
//
// The operator is not lost by ranking them third: RotateKey logs created_by,
// and identity_audit_logs records the X-User-ID caller separately from the
// identity's owner (migrations/010_identity_audit_logs.up.sql). Who performed
// the action and who the credential acts for are different questions, and
// service_keys.created_by answers only the second.
func rotationAttribution(identity *domain.Identity, callerName string) string {
	for _, candidate := range []string{identity.OwnerUserID, identity.CreatedBy, callerName} {
		if v := usableHuman(candidate); v != "" {
			return v
		}
	}
	return middleware.SystemCallerPrefix + "key_rotation"
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
