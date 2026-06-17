package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
	internalMiddleware "github.com/highflame-ai/zeroid/internal/middleware"
	"github.com/highflame-ai/zeroid/internal/service"
)

// ── Identity types ───────────────────────────────────────────────────────────

type CreateIdentityInput struct {
	Body struct {
		ExternalID         string          `json:"external_id" required:"true" minLength:"1" doc:"Unique identifier within this project"`
		Name               string          `json:"name,omitempty" doc:"Human-readable identity name"`
		TrustLevel         string          `json:"trust_level,omitempty" enum:"unverified,verified_third_party,first_party" doc:"Trust level"`
		IdentityType       string          `json:"identity_type,omitempty" enum:"agent,application,mcp_server,service" doc:"Identity type"`
		SubType            string          `json:"sub_type,omitempty" enum:"orchestrator,autonomous,tool_agent,human_proxy,evaluator,chatbot,assistant,api_service,custom,code_agent" doc:"Sub-type within identity type"`
		OwnerUserID        string          `json:"owner_user_id" required:"true" minLength:"1" doc:"User ID of the identity owner"`
		AllowedScopes      []string        `json:"allowed_scopes,omitempty" doc:"Deprecated: set scope ceiling on the identity's credential policy"`
		CredentialPolicyID string          `json:"credential_policy_id,omitempty" doc:"Identity policy — authority ceiling for this identity. Defaults to tenant default policy."`
		PublicKeyPEM       string          `json:"public_key_pem,omitempty" doc:"ECDSA P-256 public key in PEM format for jwt_bearer grant"`
		Framework          string          `json:"framework,omitempty" doc:"Agent framework (e.g. langchain, autogen, crewai)"`
		Version            string          `json:"version,omitempty" doc:"Agent version string"`
		Publisher          string          `json:"publisher,omitempty" doc:"Agent publisher or organization"`
		Description        string          `json:"description,omitempty" doc:"Human-readable description of the identity"`
		Capabilities       json.RawMessage `json:"capabilities,omitempty" doc:"JSON array of capabilities"`
		Labels             json.RawMessage `json:"labels,omitempty" doc:"JSON object of key-value labels"`
		// CoSAI §3.2 capability–risk classification + NIST SP 800-63 IAL.
		// Empty string is the default ("unclassified"); future default-policy
		// selection will key off these.
		CapabilityTier string `json:"capability_tier,omitempty" enum:"low,high" doc:"CoSAI §3.2 capability tier"`
		RiskTier       string `json:"risk_tier,omitempty" enum:"low,high" doc:"CoSAI §3.2 risk tier"`
		IAL            string `json:"ial,omitempty" enum:"ial1,ial2,ial3" doc:"NIST SP 800-63 Identity Assurance Level"`
		// ExpiresAt time-bounds the grant of authority. RFC3339. Omit for
		// no expiry (the historical default).
		ExpiresAt *time.Time `json:"expires_at,omitempty" doc:"RFC3339 timestamp after which the identity is auto-deactivated"`
	}
}

type IdentityOutput struct {
	Body *domain.Identity
}

type IdentityIDInput struct {
	ID string `path:"id" doc:"Identity UUID"`
}

// GetIdentityByWIMSEInput is the query for GET /identities/by-wimse.
// The URI is supplied as a query param (rather than a path segment) because
// SPIFFE URIs contain slashes that would conflict with route segmentation
// and the trust-domain host that wouldn't survive path encoding without
// loss-of-fidelity surprises.
type GetIdentityByWIMSEInput struct {
	URI string `query:"uri" required:"true" doc:"WIMSE/SPIFFE URI to resolve (e.g. spiffe://highflame.io/acme/prod/agent/claude-bot)"`
}

type ListIdentitiesInput struct {
	IdentityType  []string `query:"identity_type" doc:"Filter by identity type. Comma-separated for multiple (e.g. agent,application)."`
	Label         string   `query:"label" doc:"Filter by label (key:value, e.g. product:guardrails)"`
	TrustLevel    string   `query:"trust_level" doc:"Filter by trust level"`
	IsActive      string   `query:"is_active" doc:"Filter by active status"`
	Search        string   `query:"search" doc:"Search by name or external_id"`
	Metadata      string   `query:"metadata" doc:"Filter by metadata: \"key\" (key present) or \"key:value\" (containment), e.g. redteam_target"`
	IdentityClass string   `query:"identity_class" doc:"Filter by identity class: \"custom\" (user-created) or \"code_agent\" (auto-registered by hooks)"`
	Limit         int      `query:"limit" default:"20" doc:"Items per page (max 100)"`
	Offset        int      `query:"offset" default:"0" doc:"Offset for pagination"`
}

type IdentityListOutput struct {
	Body struct {
		Identities []*domain.Identity `json:"identities"`
		Total      int                `json:"total"`
		Limit      int                `json:"limit"`
		Offset     int                `json:"offset"`
	}
}

type UpdateIdentityInput struct {
	ID   string `path:"id" doc:"Identity UUID"`
	Body struct {
		Name               string          `json:"name,omitempty" doc:"Human-readable identity name"`
		TrustLevel         string          `json:"trust_level,omitempty" enum:"unverified,verified_third_party,first_party" doc:"Trust level"`
		IdentityType       string          `json:"identity_type,omitempty" enum:"agent,application,mcp_server,service" doc:"Identity type"`
		SubType            string          `json:"sub_type,omitempty" enum:"orchestrator,autonomous,tool_agent,human_proxy,evaluator,chatbot,assistant,api_service,custom,code_agent" doc:"Sub-type"`
		OwnerUserID        string          `json:"owner_user_id,omitempty" doc:"Owner user ID"`
		AllowedScopes      []string        `json:"allowed_scopes,omitempty" doc:"Deprecated: set scope ceiling on the identity's credential policy"`
		CredentialPolicyID *string         `json:"credential_policy_id,omitempty" doc:"Identity policy — authority ceiling. Empty string resets to tenant default; omit to leave unchanged."`
		PublicKeyPEM       string          `json:"public_key_pem,omitempty" doc:"ECDSA public key PEM"`
		Framework          *string         `json:"framework,omitempty" doc:"Agent framework"`
		Version            *string         `json:"version,omitempty" doc:"Agent version"`
		Publisher          *string         `json:"publisher,omitempty" doc:"Agent publisher"`
		Description        *string         `json:"description,omitempty" doc:"Agent description"`
		Capabilities       json.RawMessage `json:"capabilities,omitempty" doc:"Capabilities"`
		Labels             json.RawMessage `json:"labels,omitempty" doc:"Key-value labels"`
		Metadata           json.RawMessage `json:"metadata,omitempty" doc:"Product-specific metadata"`
		Status             *string         `json:"status,omitempty" enum:"active,suspended,deactivated" doc:"Identity status"`
		// CoSAI §3.2 + NIST SP 800-63. Pointer so callers can distinguish
		// "not set" (omit) from "clear to unclassified" (explicit "").
		CapabilityTier *string `json:"capability_tier,omitempty" enum:"low,high" doc:"CoSAI §3.2 capability tier"`
		RiskTier       *string `json:"risk_tier,omitempty" enum:"low,high" doc:"CoSAI §3.2 risk tier"`
		IAL            *string `json:"ial,omitempty" enum:"ial1,ial2,ial3" doc:"NIST SP 800-63 Identity Assurance Level"`
		// ExpiresAt tri-state: omit to leave unchanged, "" to clear (remove
		// expiry), RFC3339 timestamp to set. The "Extend access" flow PATCHes
		// a new RFC3339 value here.
		ExpiresAt *string `json:"expires_at,omitempty" doc:"RFC3339 expiry, or empty string to clear"`
	}
}

// ── Identity routes ──────────────────────────────────────────────────────────

func (a *API) registerIdentityRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "identity-schema",
		Method:      http.MethodGet,
		Path:        "/identities/schema",
		Summary:     "Get the identity type schema (valid types, sub-types, trust levels, statuses)",
		Tags:        []string{"Identities"},
	}, a.identitySchemaOp)

	huma.Register(api, huma.Operation{
		OperationID:   "create-identity",
		Method:        http.MethodPost,
		Path:          "/identities",
		Summary:       "Register a new identity",
		Tags:          []string{"Identities"},
		DefaultStatus: http.StatusCreated,
	}, a.createIdentityOp)

	// Registered before /identities/{id} so the literal `by-wimse` segment
	// is matched before falling into the {id} wildcard. chi handles this
	// fine in either order, but keeping the literal first makes the
	// precedence obvious from the registration order.
	huma.Register(api, huma.Operation{
		OperationID: "get-identity-by-wimse",
		Method:      http.MethodGet,
		Path:        "/identities/by-wimse",
		Summary:     "Resolve an identity by its WIMSE/SPIFFE URI",
		Description: "Lookup endpoint used by downstream gateways to verify a JWT's sub claim still resolves to an active identity row in the caller's tenant before forwarding the request.",
		Tags:        []string{"Identities"},
	}, a.getIdentityByWIMSEOp)

	huma.Register(api, huma.Operation{
		OperationID: "get-identity",
		Method:      http.MethodGet,
		Path:        "/identities/{id}",
		Summary:     "Get an identity by ID",
		Tags:        []string{"Identities"},
	}, a.getIdentityOp)

	huma.Register(api, huma.Operation{
		OperationID: "list-identities",
		Method:      http.MethodGet,
		Path:        "/identities",
		Summary:     "List all identities for the current tenant",
		Tags:        []string{"Identities"},
	}, a.listIdentitiesOp)

	huma.Register(api, huma.Operation{
		OperationID: "update-identity",
		Method:      http.MethodPatch,
		Path:        "/identities/{id}",
		Summary:     "Update mutable fields of an identity",
		Tags:        []string{"Identities"},
	}, a.updateIdentityOp)

	huma.Register(api, huma.Operation{
		OperationID: "delete-identity",
		Method:      http.MethodDelete,
		Path:        "/identities/{id}",
		Summary:     "Deactivate an identity (soft delete)",
		Description: "Soft-deletes the identity and returns the deactivated record. The published SDKs (highflame on PyPI, @highflame/sdk on npm) parse the response as an Identity, so this must stay 200 + body — a 204 breaks them.",
		Tags:        []string{"Identities"},
	}, a.deleteIdentityOp)
}

type IdentitySchemaOutput struct {
	Body *domain.IdentitySchema
}

func (a *API) identitySchemaOp(_ context.Context, _ *struct{}) (*IdentitySchemaOutput, error) {
	return &IdentitySchemaOutput{Body: domain.GetIdentitySchema()}, nil
}

func (a *API) createIdentityOp(ctx context.Context, input *CreateIdentityInput) (*IdentityOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	trustLevel := domain.TrustLevel(input.Body.TrustLevel)
	if trustLevel != "" && !trustLevel.Valid() {
		return nil, huma.Error400BadRequest("invalid trust_level: must be unverified, verified_third_party, or first_party")
	}

	identityType := domain.IdentityType(input.Body.IdentityType)
	if identityType != "" && !identityType.Valid() {
		return nil, huma.Error400BadRequest("invalid identity_type: must be agent, application, mcp_server, or service")
	}

	subType := domain.SubType(input.Body.SubType)
	if subType != "" && !subType.ValidForIdentityType(identityType) {
		return nil, huma.Error400BadRequest("invalid sub_type for the given identity_type")
	}

	createdBy := internalMiddleware.GetCallerName(ctx)

	identity, err := a.identitySvc.RegisterIdentity(ctx, service.RegisterIdentityRequest{
		AccountID:          tenant.AccountID,
		ProjectID:          tenant.ProjectID,
		ExternalID:         input.Body.ExternalID,
		Name:               input.Body.Name,
		TrustLevel:         trustLevel,
		IdentityType:       identityType,
		SubType:            subType,
		OwnerUserID:        input.Body.OwnerUserID,
		AllowedScopes:      input.Body.AllowedScopes,
		PublicKeyPEM:       input.Body.PublicKeyPEM,
		Framework:          input.Body.Framework,
		Version:            input.Body.Version,
		Publisher:          input.Body.Publisher,
		Description:        input.Body.Description,
		Capabilities:       input.Body.Capabilities,
		Labels:             input.Body.Labels,
		CreatedBy:          createdBy,
		CredentialPolicyID: input.Body.CredentialPolicyID,
		CapabilityTier:     input.Body.CapabilityTier,
		RiskTier:           input.Body.RiskTier,
		IAL:                input.Body.IAL,
		ExpiresAt:          input.Body.ExpiresAt,
	})
	if err != nil {
		// A collision with a soft-deleted identity is actionable — surface the
		// existing id so the caller can reactivate it instead of being stuck
		// behind an opaque 409 for a row hidden from the active registry view.
		var deactErr *service.IdentityDeactivatedConflictError
		if errors.As(err, &deactErr) {
			return nil, huma.Error409Conflict(deactErr.Error(), &huma.ErrorDetail{
				Message:  "reactivate the deactivated identity (PUT /identities/{id} with status=active) or register with a different external_id",
				Location: "body.external_id",
				Value:    deactErr.ExistingID,
			})
		}
		if errors.Is(err, service.ErrIdentityAlreadyExists) {
			return nil, huma.Error409Conflict("identity with this external_id already exists")
		}
		// Caller-supplied credential_policy_id that doesn't exist in this
		// tenant is a client error, not a server error.
		if errors.Is(err, service.ErrPolicyNotFound) {
			return nil, huma.Error400BadRequest("credential policy not found in this tenant")
		}
		// SPIFFE path-segment + risk/IAL enum validation failures are
		// caller-fixable. Service layer wraps both with ErrInvalidIdentityField.
		if errors.Is(err, service.ErrInvalidIdentityField) {
			return nil, huma.Error400BadRequest(err.Error())
		}
		log.Error().Err(err).Str("external_id", input.Body.ExternalID).Msg("failed to register identity")
		return nil, huma.Error500InternalServerError("failed to create identity")
	}

	return &IdentityOutput{Body: identity}, nil
}

func (a *API) getIdentityOp(ctx context.Context, input *IdentityIDInput) (*IdentityOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	identity, err := a.identitySvc.GetIdentity(ctx, input.ID, tenant.AccountID, tenant.ProjectID)
	if err != nil {
		return nil, huma.Error404NotFound("identity not found")
	}

	return &IdentityOutput{Body: identity}, nil
}

// getIdentityByWIMSEOp resolves an identity by its WIMSE/SPIFFE URI within
// the caller's tenant. Used by downstream gateways (firehog) to gate
// forwarding on identity status — a signature-valid, unexpired JWT for a
// deactivated identity must still be rejected, and only the identity row
// carries that signal.
//
// On 400 / 404 the body follows huma's RFC 9457 ProblemDetails shape with
// the failure code in `detail` ("invalid_wimse_uri" / "identity_not_found")
// and the offending URI echoed back in `errors[0].value` so callers can log
// it without round-tripping the query string.
func (a *API) getIdentityByWIMSEOp(ctx context.Context, input *GetIdentityByWIMSEInput) (*IdentityOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	if vErr := domain.ValidateWIMSEURI(input.URI); vErr != nil {
		return nil, huma.Error400BadRequest("invalid_wimse_uri", &huma.ErrorDetail{
			Message:  vErr.Error(),
			Location: "query.uri",
			Value:    input.URI,
		})
	}

	identity, err := a.identitySvc.GetIdentityByWIMSEURI(ctx, input.URI, tenant.AccountID, tenant.ProjectID)
	if err != nil {
		if errors.Is(err, service.ErrIdentityNotFound) {
			return nil, huma.Error404NotFound("identity_not_found", &huma.ErrorDetail{
				Message:  "no identity matches the supplied WIMSE URI in this tenant",
				Location: "query.uri",
				Value:    input.URI,
			})
		}
		log.Error().Err(err).Str("wimse_uri", input.URI).Msg("failed to resolve identity by wimse uri")
		return nil, huma.Error500InternalServerError("failed to resolve identity")
	}

	return &IdentityOutput{Body: identity}, nil
}

func (a *API) listIdentitiesOp(ctx context.Context, input *ListIdentitiesInput) (*IdentityListOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	limit := input.Limit
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	offset := max(input.Offset, 0)

	if input.IdentityClass != "" && input.IdentityClass != "custom" && input.IdentityClass != "code_agent" {
		return nil, huma.Error400BadRequest("invalid identity_class: must be custom or code_agent")
	}

	identities, total, err := a.identitySvc.ListIdentities(ctx, tenant.AccountID, tenant.ProjectID, input.IdentityType, input.Label, input.TrustLevel, input.IsActive, input.Search, input.Metadata, input.IdentityClass, limit, offset)
	if err != nil {
		log.Error().Err(err).Msg("failed to list identities")
		return nil, huma.Error500InternalServerError("failed to list identities")
	}

	if identities == nil {
		identities = []*domain.Identity{}
	}
	out := &IdentityListOutput{}
	out.Body.Identities = identities
	out.Body.Total = total
	out.Body.Limit = limit
	out.Body.Offset = offset
	return out, nil
}

func (a *API) updateIdentityOp(ctx context.Context, input *UpdateIdentityInput) (*IdentityOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	trustLevel := domain.TrustLevel(input.Body.TrustLevel)
	if trustLevel != "" && !trustLevel.Valid() {
		return nil, huma.Error400BadRequest("invalid trust_level")
	}
	identityType := domain.IdentityType(input.Body.IdentityType)
	if identityType != "" && !identityType.Valid() {
		return nil, huma.Error400BadRequest("invalid identity_type")
	}
	subType := domain.SubType(input.Body.SubType)
	if subType != "" && !subType.ValidForIdentityType(identityType) {
		return nil, huma.Error400BadRequest("invalid sub_type")
	}

	var status *domain.IdentityStatus
	if input.Body.Status != nil {
		s := domain.IdentityStatus(*input.Body.Status)
		if !s.Valid() {
			return nil, huma.Error400BadRequest("invalid status")
		}
		status = &s
	}

	identity, err := a.identitySvc.UpdateIdentity(ctx, input.ID, tenant.AccountID, tenant.ProjectID, service.UpdateIdentityRequest{
		Name:               input.Body.Name,
		TrustLevel:         trustLevel,
		IdentityType:       identityType,
		SubType:            subType,
		OwnerUserID:        input.Body.OwnerUserID,
		AllowedScopes:      input.Body.AllowedScopes,
		PublicKeyPEM:       input.Body.PublicKeyPEM,
		Framework:          input.Body.Framework,
		Version:            input.Body.Version,
		Publisher:          input.Body.Publisher,
		Description:        input.Body.Description,
		Capabilities:       input.Body.Capabilities,
		Labels:             input.Body.Labels,
		Metadata:           input.Body.Metadata,
		Status:             status,
		CredentialPolicyID: input.Body.CredentialPolicyID,
		CapabilityTier:     input.Body.CapabilityTier,
		RiskTier:           input.Body.RiskTier,
		IAL:                input.Body.IAL,
		ExpiresAt:          input.Body.ExpiresAt,
	})
	if err != nil {
		if errors.Is(err, service.ErrPolicyNotFound) {
			return nil, huma.Error400BadRequest("credential policy not found in this tenant")
		}
		// Field validation failures (SPIFFE path segments + risk/IAL enums)
		// are caller-fixable. Service layer wraps them with ErrInvalidIdentityField.
		if errors.Is(err, service.ErrInvalidIdentityField) {
			return nil, huma.Error400BadRequest(err.Error())
		}
		log.Error().Err(err).Str("identity_id", input.ID).Msg("failed to update identity")
		return nil, huma.Error500InternalServerError("failed to update identity")
	}

	return &IdentityOutput{Body: identity}, nil
}

func (a *API) deleteIdentityOp(ctx context.Context, input *IdentityIDInput) (*IdentityOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	// Soft delete: deactivate rather than hard-delete. Matches the route's
	// "Deactivate an identity (soft delete)" summary and the platform "never
	// hard DELETE" convention, and avoids the non-cascading service_keys FK
	// that 500s a hard delete on existing deployments (authn#109). mapErr
	// surfaces a missing identity as 404 rather than a blanket 500.
	identity, err := a.identitySvc.DeactivateIdentity(ctx, input.ID, tenant.AccountID, tenant.ProjectID)
	if err != nil {
		log.Error().Err(err).Str("identity_id", input.ID).Msg("failed to deactivate identity")
		return nil, mapErr(err)
	}

	return &IdentityOutput{Body: identity}, nil
}
