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
)

// ── DRM types ────────────────────────────────────────────────────────────────

type PublishDRMInput struct {
	Body struct {
		Version            string                        `json:"version" required:"true" doc:"Semver version string"`
		EffectiveAt        time.Time                     `json:"effective_at" required:"true" doc:"When this DRM becomes active"`
		ExpiresAt          *time.Time                    `json:"expires_at,omitempty" doc:"When this DRM stops being active (optional)"`
		AllowedDelegations []domain.DRMAllowedDelegation `json:"allowed_delegations" required:"true" minItems:"1" doc:"Permitted delegation rules"`
	}
}

type DRMOutput struct {
	Body *domain.DecisionRightsMatrix
}

type DRMListOutput struct {
	Body struct {
		DecisionRightsMatrix []*domain.DecisionRightsMatrix `json:"decision_rights_matrix"`
		Total                int                            `json:"total"`
	}
}

type DRMIDInput struct {
	ID string `path:"id" doc:"DRM row UUID"`
}

// ── Constraint Catalog types ─────────────────────────────────────────────────

type PublishCatalogInput struct {
	Body struct {
		Version     string          `json:"version" required:"true" doc:"Version identifier (e.g. ISO 8601 timestamp)"`
		EffectiveAt time.Time       `json:"effective_at" required:"true" doc:"When this catalog becomes active"`
		Document    json.RawMessage `json:"document" required:"true" doc:"Opaque policy document (ZeroID hashes + signs, does not parse)"`
	}
}

type CatalogOutput struct {
	Body *domain.ConstraintCatalogVersion
}

// ── Routes ───────────────────────────────────────────────────────────────────

func (a *API) registerGovernanceRoutes(api huma.API) {
	if a.governanceSvc == nil {
		// Governance binding is not configured for this deployment — skip
		// route registration so the OpenAPI surface only exposes the
		// endpoints that will actually work.
		return
	}

	huma.Register(api, huma.Operation{
		OperationID:   "publish-drm",
		Method:        http.MethodPost,
		Path:          "/governance/decision-rights-matrix",
		Summary:       "Publish a new Decision-Rights Matrix",
		Tags:          []string{"Governance"},
		DefaultStatus: http.StatusCreated,
	}, a.publishDRMOp)

	huma.Register(api, huma.Operation{
		OperationID: "get-active-drm",
		Method:      http.MethodGet,
		Path:        "/governance/decision-rights-matrix/active",
		Summary:     "Get the currently active DRM",
		Tags:        []string{"Governance"},
	}, a.getActiveDRMOp)

	huma.Register(api, huma.Operation{
		OperationID: "list-drm",
		Method:      http.MethodGet,
		Path:        "/governance/decision-rights-matrix",
		Summary:     "List DRM version history",
		Tags:        []string{"Governance"},
	}, a.listDRMOp)

	huma.Register(api, huma.Operation{
		OperationID:   "publish-constraint-catalog",
		Method:        http.MethodPost,
		Path:          "/governance/constraint-catalog",
		Summary:       "Publish a new Constraint Catalog version",
		Tags:          []string{"Governance"},
		DefaultStatus: http.StatusCreated,
	}, a.publishCatalogOp)

	huma.Register(api, huma.Operation{
		OperationID: "get-active-catalog",
		Method:      http.MethodGet,
		Path:        "/governance/constraint-catalog/active",
		Summary:     "Get the most recently signed Constraint Catalog row",
		Tags:        []string{"Governance"},
	}, a.getActiveCatalogOp)
}

func (a *API) publishDRMOp(ctx context.Context, input *PublishDRMInput) (*DRMOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}
	doc := domain.DRMDocument{
		Version:            input.Body.Version,
		EffectiveAt:        input.Body.EffectiveAt,
		ExpiresAt:          input.Body.ExpiresAt,
		AllowedDelegations: input.Body.AllowedDelegations,
	}
	row, err := a.governanceSvc.PublishDRM(ctx, tenant.AccountID, tenant.ProjectID, doc)
	if err != nil {
		if errors.Is(err, domain.ErrDRMInvalid) {
			return nil, huma.Error400BadRequest(err.Error())
		}
		log.Error().Err(err).Msg("publish DRM failed")
		return nil, huma.Error500InternalServerError("failed to publish DRM")
	}
	return &DRMOutput{Body: row}, nil
}

func (a *API) getActiveDRMOp(ctx context.Context, _ *struct{}) (*DRMOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}
	row, err := a.governanceSvc.GetActiveDRM(ctx, tenant.AccountID, tenant.ProjectID)
	if err != nil {
		return nil, huma.Error500InternalServerError("failed to get active DRM")
	}
	if row == nil {
		return nil, huma.Error404NotFound("no active DRM")
	}
	return &DRMOutput{Body: row}, nil
}

func (a *API) listDRMOp(ctx context.Context, _ *struct{}) (*DRMListOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}
	rows, err := a.governanceSvc.ListDRM(ctx, tenant.AccountID, tenant.ProjectID)
	if err != nil {
		return nil, huma.Error500InternalServerError("failed to list DRMs")
	}
	out := &DRMListOutput{}
	out.Body.DecisionRightsMatrix = rows
	out.Body.Total = len(rows)
	return out, nil
}

func (a *API) publishCatalogOp(ctx context.Context, input *PublishCatalogInput) (*CatalogOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}
	row, err := a.governanceSvc.PublishCatalog(ctx, tenant.AccountID, tenant.ProjectID, input.Body.Version, input.Body.EffectiveAt, input.Body.Document)
	if err != nil {
		log.Error().Err(err).Msg("publish catalog failed")
		return nil, huma.Error500InternalServerError("failed to publish catalog")
	}
	return &CatalogOutput{Body: row}, nil
}

func (a *API) getActiveCatalogOp(ctx context.Context, _ *struct{}) (*CatalogOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}
	row, err := a.governanceSvc.GetActiveCatalog(ctx, tenant.AccountID, tenant.ProjectID)
	if err != nil {
		return nil, huma.Error500InternalServerError("failed to get active catalog")
	}
	if row == nil {
		return nil, huma.Error404NotFound("no active catalog")
	}
	return &CatalogOutput{Body: row}, nil
}
