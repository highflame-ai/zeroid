package handler

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/rs/zerolog/log"

	internalMiddleware "github.com/highflame-ai/zeroid/internal/middleware"
	"github.com/highflame-ai/zeroid/internal/service"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// ── Delegation types ─────────────────────────────────────────────────────────

type DelegationGraphInput struct {
	IdentityID string `query:"identity_id" required:"true" pattern:"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$" doc:"Identity UUID to center the graph on"`
	Depth      int    `query:"depth"       default:"3" minimum:"1" maximum:"10" doc:"Hops from the focal credential in each direction"`
}

type DelegationGraphOutput struct {
	Body *service.Graph
}

type DelegationByJTIInput struct {
	JTI string `path:"jti" pattern:"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$" doc:"JWT ID of the credential to walk up to root"`
}

type DelegationChainOutput struct {
	Body *service.Chain
}

type DelegationChainsInput struct {
	Since time.Time `query:"since" doc:"Lower bound on issued_at (RFC3339); defaults to until-30d"`
	Until time.Time `query:"until" doc:"Upper bound on issued_at (RFC3339); defaults to now"`
	Limit int       `query:"limit" default:"50" minimum:"1" maximum:"500" doc:"Maximum number of chains to return"`
}

type DelegationChainsOutput struct {
	Body struct {
		Chains []*postgres.ChainSummary `json:"chains"`
		Total  int                      `json:"total"`
	}
}

// ── Delegation routes ────────────────────────────────────────────────────────

func (a *API) registerDelegationRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "delegation-graph",
		Method:      http.MethodGet,
		Path:        "/delegations/graph",
		Summary:     "Depth-bounded delegation subgraph centered on an identity",
		Description: "Returns nodes (identities) and edges (issued credentials) within `depth` hops up and down the parent_jti chain from the identity's most recent credential. Edges carry scope-attenuation (scopes_in / scopes_out / attenuated) so consumers can flag misconfigured delegations visually.",
		Tags:        []string{"Delegations"},
	}, a.delegationGraphOp)

	huma.Register(api, huma.Operation{
		OperationID: "delegation-by-jti",
		Method:      http.MethodGet,
		Path:        "/delegations/by-jti/{jti}",
		Summary:     "Walk the parent_jti chain from a credential up to its root",
		Description: "Returns the full lineage from the root credential to the credential identified by `jti`, with scope attenuation per edge. Used for forensic 'where did this token come from?' queries.",
		Tags:        []string{"Delegations"},
	}, a.delegationByJTIOp)

	huma.Register(api, huma.Operation{
		OperationID: "delegation-chains",
		Method:      http.MethodGet,
		Path:        "/delegations/chains",
		Summary:     "List delegation chain summaries in a time window",
		Description: "Returns one summary row per delegation tree (grouped by mission_id, falling back to root JTI for legacy credentials), ordered by last activity DESC. Defaults to the last 30 days.",
		Tags:        []string{"Delegations"},
	}, a.delegationChainsOp)
}

func (a *API) delegationGraphOp(ctx context.Context, input *DelegationGraphInput) (*DelegationGraphOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	g, err := a.delegationSvc.GetGraph(ctx, input.IdentityID, input.Depth, tenant.AccountID, tenant.ProjectID)
	if err != nil {
		log.Error().Err(err).
			Str("identity_id", input.IdentityID).
			Int("depth", input.Depth).
			Msg("failed to build delegation graph")
		return nil, huma.Error500InternalServerError("failed to build delegation graph")
	}
	return &DelegationGraphOutput{Body: g}, nil
}

func (a *API) delegationByJTIOp(ctx context.Context, input *DelegationByJTIInput) (*DelegationChainOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	chain, err := a.delegationSvc.WalkByJTI(ctx, input.JTI, tenant.AccountID, tenant.ProjectID)
	if err != nil {
		if errors.Is(err, service.ErrCredentialNotFound) {
			return nil, huma.Error404NotFound("credential not found")
		}
		log.Error().Err(err).Str("jti", input.JTI).Msg("delegation by-jti failed")
		return nil, huma.Error500InternalServerError("failed to walk delegation chain")
	}
	return &DelegationChainOutput{Body: chain}, nil
}

func (a *API) delegationChainsOp(ctx context.Context, input *DelegationChainsInput) (*DelegationChainsOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	chains, err := a.delegationSvc.ListChains(ctx, input.Since, input.Until, input.Limit, tenant.AccountID, tenant.ProjectID)
	if err != nil {
		log.Error().Err(err).Msg("failed to list delegation chains")
		return nil, huma.Error500InternalServerError("failed to list delegation chains")
	}

	out := &DelegationChainsOutput{}
	out.Body.Chains = chains
	out.Body.Total = len(chains)
	return out, nil
}
