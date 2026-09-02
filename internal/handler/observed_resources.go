package handler

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	internalMiddleware "github.com/highflame-ai/zeroid/internal/middleware"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// ObservedResourcesOutput is the tenant's observed-MCP-server inventory.
type ObservedResourcesOutput struct {
	Body struct {
		ObservedResources []postgres.ObservedIDJAGResource `json:"observed_resources"`
	}
}

// registerObservedResourceRoutes mounts the read side of the observed-MCP-server
// inventory (zeroid#259).
//
// Read-only by construction: entries are learned from successful ID-JAG
// redemptions, never declared. There is deliberately no write endpoint — a
// caller-supplied entry would be an assertion about infrastructure rather than
// evidence of it, which is the whole reason this signal is worth more than a
// name heuristic or a registry lookup.
func (a *API) registerObservedResourceRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "list-observed-resources",
		Method:      http.MethodGet,
		Path:        "/ema/observed-resources",
		Summary:     "List the MCP servers this tenant's agents have reached via ID-JAG",
		Description: "Every successful ID-JAG redemption names its target MCP server in the RFC 8707 " +
			"`resource` claim, and ZeroID audience-restricts the minted token to it. This returns the " +
			"distinct resources observed for the calling tenant — an inventory of MCP servers actually " +
			"in use, including private ones no public registry knows about.",
		Tags: []string{"EMA"},
	}, a.listObservedResourcesOp)
}

func (a *API) listObservedResourcesOp(ctx context.Context, _ *struct{}) (*ObservedResourcesOutput, error) {
	// Tenant comes from the validated request context, never from a parameter.
	// This is an inventory of a customer's internal infrastructure, so a
	// cross-tenant read here is worse than leaking the deployer-configured issuer
	// list — there is no filter argument to get wrong because there is no filter
	// argument.
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	resources, err := postgres.NewObservedIDJAGResourceStore(a.db).
		List(ctx, tenant.AccountID, tenant.ProjectID)
	if err != nil {
		return nil, mapErr(err)
	}

	out := &ObservedResourcesOutput{}
	// Serialize as [] rather than null for an empty inventory: a tenant with no
	// ID-JAG traffic yet is a normal state, and consumers shouldn't have to
	// null-guard it.
	out.Body.ObservedResources = resources
	return out, nil
}
