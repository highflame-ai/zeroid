package handler

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
	internalMiddleware "github.com/highflame-ai/zeroid/internal/middleware"
	"github.com/highflame-ai/zeroid/internal/service"
)

// ── Tenant settings types ────────────────────────────────────────────────────

// UpdateTenantSettingsInput is the request body for changing a tenant's
// settings. The tenant itself always comes from the authenticated context,
// never from the body (INV-IDN-002).
type UpdateTenantSettingsInput struct {
	Body struct {
		TokenProfile string `json:"token_profile" required:"true" enum:"legacy,rfc8693" doc:"Claim shape the tenant's new tokens are issued in. legacy keeps today's shape; rfc8693 issues the RFC 8693 delegation shape (sub is the principal for the whole chain, act nests the actors). Already-issued tokens keep their shape until they expire."`
	}
}

// TenantSettingsOutput returns the tenant's effective settings, with defaults
// filled in for a tenant that has never changed one.
type TenantSettingsOutput struct {
	Body *domain.TenantSettings
}

// UpdateTenantSettingsOutput is the update response: the stored settings, and
// how many long-lived user access tokens a switch to rfc8693 revoked.
type UpdateTenantSettingsOutput struct {
	Body struct {
		*domain.TenantSettings
		RevokedLongLivedTokens int `json:"revoked_long_lived_tokens" doc:"Credentials revoked because they were user-subject access tokens longer-lived than the short default, which the rfc8693 profile does not keep. Always 0 when setting legacy."`
	}
}

// ── Tenant settings routes ───────────────────────────────────────────────────

func (a *API) registerTenantSettingsRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "get-tenant-settings",
		Method:      http.MethodGet,
		Path:        "/tenant-settings",
		Summary:     "Get the current tenant's settings",
		Tags:        []string{"Tenant Settings"},
	}, a.getTenantSettingsOp)
	huma.Register(api, huma.Operation{
		OperationID:   "update-tenant-settings",
		Method:        http.MethodPut,
		Path:          "/tenant-settings",
		Summary:       "Update the current tenant's settings",
		Description:   "Sets the tenant's token profile. The switch applies to tokens issued from this point on; tokens already issued keep their shape until they expire.",
		Tags:          []string{"Tenant Settings"},
		DefaultStatus: http.StatusOK,
	}, a.updateTenantSettingsOp)
}

func (a *API) getTenantSettingsOp(ctx context.Context, _ *struct{}) (*TenantSettingsOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}
	settings, err := a.tenantSettingsSvc.Get(ctx, tenant.AccountID, tenant.ProjectID)
	if err != nil {
		log.Error().Err(err).Msg("failed to get tenant settings")
		return nil, huma.Error500InternalServerError("failed to get tenant settings")
	}
	return &TenantSettingsOutput{Body: settings}, nil
}

func (a *API) updateTenantSettingsOp(ctx context.Context, input *UpdateTenantSettingsInput) (*UpdateTenantSettingsOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}
	settings, revoked, err := a.tenantSettingsSvc.SetTokenProfile(ctx, tenant.AccountID, tenant.ProjectID, domain.TokenProfile(input.Body.TokenProfile))
	if err != nil {
		if errors.Is(err, service.ErrInvalidTokenProfile) {
			return nil, huma.Error400BadRequest(err.Error())
		}
		log.Error().Err(err).Int("revoked", revoked).Msg("failed to update tenant settings")
		return nil, huma.Error500InternalServerError("failed to update tenant settings; repeat the request to finish")
	}
	log.Info().
		Str("account_id", tenant.AccountID).
		Str("project_id", tenant.ProjectID).
		Str("token_profile", string(settings.TokenProfile)).
		Int("revoked_long_lived_tokens", revoked).
		Msg("tenant token profile updated")
	out := &UpdateTenantSettingsOutput{}
	out.Body.TenantSettings = settings
	out.Body.RevokedLongLivedTokens = revoked
	return out, nil
}
