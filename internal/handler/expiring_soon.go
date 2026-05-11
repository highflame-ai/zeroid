package handler

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
	internalMiddleware "github.com/highflame-ai/zeroid/internal/middleware"
)

// parseLookaheadDuration extends time.ParseDuration with the human-friendly
// "Nd" (days) and "Nw" (weeks) suffixes the spec uses (?within=7d). Plain
// Go durations like "168h" or "30m" are passed through unchanged.
func parseLookaheadDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	last := s[len(s)-1]
	if last != 'd' && last != 'w' {
		return time.ParseDuration(s)
	}
	n, err := strconv.Atoi(s[:len(s)-1])
	if err != nil {
		return 0, fmt.Errorf("invalid number before %q: %w", string(last), err)
	}
	unit := 24 * time.Hour
	if last == 'w' {
		unit = 7 * 24 * time.Hour
	}
	// Reject anything past the handler's policy cap up-front. Cheaper than
	// multiplying first and clamping after, and avoids any int64 wrap.
	maxN := int(maxExpiringSoonWindow / unit)
	if n < 0 || n > maxN {
		return 0, fmt.Errorf("within %s out of range (max %d%c)", s, maxN, last)
	}
	return time.Duration(n) * unit, nil
}

// defaultExpiringSoonWindow is used when the caller omits ?within. One week
// matches the Studio "expiring this week" stat card.
const defaultExpiringSoonWindow = 7 * 24 * time.Hour

// maxExpiringSoonWindow caps the lookahead to one year. Anything past that
// is more usefully answered by a Studio report, not the inbox endpoint.
const maxExpiringSoonWindow = 365 * 24 * time.Hour

type ExpiringSoonInput struct {
	// Within accepts a Go duration string (e.g. "168h", "30m") OR a short
	// human form using "d" for days or "w" for weeks (e.g. "7d", "2w").
	// Defaults to 7d when omitted.
	Within string `query:"within" doc:"Lookahead window. Accepts Go duration syntax (e.g. 168h, 30m) or human shorthand (7d, 2w). Defaults to 7d."`
}

type ExpiringSoonOutput struct {
	Body struct {
		Within             string                     `json:"within"`
		Identities         []*domain.Identity         `json:"identities"`
		CredentialPolicies []*domain.CredentialPolicy `json:"credential_policies"`
		APIKeys            []*domain.APIKey           `json:"api_keys"`
	}
}

func (a *API) registerExpiringSoonRoute(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "expiring-soon",
		Method:      http.MethodGet,
		Path:        "/expiring-soon",
		Summary:     "List identities, policies, and API keys expiring within a window",
		Description: "Returns active rows whose expires_at falls between now and now+within. Default window is 7d (168h).",
		Tags:        []string{"Identities", "Credential Policies", "API Keys"},
	}, a.expiringSoonOp)
}

func (a *API) expiringSoonOp(ctx context.Context, input *ExpiringSoonInput) (*ExpiringSoonOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	within := defaultExpiringSoonWindow
	if input.Within != "" {
		parsed, err := parseLookaheadDuration(input.Within)
		if err != nil {
			return nil, huma.Error400BadRequest("invalid within duration: " + err.Error())
		}
		if parsed <= 0 {
			return nil, huma.Error400BadRequest("within must be positive")
		}
		if parsed > maxExpiringSoonWindow {
			// Reject (not clamp) so behavior is consistent across input
			// formats. parseLookaheadDuration already rejects out-of-range
			// "Nd"/"Nw"; clamping a Go duration silently would let
			// "?within=9600h" succeed while "?within=400d" returns 400.
			return nil, huma.Error400BadRequest(fmt.Sprintf("within exceeds maximum window (%s)", maxExpiringSoonWindow))
		}
		within = parsed
	}

	now := time.Now().UTC()
	identities, err := a.identitySvc.ListExpiringSoon(ctx, tenant.AccountID, tenant.ProjectID, now, within)
	if err != nil {
		log.Error().Err(err).Msg("expiring-soon: identity scan failed")
		return nil, huma.Error500InternalServerError("failed to list expiring identities")
	}
	policies, err := a.credentialPolicySvc.ListExpiringSoon(ctx, tenant.AccountID, tenant.ProjectID, now, within)
	if err != nil {
		log.Error().Err(err).Msg("expiring-soon: policy scan failed")
		return nil, huma.Error500InternalServerError("failed to list expiring credential policies")
	}
	keys, err := a.apiKeySvc.ListExpiringSoon(ctx, tenant.AccountID, tenant.ProjectID, now, within)
	if err != nil {
		log.Error().Err(err).Msg("expiring-soon: api-key scan failed")
		return nil, huma.Error500InternalServerError("failed to list expiring api keys")
	}

	if identities == nil {
		identities = []*domain.Identity{}
	}
	if policies == nil {
		policies = []*domain.CredentialPolicy{}
	}
	if keys == nil {
		keys = []*domain.APIKey{}
	}

	out := &ExpiringSoonOutput{}
	out.Body.Within = within.String()
	out.Body.Identities = identities
	out.Body.CredentialPolicies = policies
	out.Body.APIKeys = keys
	return out, nil
}
