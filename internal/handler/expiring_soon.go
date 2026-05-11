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
//
// Bounds-checks N against the unit's mathematical ceiling before
// multiplying so a caller submitting "9999999d" gets a clean 400 instead
// of a silently truncated int64-overflow result. The handler-side cap
// (maxExpiringSoonWindow) trims any survivor that's still beyond the
// product's policy window, but that cap only fires if the multiply
// itself doesn't wrap.
func parseLookaheadDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	last := s[len(s)-1]
	if last == 'd' || last == 'w' {
		n, err := strconv.Atoi(s[:len(s)-1])
		if err != nil {
			return 0, fmt.Errorf("invalid number before %q: %w", string(last), err)
		}
		if n < 0 {
			return 0, fmt.Errorf("negative duration: %s", s)
		}
		unit := 24 * time.Hour
		if last == 'w' {
			unit = 7 * 24 * time.Hour
		}
		// Reject any N that would overflow int64 when multiplied by unit.
		// Stays well clear of math.MaxInt64; the handler caps the result
		// at maxExpiringSoonWindow regardless.
		if int64(n) > int64(time.Duration(1<<62)/unit) {
			return 0, fmt.Errorf("duration overflow: %s", s)
		}
		return time.Duration(n) * unit, nil
	}
	return time.ParseDuration(s)
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
		Description: "Returns active rows whose expires_at falls between now and now+within. Default window is 168h (one week).",
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
			parsed = maxExpiringSoonWindow
		}
		within = parsed
	}

	now := time.Now()
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
