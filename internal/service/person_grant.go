package service

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync/atomic"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/telemetry"
)

// PersonGrantMode says what the person-grant ceiling does. See
// docs/scope-ceilings.md, "A person's ceiling".
type PersonGrantMode string

const (
	// PersonGrantModeOff never calls the resolver.
	PersonGrantModeOff PersonGrantMode = "off"
	// PersonGrantModeShadow calls the resolver and counts what enforce would
	// narrow or refuse, but issues the token unchanged.
	PersonGrantModeShadow PersonGrantMode = "shadow"
	// PersonGrantModeEnforce issues request ∩ ceiling and refuses a request
	// that leaves nothing.
	PersonGrantModeEnforce PersonGrantMode = "enforce"
)

// PersonGrantRequest.GrantType values, one per grant that mints for a person.
// The two token exchanges are told apart by the names their tokens' own
// token_exchange claim already uses.
const (
	PersonGrantAuthorizationCode = string(domain.GrantTypeAuthorizationCode)
	PersonGrantRefreshToken      = string(domain.GrantTypeRefreshToken)
	PersonGrantCIBA              = string(domain.GrantTypeCIBA)
	PersonGrantIDJAG             = string(domain.GrantTypeJWTBearer)
	PersonGrantExternalPrincipal = "external_principal"
	PersonGrantExternalIDToken   = "external_id_token"
)

// PersonGrantRequest describes one token about to be minted for a person.
type PersonGrantRequest struct {
	// GrantType names the grant minting the token: one of the PersonGrant*
	// constants.
	GrantType string
	AccountID string
	ProjectID string
	// UserID and UserIss are the person: the token's sub, and the issuer that
	// vouched for it (the upstream IdP on a federated grant, else ZeroID).
	UserID  string
	UserIss string
	// ClientID is the OAuth client the token is issued to, when there is one.
	ClientID string
	// Audience is the token's aud: resource indicators or an audience profile.
	// Empty when the token gets the default audience.
	Audience []string
	// RequestedScopes is the request, or its default, after every other layer
	// narrowed it.
	RequestedScopes []string
	// TrustedRole is the role a trusted service asserted on the external
	// principal exchange (GrantRequest.Role). Empty on every other grant.
	TrustedRole string
}

// PersonGrant is the deployer's answer for one person.
type PersonGrant struct {
	// Scopes is the person's ceiling. Empty grants nothing.
	Scopes []string
	// Roles is stamped as the RFC 9068 §2.2.3.1 roles claim on the token.
	Roles []string
}

// PersonGrantResolver returns a person's scope ceiling and roles. A nil
// PersonGrant is an empty ceiling. Returning an error (or panicking) fails
// the grant closed in enforce mode. It runs on the token request's path: it
// must honour ctx's deadline and should cache.
type PersonGrantResolver func(ctx context.Context, r PersonGrantRequest) (*PersonGrant, error)

// ErrPersonScopeDenied is returned when the person's ceiling leaves none of
// the requested scopes.
var ErrPersonScopeDenied = errors.New("none of the requested scopes is granted to this user")

// ErrPersonGrantUnavailable is returned in enforce mode when the resolver
// fails.
var ErrPersonGrantUnavailable = errors.New("the user's scope ceiling could not be resolved")

// personGrantMsg is the stable log message for every ceiling outcome other
// than "within the ceiling".
const personGrantMsg = "person_scope_ceiling_violation"

type personGrantHook struct {
	resolve PersonGrantResolver
	mode    PersonGrantMode
}

// personGrantDecision is the resolver's decision for one person mint.
// requested is what was asked, scopes what is issued; enforced says the
// ceiling bounded them, which the ceiling rule counts as a bound.
type personGrantDecision struct {
	requested []string
	scopes    []string
	roles     []string
	enforced  bool
}

// personGrantState holds the installed hook. Kept apart from the
// constructor's fields so the setter can run concurrently with issuance.
type personGrantState struct {
	hook atomic.Pointer[personGrantHook]
}

// SetPersonGrantResolver installs the person-grant hook; PersonGrantModeOff
// removes it. A nil resolver in shadow or enforce mode, or any other mode
// (including ""), is rejected and leaves the hook unchanged, so a wiring
// mistake never turns the ceiling off silently.
func (s *CredentialService) SetPersonGrantResolver(fn PersonGrantResolver, mode PersonGrantMode) error {
	switch mode {
	case PersonGrantModeOff:
		s.personGrant.hook.Store(nil)
		return nil
	case PersonGrantModeShadow, PersonGrantModeEnforce:
		if fn == nil {
			return fmt.Errorf("person grant mode %q needs a resolver; use %q to remove the hook", mode, PersonGrantModeOff)
		}
		s.personGrant.hook.Store(&personGrantHook{resolve: fn, mode: mode})
		return nil
	default:
		return fmt.Errorf("unknown person grant mode %q (want off, shadow or enforce)", mode)
	}
}

// personGrantEnforced reports whether a resolver is installed in enforce mode.
func (s *CredentialService) personGrantEnforced() bool {
	if s == nil {
		return false
	}
	h := s.personGrant.hook.Load()
	return h != nil && h.mode == PersonGrantModeEnforce
}

// isPersonRoot reports whether req mints a person's own token: a user
// principal the chokepoint derives itself. Token exchange and a CIBA step-up
// pass their chain's principal in PrincipalType, so they are never roots.
func isPersonRoot(req IssueRequest, principal resolvedPrincipal) bool {
	return principal.Type == domain.PrincipalUser && req.PrincipalType == ""
}

// decidePersonGrant applies the person's ceiling to req.Scopes when req mints
// a person root, and records the decision on req so the chokepoint reuses it.
// Grants that burn a single-use credential call it before the burn.
func (s *CredentialService) decidePersonGrant(ctx context.Context, req *IssueRequest) error {
	if s == nil || req.Identity == nil {
		return nil
	}
	principal := s.resolvePrincipal(*req)
	if !isPersonRoot(*req, principal) {
		return nil
	}
	if d := req.personGrant; d != nil && (slices.Equal(req.Scopes, d.scopes) || slices.Equal(req.Scopes, d.requested)) {
		req.Scopes = d.scopes
		return nil
	}
	req.personGrant = nil
	hook := s.personGrant.hook.Load()
	if hook == nil {
		return nil
	}

	pr := PersonGrantRequest{
		GrantType:       personGrantType(*req),
		AccountID:       req.Identity.AccountID,
		ProjectID:       req.Identity.ProjectID,
		UserID:          principal.Sub,
		UserIss:         principal.Iss,
		ClientID:        req.ClientID,
		Audience:        slices.Clone(req.Audience),
		RequestedScopes: slices.Clone(req.Scopes),
		TrustedRole:     req.TrustedRole,
	}
	grant, err := callPersonGrantResolver(ctx, hook.resolve, pr)
	if err != nil {
		recordPersonGrant(ctx, hook.mode, pr, "resolver_error", nil, err)
		if hook.mode == PersonGrantModeEnforce {
			return fmt.Errorf("%w: %w", ErrPersonGrantUnavailable, err)
		}
		return nil
	}

	var ceiling, roles []string
	if grant != nil {
		ceiling, roles = grant.Scopes, cleanRoles(grant.Roles)
	}
	granted, outcome := applyPersonCeiling(req.Scopes, ceiling)
	if outcome != "" {
		recordPersonGrant(ctx, hook.mode, pr, outcome, ceiling, nil)
	}
	d := &personGrantDecision{requested: pr.RequestedScopes, scopes: req.Scopes, roles: roles}
	if hook.mode == PersonGrantModeEnforce {
		if outcome == "denied" {
			return ErrPersonScopeDenied
		}
		d.scopes, d.enforced = granted, true
	}
	req.Scopes = d.scopes
	req.personGrant = d
	return nil
}

// personGrantType names req's grant for the resolver. The two exchanges share
// the token_exchange grant type, so they name themselves.
func personGrantType(req IssueRequest) string {
	if req.PersonGrantType != "" {
		return req.PersonGrantType
	}
	return string(req.GrantType)
}

// applyPersonCeiling returns requested ∩ ceiling, in request order, and
// "narrowed" or "denied" when the ceiling removed something. openid asks for
// authentication, not authority, so it is never removed and never counts as
// a requested scope on its own.
func applyPersonCeiling(requested, ceiling []string) ([]string, string) {
	var granted []string
	authority := 0
	for _, sc := range requested {
		if sc == "openid" {
			granted = append(granted, sc)
			continue
		}
		authority++
		if slices.Contains(ceiling, sc) {
			granted = append(granted, sc)
		}
	}
	switch kept := len(granted) - (len(requested) - authority); {
	case kept == authority:
		return granted, ""
	case kept == 0:
		return granted, "denied"
	default:
		return granted, "narrowed"
	}
}

// callPersonGrantResolver runs the deployer's resolver, turning a panic into
// an error so it fails closed like one.
func callPersonGrantResolver(ctx context.Context, fn PersonGrantResolver, pr PersonGrantRequest) (grant *PersonGrant, err error) {
	defer func() {
		if r := recover(); r != nil {
			grant, err = nil, fmt.Errorf("person grant resolver panicked: %v", r)
		}
	}()
	return fn(ctx, pr)
}

// cleanRoles drops empty and repeated roles, keeping order.
func cleanRoles(roles []string) []string {
	var out []string
	for _, r := range roles {
		if r != "" && !slices.Contains(out, r) {
			out = append(out, r)
		}
	}
	return out
}

// recordPersonGrant counts and logs a ceiling outcome. Shadow mode and
// resolver errors log at warn; an enforced refusal at info; an enforced
// narrowing, which is ordinary issuance (RFC 6749 §3.3), at debug.
func recordPersonGrant(ctx context.Context, mode PersonGrantMode, pr PersonGrantRequest, outcome string, ceiling []string, err error) {
	telemetry.PersonScopeCeiling.Add(ctx, 1, metric.WithAttributes(
		attribute.String("account_id", pr.AccountID),
		attribute.String("project_id", pr.ProjectID),
		attribute.String("grant_type", pr.GrantType),
		attribute.String("mode", string(mode)),
		attribute.String("outcome", outcome),
	))
	level := zerolog.WarnLevel
	if mode == PersonGrantModeEnforce && err == nil {
		level = zerolog.InfoLevel
		if outcome == "narrowed" {
			level = zerolog.DebugLevel
		}
	}
	log.WithLevel(level).
		Err(err).
		Str("mode", string(mode)).
		Str("outcome", outcome).
		Str("grant_type", pr.GrantType).
		Str("account_id", pr.AccountID).
		Str("project_id", pr.ProjectID).
		Str("user_id", pr.UserID).
		Strs("requested_scopes", pr.RequestedScopes).
		Strs("ceiling", ceiling).
		Msg(personGrantMsg)
}

// personGrantOAuthError maps a ceiling refusal to deniedCode and a resolver
// failure to server_error. Any other error is returned unchanged.
func personGrantOAuthError(err error, deniedCode string) error {
	switch {
	case errors.Is(err, ErrPersonScopeDenied):
		return oauthBadRequestCause(deniedCode, "none of the requested scopes is granted to this user", err)
	case errors.Is(err, ErrPersonGrantUnavailable):
		return oauthServerError("the user's scope ceiling could not be resolved", err)
	}
	return err
}
