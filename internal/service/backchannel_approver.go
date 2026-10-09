package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/oautherror"
	"github.com/highflame-ai/zeroid/internal/telemetry"
)

// ApproverAuth says how the user resolving a CIBA request was authenticated.
// Re-exported as zeroid.ApproverAuth.
type ApproverAuth string

const (
	// ApproverAuthSession — the approver presented their own session or ID token.
	ApproverAuthSession ApproverAuth = "session"
	// ApproverAuthChannelAttested — an approval channel (a credential holding
	// the ciba:approve scope) vouched for the approver's IdP subject.
	ApproverAuthChannelAttested ApproverAuth = "channel_attested"
)

// ApproverIdentity is the authenticated user resolving a CIBA request. The
// deployer's authentication layer sets it on the approve/deny request context
// (zeroid.WithApproverIdentity); zeroid never reads it from the request body.
// Re-exported as zeroid.ApproverIdentity.
type ApproverIdentity struct {
	Subject         string // approver user id (token sub)
	Issuer          string // issuer that authenticated the approver
	Auth            ApproverAuth
	ChannelClientID string // set only when Auth == ApproverAuthChannelAttested
	Email, Name     string // optional display enrichment
}

type approverIdentityCtxKey struct{}

// WithApproverIdentity returns ctx carrying the authenticated approver.
func WithApproverIdentity(ctx context.Context, a ApproverIdentity) context.Context {
	return context.WithValue(ctx, approverIdentityCtxKey{}, a)
}

// ApproverIdentityFromContext returns the approver set by WithApproverIdentity.
func ApproverIdentityFromContext(ctx context.Context) (ApproverIdentity, bool) {
	a, ok := ctx.Value(approverIdentityCtxKey{}).(ApproverIdentity)
	return a, ok
}

// ApprovalRequestView is the read-only view of a pending CIBA request handed
// to an ApproverAuthorizer. Re-exported as zeroid.ApprovalRequestView.
type ApprovalRequestView struct {
	AuthReqID, AccountID, ProjectID string
	LoginHint, GroupHint            string
	FourEyes                        bool
	RequesterOwner                  string
}

// ApproverDecision is an ApproverAuthorizer's verdict. Reason is returned to
// the caller on refusal, so it should name what is required (e.g. "approval
// requires role admin"). SatisfiedHint is "login_hint", "group_hint" or "".
// Re-exported as zeroid.ApproverDecision.
type ApproverDecision struct {
	Allowed       bool
	Reason        string
	SatisfiedHint string
}

// ApproverAuthorizer decides whether an approver may resolve a request whose
// group_hint zeroid cannot interpret itself. Re-exported as
// zeroid.ApproverAuthorizer.
type ApproverAuthorizer interface {
	AuthorizeApprover(ctx context.Context, req ApprovalRequestView, approver ApproverIdentity) (ApproverDecision, error)
}

// Values for BackchannelServiceConfig.EnforceHints. Empty means off.
const (
	EnforceHintsOff    = "off"
	EnforceHintsShadow = "shadow"
	EnforceHintsOn     = "on"
)

// ValidEnforceHints reports whether mode is a recognised enforce_hints value.
func ValidEnforceHints(mode string) bool {
	switch mode {
	case "", EnforceHintsOff, EnforceHintsShadow, EnforceHintsOn:
		return true
	}
	return false
}

const (
	hintLoginHint = "login_hint"
	hintGroupHint = "group_hint"
)

// Refusal reasons. The code is the low-cardinality metric label; the message
// is what the caller sees.
const (
	reasonApproverUnknown   = "approver_unknown"
	reasonLoginHintMismatch = "login_hint_mismatch"
	reasonFourEyes          = "four_eyes"
	reasonNoAuthorizer      = "no_authorizer"
	reasonAuthorizerError   = "authorizer_error"
	reasonGroupHintDenied   = "group_hint_denied"

	msgApproverIdentityRequired = "approver identity required"
)

// approverCheck is the outcome of evaluating the approver binding rules.
type approverCheck struct {
	allowed       bool
	code          string // refusal reason code (metric label)
	reason        string // refusal message
	satisfiedHint string
}

// SetApproverAuthorizer installs the hook consulted for group_hint requests.
// nil removes it, after which group_hint requests fail the binding check.
func (s *BackchannelService) SetApproverAuthorizer(a ApproverAuthorizer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.approverAuthorizer = a
}

// EnforceHintsActive reports whether mode runs the approver binding checks
// (shadow or on). Those modes require RequireApproverIdentity.
func EnforceHintsActive(mode string) bool {
	return mode == EnforceHintsShadow || mode == EnforceHintsOn
}

// errEnforceHintsNeedsApproverIdentity is returned by the runtime setters for a
// change that would leave enforce_hints shadow or on without
// require_approver_identity.
var errEnforceHintsNeedsApproverIdentity = errors.New(
	"enforce_hints shadow or on requires require_approver_identity=true")

// SetRequireApproverIdentity toggles backchannel.require_approver_identity at
// runtime. Turning it off while enforce_hints is shadow or on is refused and
// leaves the setting unchanged.
func (s *BackchannelService) SetRequireApproverIdentity(require bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !require && EnforceHintsActive(s.cfg.EnforceHints) {
		return errEnforceHintsNeedsApproverIdentity
	}
	s.cfg.RequireApproverIdentity = require
	return nil
}

// SetEnforceHints sets backchannel.enforce_hints at runtime. shadow and on are
// refused unless require_approver_identity is true; a refused or unknown mode
// leaves the setting unchanged.
func (s *BackchannelService) SetEnforceHints(mode string) error {
	if !ValidEnforceHints(mode) {
		return fmt.Errorf("enforce_hints must be one of off, shadow, on (got %q)", mode)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if EnforceHintsActive(mode) && !s.cfg.RequireApproverIdentity {
		return errEnforceHintsNeedsApproverIdentity
	}
	s.cfg.EnforceHints = mode
	return nil
}

func (s *BackchannelService) approverSettings() (require bool, mode string, authz ApproverAuthorizer) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	mode = s.cfg.EnforceHints
	if mode == "" {
		mode = EnforceHintsOff
	}
	return s.cfg.RequireApproverIdentity, mode, s.approverAuthorizer
}

// resolveApprover derives the approver for an approve/deny call. The request
// context is authoritative; body fields (approve only) are used only when the
// context carries no identity and the deployment does not require one.
func resolveApprover(ctx context.Context, require bool, bodySubject, bodyEmail, bodyName string) (ApproverIdentity, error) {
	if a, ok := ApproverIdentityFromContext(ctx); ok {
		if a.Subject == "" {
			return ApproverIdentity{}, oauthUnauthorized(msgApproverIdentityRequired, nil)
		}
		if bodySubject != "" && bodySubject != a.Subject {
			return ApproverIdentity{}, oauthBadRequest(oautherror.InvalidRequest, "subject_id does not match the authenticated approver")
		}
		if a.Email == "" {
			a.Email = bodyEmail
		}
		if a.Name == "" {
			a.Name = bodyName
		}
		return a, nil
	}
	if require {
		return ApproverIdentity{}, oauthUnauthorized(msgApproverIdentityRequired, nil)
	}
	return ApproverIdentity{Subject: bodySubject, Email: bodyEmail, Name: bodyName}, nil
}

// checkApprover evaluates the binding rules for row against approver:
//
//   - login_hint set → approver.Subject must equal it
//   - four_eyes set  → approver.Subject must not equal requester_owner
//   - group_hint set → the ApproverAuthorizer must allow (none installed → refused)
//
// All applicable rules must pass.
func checkApprover(ctx context.Context, row *domain.BackchannelAuthRequest, approver ApproverIdentity, authz ApproverAuthorizer) approverCheck {
	if approver.Subject == "" {
		return approverCheck{code: reasonApproverUnknown, reason: msgApproverIdentityRequired}
	}
	satisfied := ""
	if row.LoginHint != "" {
		if approver.Subject != row.LoginHint {
			return approverCheck{code: reasonLoginHintMismatch, reason: "approval requires the user named by login_hint"}
		}
		satisfied = hintLoginHint
	}
	if row.FourEyes && row.RequesterOwner != "" && approver.Subject == row.RequesterOwner {
		return approverCheck{code: reasonFourEyes, reason: "approval requires an approver other than the requester owner"}
	}
	if row.GroupHint != "" {
		if authz == nil {
			return approverCheck{code: reasonNoAuthorizer, reason: "no approver authorizer configured"}
		}
		view := ApprovalRequestView{
			AuthReqID:      row.AuthReqID,
			AccountID:      row.AccountID,
			ProjectID:      row.ProjectID,
			LoginHint:      row.LoginHint,
			GroupHint:      row.GroupHint,
			FourEyes:       row.FourEyes,
			RequesterOwner: row.RequesterOwner,
		}
		dec, err := runApproverAuthorizer(ctx, authz, view, approver)
		if err != nil {
			log.Warn().Err(err).Str("auth_req_id", row.AuthReqID).Msg("ciba approver authorizer failed")
			return approverCheck{code: reasonAuthorizerError, reason: "approver eligibility could not be verified"}
		}
		if !dec.Allowed {
			reason := dec.Reason
			if reason == "" {
				reason = "approver is not eligible for this request's group_hint"
			}
			return approverCheck{code: reasonGroupHintDenied, reason: reason}
		}
		if satisfied == "" {
			satisfied = dec.SatisfiedHint
			if satisfied == "" {
				satisfied = hintGroupHint
			}
		}
	}
	return approverCheck{allowed: true, satisfiedHint: satisfied}
}

// runApproverAuthorizer invokes the hook, converting a panic into an error so
// a faulty authorizer fails closed instead of escaping the handler.
func runApproverAuthorizer(ctx context.Context, authz ApproverAuthorizer, view ApprovalRequestView, approver ApproverIdentity) (dec ApproverDecision, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("approver authorizer panicked: %v", r)
		}
	}()
	return authz.AuthorizeApprover(ctx, view, approver)
}

// authorizeResolution runs the approver checks for an approve (action
// "approve") or deny ("deny") under the configured mode and returns the
// record to persist with the resolution, or the refusal.
func (s *BackchannelService) authorizeResolution(ctx context.Context, action string, row *domain.BackchannelAuthRequest, approver ApproverIdentity) (domain.BackchannelResolution, error) {
	_, mode, authz := s.approverSettings()
	rec := domain.BackchannelResolution{
		SubjectID:       approver.Subject,
		SubjectEmail:    approver.Email,
		SubjectName:     approver.Name,
		ApproverIss:     approver.Issuer,
		ApproverAuth:    string(approver.Auth),
		ChannelClientID: approver.ChannelClientID,
	}
	if mode == EnforceHintsOff {
		return rec, nil
	}

	check := checkApprover(ctx, row, approver, authz)
	if check.allowed {
		rec.HintSatisfied = check.satisfiedHint
		return rec, nil
	}

	logEvt := func(msg string) {
		log.Info().
			Str("auth_req_id", row.AuthReqID).
			Str("account_id", row.AccountID).
			Str("project_id", row.ProjectID).
			Str("action", action).
			Str("approver_sub", approver.Subject).
			Str("approver_iss", approver.Issuer).
			Str("reason_code", check.code).
			Str("reason", check.reason).
			Msg(msg)
	}

	if mode == EnforceHintsShadow {
		logEvt("ciba approver would deny")
		telemetry.CIBAApproverWouldDeny.Add(ctx, 1, metric.WithAttributes(attribute.String("reason", check.code)))
		rec.ShadowWouldDeny = true
		rec.ShadowReason = check.reason
		return rec, nil
	}

	logEvt("ciba approver denied")
	if check.code == reasonApproverUnknown {
		return rec, oauthUnauthorized(msgApproverIdentityRequired, nil)
	}
	return rec, oauthForbidden(oautherror.AccessDenied, check.reason)
}
