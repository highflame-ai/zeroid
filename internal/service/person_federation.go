package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/internal/oautherror"
)

// FederatedPersonRequest names the person in a verified IdP token, for the
// deployer to resolve to its own user (ADR 0042 D5a).
type FederatedPersonRequest struct {
	// GrantType is PersonGrantIDJAG or PersonGrantExternalIDToken.
	GrantType string
	// AccountID and ProjectID are the tenant the token will be minted into.
	AccountID string
	ProjectID string
	// Issuer is the IdP's iss. Subject is the person's user key: the claim
	// the issuer's claim_mapping.user_id names (Entra oid, Okta sub).
	Issuer  string
	Subject string
	// Email is the mapped email claim. EmailVerified is true only when the
	// IdP asserted it (the claim claim_mapping.email_verified names, default
	// email_verified; Entra's xms_edov).
	Email         string
	EmailVerified bool
	// ClientID is the authenticated client; AgentIdentityID the agent the
	// grant mints for, when it has an identity row.
	ClientID        string
	AgentIdentityID string
}

// FederatedPersonResolver returns the deployer's user id for the person in
// an IdP token. Return ErrPersonNotMember when the person is not a member of
// the account (invalid_grant); any other error, an empty id or a panic fails
// the grant closed with server_error. It runs on the token request's path
// before any single-use credential is consumed, and must honour ctx.
type FederatedPersonResolver func(ctx context.Context, r FederatedPersonRequest) (userID string, err error)

// ErrPersonNotMember is a FederatedPersonResolver's answer for a person who
// is not a member of the account.
var ErrPersonNotMember = errors.New("the person is not a member of this account")

// federatedPersonTimeout bounds one resolver call.
const federatedPersonTimeout = 5 * time.Second

type federatedPersonHook struct {
	fn atomic.Pointer[FederatedPersonResolver]
}

// SetFederatedPersonResolver installs the person resolver; nil removes it.
func (s *OAuthService) SetFederatedPersonResolver(fn FederatedPersonResolver) {
	if fn == nil {
		s.federatedPerson.fn.Store(nil)
		return
	}
	s.federatedPerson.fn.Store(&fn)
}

// federatedPerson is the result of resolving a person: the token's sub and,
// when a resolver mapped it, the IdP's pair for user_idp_iss and user_idp_sub.
type federatedPerson struct {
	sub    string
	idpIss string
	idpSub string
}

// apply sets the person on req. A resolved person's sub is the deployer's
// user, whose issuer is ZeroID's: user_id_iss names sub's issuer, so the
// IdP's issuer moves to user_idp_iss with user_idp_sub (ADR 0042 D5a), and the token
// carries the same user_id_iss as other person grants.
func (p federatedPerson) apply(req *IssueRequest) {
	req.SubjectOverride = p.sub
	if p.idpSub == "" {
		return
	}
	req.IdPIssuer, req.IdPSubject = p.idpIss, p.idpSub
	delete(req.CustomClaims, "user_id_iss")
}

// resolveFederatedPerson maps the IdP subject to the deployer's user.
//
// Without a resolver, a static issuer keeps today's behaviour (sub is the
// IdP subject); an issuer row refuses, because ADR 0042 D5a requires the
// person to be a member of the row's account and only the deployer knows.
func (s *OAuthService) resolveFederatedPerson(ctx context.Context, fromRow bool, r FederatedPersonRequest) (federatedPerson, error) {
	p := s.federatedPerson.fn.Load()
	if p == nil {
		if fromRow {
			return federatedPerson{}, oauthServerError("person resolution is not configured for trusted issuers", nil)
		}
		return federatedPerson{sub: r.Subject}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, federatedPersonTimeout)
	defer cancel()
	userID, err := callFederatedPersonResolver(ctx, *p, r)
	switch {
	case errors.Is(err, ErrPersonNotMember):
		log.Info().Str("account_id", r.AccountID).Str("issuer", r.Issuer).Str("grant_type", r.GrantType).
			Msg("federated person is not a member of the account")
		return federatedPerson{}, oauthBadRequestCause(oautherror.InvalidGrant, "the person is not a member of this organization", err)
	case err != nil:
		log.Error().Err(err).Str("account_id", r.AccountID).Str("issuer", r.Issuer).Str("grant_type", r.GrantType).
			Msg("federated person resolver failed")
		return federatedPerson{}, oauthServerError("the person could not be resolved", err)
	case strings.TrimSpace(userID) == "":
		return federatedPerson{}, oauthServerError("the person could not be resolved", errors.New("resolver returned an empty user id"))
	}
	return federatedPerson{sub: userID, idpIss: r.Issuer, idpSub: r.Subject}, nil
}

func callFederatedPersonResolver(ctx context.Context, fn FederatedPersonResolver, r FederatedPersonRequest) (userID string, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			userID, err = "", fmt.Errorf("federated person resolver panicked: %v", rec)
		}
	}()
	return fn(ctx, r)
}

// emailVerified reads the claim that asserts the email was verified: a JSON
// true, or the strings "true"/"1" some IdPs emit.
func emailVerified(claims map[string]any, claim string) bool {
	if claim == "" {
		claim = "email_verified"
	}
	switch v := claims[claim].(type) {
	case bool:
		return v
	case string:
		return v == "true" || v == "1"
	}
	return false
}
