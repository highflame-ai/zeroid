package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/oautherror"
)

// RequestingToken is a verified bc-authorize requesting_token: the access
// token of the request an approval is for.
type RequestingToken struct {
	JTI        string
	Subject    string
	ActSubject string          // act.sub, "" when the token has no act claim
	Act        json.RawMessage // the act claim as issued, nil when absent
	ExpiresAt  time.Time
	ClientID   string
	AccountID  string
	ProjectID  string
	// IdentityID is the identity the token was issued to, "" when none.
	IdentityID string
	// DPoPKeyThumbprint is the token's cnf.jkt, "" when it is not DPoP-bound.
	DPoPKeyThumbprint string
}

// Actor returns who made the request: act.sub, else client_id, else sub.
func (t *RequestingToken) Actor() string {
	switch {
	case t.ActSubject != "":
		return t.ActSubject
	case t.ClientID != "":
		return t.ClientID
	}
	return t.Subject
}

type requestingTokenVerifier func(ctx context.Context, token string) (*RequestingToken, error)

// setTrustedCallerCheck is wired by OAuthService.SetBackchannelService: it
// reports whether the deployer's TrustedServiceValidator accepts the request.
func (s *BackchannelService) setTrustedCallerCheck(fn func(ctx context.Context) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.isTrustedCaller = fn
}

// callerAuthenticated reports whether the bc-authorize caller authenticated:
// either as the client (a client that must authenticate got past the secret
// check) or through the deployer's trusted-service mechanism.
func (s *BackchannelService) callerAuthenticated(ctx context.Context, client *domain.OAuthClient) bool {
	if client.RequiresClientAuthentication() {
		return true
	}
	s.mu.RLock()
	trusted := s.isTrustedCaller
	s.mu.RUnlock()
	return trusted != nil && trusted(ctx)
}

// setRequestingTokenVerifier is wired by OAuthService.SetBackchannelService,
// which owns token verification.
func (s *BackchannelService) setRequestingTokenVerifier(fn requestingTokenVerifier) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verifyRequestingToken = fn
}

// resolveRequestingToken verifies in.RequestingToken and checks it belongs to
// the bc-authorize request's tenant. Every failure is invalid_request.
func (s *BackchannelService) resolveRequestingToken(ctx context.Context, in CreateAuthRequestInput) (*RequestingToken, error) {
	s.mu.RLock()
	verify := s.verifyRequestingToken
	s.mu.RUnlock()
	if verify == nil {
		return nil, oauthBadRequest(oautherror.InvalidRequest, "requesting_token is not supported by this deployment")
	}
	rt, err := verify(ctx, in.RequestingToken)
	if err != nil {
		return nil, oauthBadRequestCause(oautherror.InvalidRequest, "requesting_token is invalid", err)
	}
	if rt.AccountID != in.AccountID || rt.ProjectID != in.ProjectID {
		return nil, oauthBadRequest(oautherror.InvalidRequest, "requesting_token is invalid")
	}
	return rt, nil
}

// requestingOwner returns the owner_user_id of the identity rt was issued to,
// or "" when rt names no identity or the identity has no owner. A failed
// lookup is invalid_request.
func (s *BackchannelService) requestingOwner(ctx context.Context, rt *RequestingToken) (string, error) {
	if rt == nil || rt.IdentityID == "" || s.identitySvc == nil {
		return "", nil
	}
	ident, err := s.identitySvc.GetIdentity(ctx, rt.IdentityID, rt.AccountID, rt.ProjectID)
	if err != nil {
		return "", oauthBadRequestCause(oautherror.InvalidRequest, "requesting_token is invalid", err)
	}
	return ident.OwnerUserID, nil
}

// requireRequestingTokenHolder refuses a poll on a row made with a
// requesting_token unless the poll presents that same token (jti match) and,
// when that token is DPoP-bound, carries a DPoP proof for its key. Every
// refusal is access_denied and leaves the row unchanged.
func (s *BackchannelService) requireRequestingTokenHolder(ctx context.Context, row *domain.BackchannelAuthRequest, in RedeemInput) error {
	if row.RequestingJTI == "" {
		return nil
	}
	if in.RequestingToken == "" {
		return oauthBadRequest(oautherror.AccessDenied, "this request was made with a requesting_token; present it as requesting_token to redeem")
	}
	s.mu.RLock()
	verify := s.verifyRequestingToken
	s.mu.RUnlock()
	if verify == nil {
		return oauthBadRequest(oautherror.AccessDenied, "requesting_token cannot be verified by this deployment")
	}
	rt, err := verify(ctx, in.RequestingToken)
	if err != nil || rt.JTI != row.RequestingJTI {
		return oauthBadRequestCause(oautherror.AccessDenied, "requesting_token does not match this request", err)
	}
	if rt.DPoPKeyThumbprint != "" && rt.DPoPKeyThumbprint != in.DPoPKeyThumbprint {
		return oauthBadRequest(oautherror.AccessDenied, "the requesting_token is DPoP-bound; a DPoP proof for its key is required")
	}
	return nil
}

// stampAuthorizationDetails adds approval_id (the auth_req_id) and, when
// known, approver_auth to every authorization_details entry approved by row.
// Values supplied by the client under those keys are overwritten.
func stampAuthorizationDetails(row *domain.BackchannelAuthRequest) (json.RawMessage, error) {
	raw := row.AuthorizationDetailsRaw
	if len(raw) == 0 {
		return raw, nil
	}
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("decode authorization_details: %w", err)
	}
	if len(entries) == 0 {
		return raw, nil
	}
	approvalID, _ := json.Marshal(row.AuthReqID)
	approverAuth, _ := json.Marshal(row.ApproverAuth)
	for _, e := range entries {
		e["approval_id"] = approvalID
		if row.ApproverAuth != "" {
			e["approver_auth"] = approverAuth
		} else {
			delete(e, "approver_auth")
		}
	}
	return json.Marshal(entries)
}

// requestingChainIssue adjusts a CIBA issuance for a row that carries a
// requesting chain: the token keeps the chain's subject, actors (nested
// actors included, in the shape of the profile it is minted under), identity
// claims and DPoP key binding, carries
// nothing about the approver, never holds a scope the requesting token does
// not (see requestingChainScopes), and never outlives it. When the requesting
// token belongs to an identity, that identity's credential policy governs the
// result. Every refusal is returned before the caller burns the auth_req_id.
// Returns ok=false when the row has no requesting chain.
func (s *BackchannelService) requestingChainIssue(ctx context.Context, row *domain.BackchannelAuthRequest, req *IssueRequest) (bool, error) {
	if row.RequestingJTI == "" {
		return false, nil
	}
	req.SubjectOverride = row.RequesterSub
	req.UserEmail = ""
	req.UserName = ""
	req.ParentJTI = row.RequestingJTI
	var act map[string]any
	if row.RequestingAct != "" {
		if err := json.Unmarshal([]byte(row.RequestingAct), &act); err != nil {
			return true, oauthServerError("failed to decode the requesting token's act claim", err)
		}
		req.ActClaim = act
		req.DelegatedBy, _ = act["sub"].(string)
	}

	if s.credentialSvc == nil || s.credentialSvc.repo == nil {
		return true, oauthServerError("backchannel service is missing its credential service", nil)
	}
	cred, err := s.credentialSvc.repo.GetByJTI(ctx, row.RequestingJTI)
	if err != nil {
		return true, oauthBadRequestCause(oautherror.InvalidGrant, "the requesting token for this request no longer exists", err)
	}
	if cred.IsRevoked {
		return true, oauthBadRequest(oautherror.InvalidGrant, "the requesting token for this request has been revoked")
	}
	if !time.Now().Before(cred.ExpiresAt) {
		return true, oauthBadRequest(oautherror.InvalidGrant, "the requesting token for this request has expired")
	}
	// The approval extends the chain, so the chain's principal carries over
	// unchanged (RFC 8693 §4.1) and the token is not a request-bounded root:
	// no role applies and the approver is evidence only (ADR 0041 D15).
	req.RequestBoundedRoot = false
	p := requestingChainPrincipal(cred, row.RequesterSub, s.credentialSvc.issuer)
	req.PrincipalType, req.PrincipalSub, req.PrincipalIss = p.Type, p.Sub, p.Iss

	// Never outlive the chain: the chokepoint clamps exp to this bound.
	chainExp := cred.ExpiresAt
	req.CredentialExpiresAt = &chainExp
	req.MissionID = cred.MissionID
	req.DelegationDepth = cred.DelegationDepth
	// Keep the chain's sender constraint: a DPoP-bound requesting token
	// yields a token bound to the same key (in poll mode the poll has already
	// proved possession of it).
	if cred.DPoPKeyThumbprint != "" {
		req.DPoPKeyThumbprint = cred.DPoPKeyThumbprint
	}
	// The approval extends the chain, so the token holds the chain's scopes,
	// never more (RFC 8693: a child never exceeds its parent). The approval
	// itself grants the authorization_details entry, not scopes.
	scopes, err := requestingChainScopes(cred.Scopes, req.Scopes)
	if err != nil {
		return true, err
	}
	req.Scopes = scopes
	if cred.IdentityID == nil || *cred.IdentityID == "" {
		// No requesting identity: the token stays anchored to the polling
		// client's bound identity, if any, and the chokepoint enforces that
		// identity's ceilings and policy on the chain's scopes, which the
		// caller's pre-burn checks saw only as the request's own scope.
		return true, s.boundAnchorGates(ctx, req)
	}

	ident, err := s.identitySvc.GetIdentity(ctx, *cred.IdentityID, row.AccountID, row.ProjectID)
	if err != nil {
		log.Warn().Err(err).Str("auth_req_id", row.AuthReqID).Msg("requesting identity lookup failed")
		return true, oauthServerError("failed to load the requesting identity", err)
	}
	if !ident.Status.IsUsable() {
		return true, oauthBadRequest(oautherror.AccessDenied, "the requesting identity is suspended or deactivated")
	}
	if ident.IsExpired() {
		return true, oauthBadRequest(oautherror.InvalidGrant, "identity_expired")
	}
	if refused := scopeRefusedForIdentityType(ident.IdentityType, req.Scopes); refused != "" {
		return true, oauthBadRequest(oautherror.InvalidScope, fmt.Sprintf("scope %q is not issued to this identity", refused))
	}
	if err := requireScopesWithin(req.Scopes, ident.AllowedScopes, "the requesting identity's allowed_scopes"); err != nil {
		return true, err
	}

	// The requesting identity's credential policy is its authority ceiling;
	// enforce it here, before the burn. The grant-type axis is evaluated
	// against the grant that minted the requesting token (the chain's own
	// grant), so a policy need not list CIBA for its tokens to be extended
	// by an approval.
	policy, err := s.identitySvc.ResolveCredentialPolicy(ctx, ident)
	if err != nil {
		return true, oauthServerError("failed to resolve the requesting identity's credential policy", err)
	}
	// A chain acting for a person is capped by the policy's user_grant_scopes
	// in place of its allowed_scopes (ADR 0041 D2, #385 D10); the identity's
	// own allowed_scopes, checked above, binds either way. The chain bounds
	// the person's grant, as on a token exchange, so the split applies to
	// every user-rooted chain.
	userGrant := p.Type == domain.PrincipalUser
	policyCeiling, ceilingName := policy.AllowedScopes, "the requesting identity's credential policy allowed_scopes"
	if userGrant {
		policyCeiling, ceilingName = policy.UserGrantScopes, "the requesting identity's credential policy user_grant_scopes"
	}
	if err := requireScopesWithin(req.Scopes, policyCeiling, ceilingName); err != nil {
		return true, err
	}
	if policy.MaxTTLSeconds > 0 && req.TTL > policy.MaxTTLSeconds {
		req.TTL = policy.MaxTTLSeconds
	}
	var attestationLevel string
	if s.credentialSvc.attestationRepo != nil {
		attestationLevel, _ = s.credentialSvc.attestationRepo.GetHighestVerifiedLevel(ctx, ident.ID)
	}
	if s.credentialSvc.policySvc != nil {
		if perr := s.credentialSvc.policySvc.EnforcePolicy(ctx, policy, EnforcePolicyRequest{
			TTL:              req.TTL,
			GrantType:        cred.GrantType,
			Scopes:           req.Scopes,
			TrustLevel:       ident.TrustLevel,
			AttestationLevel: attestationLevel,
			DelegationDepth:  req.DelegationDepth,
			// The chain's principal, so required_principal_type is judged
			// against who the chain acts for, and the user-grant ceiling
			// applies to a person's chain.
			PrincipalType:    p.Type,
			UserGrantBounded: userGrant,
		}); perr != nil {
			return true, oauthBadRequestCause(oautherror.AccessDenied, "the requesting identity's credential policy refused issuance", perr)
		}
	}

	req.Identity = ident
	// The rfc8693 profile carries the requesting identity's attributes in the
	// outermost act. They are re-derived from its record rather than read from
	// the chain's act, which is in the legacy shape when the chain was minted
	// before the tenant switched profile. A root (depth 0) has no actor chain.
	if cred.DelegationDepth > 0 {
		req.Actors = requestingChainActors(ident, act, p.Sub)
	}
	req.UserGrantBounded = userGrant
	// Enforced above against the chain's grant type; the chokepoint would
	// re-check it against the CIBA grant type instead. The policy still
	// governs the token's non-enforcement choices (typ header, ceiling-rule
	// counting), so it is handed over without its ID.
	req.IdentityPolicyID = ""
	req.EnforcedIdentityPolicy = policy
	return true, nil
}

// requestingChainActors returns the RFC 8693 §4.1 actor chain of a token
// approved into a delegated chain: the requesting identity as the current
// actor, with its attributes from its record, then the chain's prior actors
// taken from act, the requesting token's act claim as issued.
//
// An act in the rfc8693 shape has the current actor outermost and the prior
// actors nested under it; they carry over unchanged. An act in the legacy
// shape is a single level naming the agent that delegated or an end user. The
// agent (a WIMSE URI) becomes the one prior actor unless it is the chain's
// principal, which is `sub` and never an actor; an end user never does.
func requestingChainActors(ident *domain.Identity, act map[string]any, principalSub string) []domain.Actor {
	actors := []domain.Actor{{
		Sub:          ident.WIMSEURI,
		IdentityType: string(ident.IdentityType),
		TrustLevel:   string(ident.TrustLevel),
		ExternalID:   ident.ExternalID,
	}}
	if act == nil {
		return actors
	}
	if !carriesActorAttributes(act) {
		sub, _ := act["sub"].(string)
		if strings.HasPrefix(sub, "spiffe://") && sub != principalSub && sub != ident.WIMSEURI {
			actors = append(actors, domain.Actor{Sub: sub})
		}
		return actors
	}
	prior, _ := act["act"].(map[string]any)
	for prior != nil && len(actors) < domain.MaxActorChainDepth {
		sub, _ := prior["sub"].(string)
		if sub == "" {
			break
		}
		actors = append(actors, domain.Actor{Sub: sub})
		prior, _ = prior["act"].(map[string]any)
	}
	return actors
}

// boundAnchorGates applies, before the burn, the checks IssueCredential makes
// against req.Identity and req.IdentityPolicyID when a step-up into a chain
// with no identity leaves the token anchored to the polling client's bound
// identity. It mirrors the chokepoint so a deterministic refusal there cannot
// consume the approval. A request with no anchor (an unbound client) has
// nothing to check.
func (s *BackchannelService) boundAnchorGates(ctx context.Context, req *IssueRequest) error {
	if req.Identity == nil || req.Identity.ID == "" {
		return nil
	}
	if refused := scopeRefusedForIdentityType(req.Identity.IdentityType, req.Scopes); refused != "" {
		return oauthBadRequest(oautherror.InvalidScope, fmt.Sprintf("scope %q is not issued to the bound identity", refused))
	}
	if err := requireScopesWithin(req.Scopes, req.Identity.AllowedScopes, "the bound identity's allowed_scopes"); err != nil {
		return err
	}
	if req.IdentityPolicyID == "" || s.credentialSvc.policySvc == nil {
		return nil
	}
	policy, err := s.credentialSvc.policySvc.GetPolicy(ctx, req.IdentityPolicyID, req.Identity.AccountID, req.Identity.ProjectID)
	if err != nil {
		return oauthServerError("failed to load the bound identity's credential policy", err)
	}
	var attestationLevel string
	if s.credentialSvc.attestationRepo != nil {
		attestationLevel, _ = s.credentialSvc.attestationRepo.GetHighestVerifiedLevel(ctx, req.Identity.ID)
	}
	enforce := EnforcePolicyRequest{
		TTL:              req.TTL,
		GrantType:        req.GrantType,
		Scopes:           req.Scopes,
		TrustLevel:       req.Identity.TrustLevel,
		AttestationLevel: attestationLevel,
		DelegationDepth:  req.DelegationDepth,
		PrincipalType:    req.PrincipalType,
		UserGrantBounded: req.UserGrantBounded,
	}
	if err := requireScopesWithin(req.Scopes, scopeCeiling(policy, enforce), "the bound identity's credential policy"); err != nil {
		return err
	}
	if perr := s.credentialSvc.policySvc.EnforcePolicy(ctx, policy, enforce); perr != nil {
		return oauthBadRequestCause(oautherror.AccessDenied, "the bound identity's credential policy refused issuance", perr)
	}
	return nil
}

// requestingChainScopes returns the scopes of a token approved into a chain
// holding chainScopes, given the scopes the bc-authorize request named.
//
// "openid" is the CIBA protocol scope (CIBA Core §7.1 requires it, so a
// caller such as Shield always sends it); it asks for authentication, not
// authority, and narrows nothing. Any other requested scope narrows the
// result to the scopes named. A named scope the chain does not hold is
// refused with invalid_scope rather than dropped: the approver was shown a
// request for it, and a silently narrower token would leave the client
// believing it holds authority it does not. A step-up can never add a scope
// to its chain.
//
// A chain with no scopes is the legacy scopeless shape (an identity with no
// ceiling anywhere), which downstream reads as unrestricted. The approval
// then keeps the request's scopes, exactly as a root CIBA grant does, so the
// token never ends up with no scopes claim where the root grant would carry
// one; the ceilings checked afterwards still bound it.
func requestingChainScopes(chainScopes, requested []string) ([]string, error) {
	if len(chainScopes) == 0 {
		return requested, nil
	}
	held := make(map[string]bool, len(chainScopes))
	for _, sc := range chainScopes {
		held[sc] = true
	}
	var narrowed []string
	seen := make(map[string]bool, len(requested))
	for _, sc := range requested {
		if sc == cibaProtocolScope || seen[sc] {
			continue
		}
		seen[sc] = true
		if !held[sc] {
			return nil, oauthBadRequest(oautherror.InvalidScope, fmt.Sprintf("scope %q is not held by the requesting token; a step-up cannot add scopes to its chain", sc))
		}
		narrowed = append(narrowed, sc)
	}
	if len(narrowed) == 0 {
		return append([]string(nil), chainScopes...), nil
	}
	return narrowed, nil
}

// cibaProtocolScope is the OpenID scope CIBA Core §7.1 requires on every
// authentication request.
const cibaProtocolScope = "openid"

// requestingChainPrincipal returns the principal of the chain a step-up is
// approved into. A requesting credential minted since migration 048 records
// it; an older one does not, and the exchange's legacy rule applies (see
// OAuthService.parentPrincipal): at depth 0 a WIMSE subject is a workload and
// anything else a person; above depth 0 the original principal is lost and
// the result is unknown, which never satisfies a principal requirement.
func requestingChainPrincipal(cred *domain.IssuedCredential, sub, issuer string) resolvedPrincipal {
	if cred.PrincipalType != "" {
		return resolvedPrincipal{Type: cred.PrincipalType, Sub: cred.PrincipalSub, Iss: cred.PrincipalIss}
	}
	switch {
	case cred.DelegationDepth > 0:
		return resolvedPrincipal{Type: domain.PrincipalUnknown, Sub: sub, Iss: issuer}
	case strings.HasPrefix(sub, "spiffe://"):
		return resolvedPrincipal{Type: domain.PrincipalWorkload, Sub: sub, Iss: issuer}
	default:
		return resolvedPrincipal{Type: domain.PrincipalUser, Sub: sub, Iss: issuer}
	}
}

// requireScopesWithin refuses any requested scope outside a non-empty ceiling.
func requireScopesWithin(requested, ceiling []string, what string) error {
	if len(ceiling) == 0 {
		return nil
	}
	allowed := make(map[string]bool, len(ceiling))
	for _, sc := range ceiling {
		allowed[sc] = true
	}
	for _, sc := range requested {
		if !allowed[sc] {
			return oauthBadRequest(oautherror.InvalidScope, fmt.Sprintf("scope %q is not permitted by %s", sc, what))
		}
	}
	return nil
}
