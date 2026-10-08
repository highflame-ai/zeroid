package service

import (
	"context"
	"encoding/json"
	"fmt"
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
// requesting chain: the token keeps the chain's subject, act (as issued,
// nested actors included), identity claims and DPoP key binding, carries
// nothing about the approver, and never outlives the requesting token. When the requesting
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
	if row.RequestingAct != "" {
		var act map[string]any
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
	if cred.IdentityID == nil || *cred.IdentityID == "" {
		return true, nil
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
	if err := requireScopesWithin(req.Scopes, policy.AllowedScopes, "the requesting identity's credential policy"); err != nil {
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
		}); perr != nil {
			return true, oauthBadRequestCause(oautherror.AccessDenied, "the requesting identity's credential policy refused issuance", perr)
		}
	}

	req.Identity = ident
	// Enforced above against the chain's grant type; the chokepoint would
	// re-check it against the CIBA grant type instead.
	req.IdentityPolicyID = ""
	return true, nil
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
