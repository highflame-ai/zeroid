package service

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/oautherror"
)

// RequestingToken is a verified bc-authorize requesting_token: the access
// token of the request an approval is for.
type RequestingToken struct {
	JTI        string
	Subject    string
	ActSubject string // act.sub, "" when the token has no act claim
	ClientID   string
	AccountID  string
	ProjectID  string
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
// requesting chain: the token keeps the chain's subject, act and identity
// claims, and carries nothing about the approver. Deterministic refusals are
// returned before the caller burns the auth_req_id. Returns ok=false when the
// row has no requesting chain.
func (s *BackchannelService) requestingChainIssue(ctx context.Context, row *domain.BackchannelAuthRequest, req *IssueRequest) (bool, error) {
	if row.RequestingJTI == "" {
		return false, nil
	}
	req.SubjectOverride = row.RequesterSub
	req.DelegatedBy = row.RequesterActSub
	req.UserEmail = ""
	req.UserName = ""
	req.ParentJTI = row.RequestingJTI

	if s.credentialSvc == nil || s.credentialSvc.repo == nil {
		return true, nil
	}
	cred, err := s.credentialSvc.repo.GetByJTI(ctx, row.RequestingJTI)
	if err != nil {
		return true, oauthBadRequestCause(oautherror.InvalidGrant, "the requesting token for this request no longer exists", err)
	}
	if cred.IsRevoked {
		return true, oauthBadRequest(oautherror.InvalidGrant, "the requesting token for this request has been revoked")
	}
	req.MissionID = cred.MissionID
	req.DelegationDepth = cred.DelegationDepth
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
	if len(ident.AllowedScopes) > 0 {
		allowed := make(map[string]bool, len(ident.AllowedScopes))
		for _, sc := range ident.AllowedScopes {
			allowed[sc] = true
		}
		for _, sc := range req.Scopes {
			if !allowed[sc] {
				return true, oauthBadRequest(oautherror.InvalidScope,
					fmt.Sprintf("scope %q is not in the requesting identity's allowed_scopes", sc))
			}
		}
	}
	req.Identity = ident
	// The requesting identity's own ceiling was enforced when its token was
	// issued; this grant is governed by the CIBA client's identity, checked
	// before issuance.
	req.IdentityPolicyID = ""
	return true, nil
}
