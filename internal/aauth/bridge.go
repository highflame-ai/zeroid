package aauth

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/oautherror"
	"github.com/highflame-ai/zeroid/internal/service"
)

// The bridge grant exchanges an AAuth agent token for an OAuth access token,
// so an agent that holds only an AAuth identity can call a resource that only
// speaks OAuth (MCP servers today). It is the interim, Highflame-internal
// edge: AAuth inside, OAuth at the boundary. The AAuth-native edges are a
// resource that verifies agent tokens itself, and a gateway that does it for
// one.
//
//	POST /oauth2/token
//	DPoP: <proof signed by the agent token's cnf key>
//	grant_type=urn:highflame:params:oauth:grant-type:aauth-agent-token
//	subject_token=<aa-agent+jwt>
//	resource=<the one resource the token is for>
//	scope=<optional, narrowed to the identity's ceilings>
//
// Possession of the agent key is proven by the DPoP proof the token endpoint
// already verifies, not by an RFC 9421 signature: one proof format at
// /oauth2/token. The issued token is DPoP-bound to the same key, never a
// bearer token: AAuth has no bearer credentials, and a resource that can't
// check DPoP belongs behind a gateway that can.

// AgentTokenTypeURN is the subject_token_type of an AAuth agent token. It is
// optional on the bridge grant, whose subject token is always one.
const AgentTokenTypeURN = "urn:highflame:params:oauth:token-type:aauth-agent"

// AgentClaim names the agent on a bridged token: the aauth: identifier of the
// agent token it was exchanged for. Not `act`, which says another party
// delegated; the agent is the identity's own instance.
const AgentClaim = "aauth_agent"

// registerBridge registers the bridge grant on the token endpoint.
func (p *Provider) registerBridge(oauth *service.OAuthService) {
	oauth.RegisterGrantAcceptingResource(domain.GrantTypeAAuthBridgeURN, p.bridgeGrant)
}

func bridgeRefusal(code, description string) error {
	return service.NewOAuthError(code, description, http.StatusBadRequest)
}

func (p *Provider) bridgeGrant(ctx context.Context, req service.TokenRequest) (*domain.AccessToken, error) {
	if req.SubjectToken == "" {
		return nil, bridgeRefusal(oautherror.InvalidRequest, "subject_token must be the AAuth agent token")
	}
	if req.SubjectTokenType != "" && req.SubjectTokenType != AgentTokenTypeURN {
		return nil, bridgeRefusal(oautherror.InvalidRequest, "subject_token_type must be "+AgentTokenTypeURN)
	}
	if len(req.Resource) != 1 {
		return nil, bridgeRefusal(oautherror.InvalidTarget, "name exactly one resource the token is for")
	}

	now := p.now()
	agent, err := p.key.verify(req.SubjectToken, p.cfg.Issuer, now)
	if err != nil {
		log.Info().Err(err).Msg("aauth: bridge refused an agent token")
		return nil, bridgeRefusal(oautherror.InvalidGrant, "the subject_token is not a valid agent token from this Agent Provider")
	}
	jkt, err := agent.Cnf.Thumbprint()
	if err != nil {
		return nil, bridgeRefusal(oautherror.InvalidGrant, "the agent token's cnf key has no thumbprint")
	}
	if req.DPoPKeyThumbprint == "" {
		return nil, bridgeRefusal(oautherror.InvalidRequest, "a DPoP proof signed by the agent token's key is required")
	}
	if req.DPoPKeyThumbprint != jkt {
		return nil, bridgeRefusal(oautherror.InvalidGrant, "the DPoP proof is not signed by the agent token's key")
	}

	// The row, not only the signature: revoked or unknown agent tokens are
	// refused, and so is anything that isn't one.
	row, err := p.liveAgentRow(ctx, agent.JTI, now)
	if err != nil {
		return nil, err
	}
	identity, err := p.identities.GetIdentity(ctx, *row.IdentityID, row.AccountID, row.ProjectID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, bridgeRefusal(oautherror.InvalidGrant, "the agent token's identity no longer exists")
	}
	if err != nil {
		return nil, service.NewOAuthError(oautherror.ServerError, "the agent token's identity could not be loaded", http.StatusInternalServerError)
	}
	// A request that names a tenant must name the agent's, as on the
	// federated grant (ADR 0042 D5): a tenant-routed embedder must not mint
	// for another tenant through its endpoint.
	if (req.AccountID != "" && req.AccountID != identity.AccountID) || (req.ProjectID != "" && req.ProjectID != identity.ProjectID) {
		return nil, bridgeRefusal(oautherror.InvalidGrant, "account_id or project_id does not match the agent token's tenant")
	}

	grant, err := p.oauth.ResolveWorkloadGrant(ctx, identity, req.Scope)
	if err != nil {
		return nil, err
	}
	// Never outlive the agent token it came from.
	ttl := grant.TTL
	if left := int(agent.ExpiresAt.Sub(now) / time.Second); left < ttl {
		ttl = left
	}
	if ttl <= 0 {
		return nil, bridgeRefusal(oautherror.InvalidGrant, "the agent token expires too soon to exchange")
	}

	issue := service.IssueRequest{
		Identity:          identity,
		IdentityPolicyID:  grant.Policy.ID,
		Scopes:            grant.Scopes,
		TTL:               ttl,
		GrantType:         domain.GrantTypeAAuthBridge,
		ParentJTI:         agent.JTI,     // revoking the agent token revokes this one
		MissionID:         row.MissionID, // the agent token's delegation tree
		DPoPKeyThumbprint: jkt,
		CustomClaims:      map[string]any{AgentClaim: agent.Subject},
	}
	service.BindResourceOnIssue(&issue, req.Resource)
	token, child, err := p.creds.IssueCredential(ctx, issue)
	if err != nil {
		var oe *service.OAuthError
		switch {
		case errors.As(err, &oe):
			return nil, err
		case errors.Is(err, service.ErrScopesNotAllowed):
			return nil, bridgeRefusal(oautherror.InvalidScope, err.Error())
		case errors.Is(err, service.ErrPolicyViolation) ||
			errors.Is(err, domain.ErrIdentityNotUsable) || errors.Is(err, domain.ErrIdentityExpired):
			return nil, bridgeRefusal(oautherror.InvalidGrant, err.Error())
		}
		return nil, err
	}

	// The agent token may have been revoked after the check above and before
	// the child row was written, which the revoke's cascade then missed.
	// Re-check, and revoke the child if so. A failure to read is not a
	// revocation: the child stands, and the error is the caller's to retry.
	if _, err := p.liveAgentRow(ctx, agent.JTI, p.now()); err != nil {
		var oe *service.OAuthError
		if errors.As(err, &oe) && oe.HTTPStatus >= http.StatusInternalServerError {
			log.Warn().Err(err).Str("jti", child.JTI).Msg("aauth: could not re-check the agent token after an exchange")
			return token, nil
		}
		if rErr := p.creds.RevokeCredential(ctx, child.ID, child.AccountID, child.ProjectID, "parent agent token revoked during exchange"); rErr != nil {
			log.Error().Err(rErr).Str("jti", child.JTI).Msg("aauth: could not revoke a bridged token whose agent token was revoked")
			return nil, service.NewOAuthError(oautherror.ServerError, "the exchange could not be completed", http.StatusInternalServerError)
		}
		return nil, bridgeRefusal(oautherror.InvalidGrant, "the agent token was revoked during the exchange")
	}
	return token, nil
}

// liveAgentRow returns the agent token's row if it is an unrevoked,
// unexpired aauth_agent credential with an identity. A storage failure is a
// server error, never "revoked".
func (p *Provider) liveAgentRow(ctx context.Context, jti string, now time.Time) (*domain.IssuedCredential, error) {
	row, err := p.creds.CredentialByJTI(ctx, jti)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, bridgeRefusal(oautherror.InvalidGrant, "the agent token is revoked, expired or unknown")
	}
	if err != nil {
		return nil, service.NewOAuthError(oautherror.ServerError, "the agent token could not be checked", http.StatusInternalServerError)
	}
	if row.IsRevoked || !now.Before(row.ExpiresAt) || row.GrantType != domain.GrantTypeAAuthAgent || row.IdentityID == nil {
		return nil, bridgeRefusal(oautherror.InvalidGrant, "the agent token is revoked, expired or unknown")
	}
	return row, nil
}
