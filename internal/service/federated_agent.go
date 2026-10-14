package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/oautherror"
	"github.com/highflame-ai/zeroid/internal/telemetry"
)

// issuerBindingSource reads credential bindings;
// *postgres.ExternalIssuerRepository.
type issuerBindingSource interface {
	EnabledBinding(ctx context.Context, issuerID, subjectKey string) (*domain.IssuerBinding, error)
}

// SetIssuerBindings installs the binding store the federated person grants
// map agents through when issuers are account rows.
func (s *OAuthService) SetIssuerBindings(b issuerBindingSource) {
	s.issuerBindings = b
}

// Grant names for the unmatched-agent and adoption metrics.
const (
	federatedGrantIDJAG   = "id_jag"
	federatedGrantIDToken = "id_token"
)

// bindFederatedAgent maps the agent a federated person grant names to its
// own identity through an enabled binding under the issuer row (ADR 0042
// D6), and refuses an identity that is not active (D7). subjectKey is the
// value the credential carries at runtime: the ID-JAG's act.sub, or the
// presenting client's client_id on the ID-token exchange.
//
// There is no synthetic identity: no binding, or a client registered to a
// different identity, is invalid_grant and an unmatched-agent event.
func (s *OAuthService) bindFederatedAgent(ctx context.Context, row *domain.ExternalIssuer, subjectKey string,
	client *domain.OAuthClient, grant string,
) (*domain.Identity, error) {
	if s.issuerBindings == nil {
		return nil, oauthServerError("credential bindings are not configured", nil)
	}
	return bindAgent(ctx, s.issuerBindings, s.identitySvc.repo.GetByIDInAccounts, row, subjectKey, client, grant)
}

func bindAgent(ctx context.Context, bindings issuerBindingSource, lookup linkedIdentityLookup, row *domain.ExternalIssuer,
	subjectKey string, client *domain.OAuthClient, grant string,
) (*domain.Identity, error) {
	if subjectKey == "" {
		recordUnmatchedAgent(ctx, row, subjectKey, grant, "no_subject_key")
		return nil, oauthBadRequest(oautherror.InvalidGrant, "the credential names no agent to bind (no act.sub)")
	}
	binding, err := bindings.EnabledBinding(ctx, row.ID, subjectKey)
	if err != nil {
		return nil, oauthServerError("failed to read the agent's credential binding", err)
	}
	if binding == nil {
		recordUnmatchedAgent(ctx, row, subjectKey, grant, "no_binding")
		return nil, oauthBadRequest(oautherror.InvalidGrant,
			fmt.Sprintf("no enabled binding maps agent %q under issuer %s to an identity", subjectKey, row.Issuer))
	}
	identity, err := lookup(ctx, binding.IdentityID, []string{row.AccountID})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			recordUnmatchedAgent(ctx, row, subjectKey, grant, "no_identity")
			return nil, oauthBadRequestCause(oautherror.InvalidGrant, "the agent's binding names no identity in the issuer's account", err)
		}
		return nil, oauthServerError("failed to load the agent's identity", err)
	}
	if client != nil && !client.SelfAsserted() && client.IdentityID != nil && *client.IdentityID != identity.ID {
		recordUnmatchedAgent(ctx, row, subjectKey, grant, "client_mismatch")
		return nil, oauthBadRequest(oautherror.InvalidGrant,
			"the authenticated client is registered to a different identity than the agent's binding")
	}
	if identity.Status != domain.IdentityStatusActive {
		recordAgentNotAdopted(ctx, row, identity, grant)
		return nil, oauthBadRequest(oautherror.InvalidGrant,
			fmt.Sprintf("agent identity is %s; tokens are minted only for an adopted (active) identity", identity.Status))
	}
	if identity.IsExpired() {
		return nil, oauthBadRequest(oautherror.InvalidGrant, "identity_expired")
	}
	return identity, nil
}

// federatedTenant applies ADR 0042 D5: the tenant is the bound identity's,
// and a request that names one must name the same.
func federatedTenant(identity *domain.Identity, reqAccountID, reqProjectID string) error {
	if reqAccountID != "" && reqAccountID != identity.AccountID {
		return oauthBadRequest(oautherror.InvalidGrant, "account_id does not match the tenant derived from the issuer and the agent's binding")
	}
	if reqProjectID != "" && reqProjectID != identity.ProjectID {
		return oauthBadRequest(oautherror.InvalidGrant, "project_id does not match the tenant derived from the issuer and the agent's binding")
	}
	return nil
}

// recordUnmatchedAgent is the unmatched-agent event (ADR 0027): a credential
// from a trusted issuer that maps to no adopted identity. A log line and a
// metric; ZeroID has no event bus.
func recordUnmatchedAgent(ctx context.Context, row *domain.ExternalIssuer, subjectKey, grant, reason string) {
	telemetry.FederationUnmatchedAgent.Add(ctx, 1, metric.WithAttributes(
		attribute.String("account_id", row.AccountID),
		attribute.String("grant_type", grant),
		attribute.String("reason", reason),
	))
	log.Warn().
		Str("account_id", row.AccountID).
		Str("issuer_id", row.ID).
		Str("issuer", row.Issuer).
		Str("subject_key", subjectKey).
		Str("grant_type", grant).
		Str("reason", reason).
		Msg("federation_unmatched_agent")
}

func recordAgentNotAdopted(ctx context.Context, row *domain.ExternalIssuer, identity *domain.Identity, grant string) {
	telemetry.FederationAgentNotAdopted.Add(ctx, 1, metric.WithAttributes(
		attribute.String("account_id", row.AccountID),
		attribute.String("grant_type", grant),
		attribute.String("status", string(identity.Status)),
	))
	log.Info().
		Str("account_id", row.AccountID).
		Str("project_id", identity.ProjectID).
		Str("identity_id", identity.ID).
		Str("status", string(identity.Status)).
		Str("grant_type", grant).
		Msg("federation_agent_not_adopted")
}

// actorSubject returns the ID-JAG's act.sub, the agent's IdP client id.
func actorSubject(claims map[string]any) string {
	act, _ := claims["act"].(map[string]any)
	sub, _ := act["sub"].(string)
	return sub
}
