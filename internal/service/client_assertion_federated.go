package service

import (
	"context"
	"errors"
	"net/http"

	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/pkg/dpop"
)

// Federated client assertions (ADR 0042 D8, path P2): an agent authenticates
// on client_credentials with a JWT a trusted workload issuer signed for it,
// such as an AWS STS web identity token, a Kubernetes service account token
// or a SPIFFE JWT-SVID. It holds no secret and registers no key. The
// assertion's (iss, sub) names the agent through an enabled binding under the
// issuer's workload row (D6), and the tenant is the bound identity's (D5).

// federatedGrantClientCredentials names this path in the unmatched-agent and
// adoption metrics.
const federatedGrantClientCredentials = "client_credentials"

// ClientAuthClaim marks an access token whose client authenticated with a
// federated client assertion. Such a token is held by whatever runs the
// agent's credential provider (an AgentCore token vault, a gateway) rather
// than by a key the agent controls, so agent self-service refuses it: it must
// not become a durable key on an agent that was meant to hold no secret.
const (
	ClientAuthClaim              = "client_auth"
	ClientAuthFederatedAssertion = "federated_assertion"
)

// federatedAuthUnavailable is the description of a server-side failure to
// verify a federated client assertion. The detail goes to the log.
const federatedAuthUnavailable = "client authentication is temporarily unavailable"

// workloadIssuerFor reports whether req's client_assertion was issued by an
// enabled workload issuer row, and returns its entry (see
// LookupWorkloadIssuer). An assertion whose iss names no workload row (a
// registered client's own private_key_jwt) returns ok=false and keeps today's
// registered-client path.
func (s *OAuthService) workloadIssuerFor(ctx context.Context, req TokenRequest) (*ExternalIssuerEntry, bool, error) {
	return s.LookupWorkloadIssuer(ctx, req.ClientAssertion)
}

// federatedClientCredentials mints a client_credentials token for the agent a
// federated client assertion is bound to.
func (s *OAuthService) federatedClientCredentials(ctx context.Context, req TokenRequest, entry *ExternalIssuerEntry) (*domain.AccessToken, error) {
	row := entry.Row
	// Until the assertion's signature verifies, every refusal is the generic
	// one an unknown client gets, and the reason goes to the log: a distinct
	// answer would tell an unsigned probe that its iss and claims matched an
	// enabled row.
	if req.ClientAssertionType != clientAssertionTypeJWTBearer {
		return nil, refuseUnverifiedWorkload(row, "client_assertion_type is not jwt-bearer", nil)
	}
	// One client authentication method per request (RFC 6749 §2.3).
	if req.ClientSecret != "" {
		return nil, refuseUnverifiedWorkload(row, "client_secret sent with a client_assertion", nil)
	}

	var clientID string
	wa, err := s.VerifyWorkloadAssertion(ctx, req.ClientAssertion, entry, "client_assertion", func(sub string) error {
		clientID = federatedClientID(row.Issuer, sub)
		// RFC 7523 §3 makes sub the client_id; the issued token names the
		// client as <iss>#<sub>. The handler fills an omitted client_id from
		// the assertion's iss, so that value means "not sent".
		if req.ClientID != "" && req.ClientID != row.Issuer && req.ClientID != sub && req.ClientID != clientID {
			return oauthUnauthorized("client_id must equal the client_assertion's sub", nil)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Single use, spent once the assertion itself has passed every check and
	// before the binding is read, so a captured assertion cannot replay the
	// binding and adoption refusals (and their events) over and over.
	if err := s.SpendWorkloadAssertion(ctx, wa); err != nil {
		if errors.Is(err, dpop.ErrReplay) {
			return nil, oauthUnauthorized("client_assertion has already been used (replay)", nil)
		}
		var oe *OAuthError
		if errors.As(err, &oe) {
			return nil, err
		}
		return nil, oauthServerError("client assertion replay check failed", err)
	}

	accessToken, err := s.mintFederatedClientCredentials(ctx, req, row, wa.Subject, clientID, wa.Claims)
	if err != nil && federatedServerFailure(err) {
		// Nothing was minted, and the caller was told to retry. The assertion
		// is single use, and a Kubernetes or STS token can't be re-signed on
		// demand, so a spent jti would turn that retry into "replay" until the
		// platform token rotates. Releasing it still mints at most one token
		// per assertion. Refusals (4xx) keep it spent, as above.
		s.ReleaseWorkloadAssertion(ctx, wa)
	}

	return accessToken, err
}

// mintFederatedClientCredentials resolves the agent bound to (row, sub) and
// mints its token. The assertion has been verified and its jti spent, so it
// may register the agent on first contact; claims are its verified claims.
func (s *OAuthService) mintFederatedClientCredentials(
	ctx context.Context, req TokenRequest, row *domain.ExternalIssuer, sub, clientID string, claims map[string]any,
) (*domain.AccessToken, error) {
	firstContact := s.firstContactFor(row, sub, federatedGrantClientCredentials, claims, nil)
	identity, err := s.bindFederatedAgent(ctx, row, sub, nil, federatedGrantClientCredentials, firstContact)
	if err != nil {
		return nil, err
	}
	if err := federatedTenant(identity, req.AccountID, req.ProjectID); err != nil {
		return nil, err
	}
	// clientCredentials recorded the request; the client here is the
	// federated issuer and subject, which registered no scope list.
	trace := scopeTraceFrom(ctx)
	trace.setClientID(clientID)
	trace.setIdentity(identity)

	grant, err := s.ResolveWorkloadGrant(ctx, identity, req.Scope)
	if err != nil {
		return nil, err
	}
	policy, scopes := grant.Policy, grant.Scopes

	issue := IssueRequest{
		TTL:                 grant.TTL,
		Identity:            identity,
		IdentityPolicyID:    policy.ID,
		Scopes:              scopes,
		GrantType:           domain.GrantTypeClientCredentials,
		DPoPKeyThumbprint:   req.DPoPKeyThumbprint,
		ClientID:            clientID,
		FederatedClientAuth: true,
	}
	bindResourceOnIssue(&issue, req.Resource)

	accessToken, _, err := s.credentialSvc.IssueCredential(ctx, issue)
	if err != nil {
		return nil, err
	}
	return accessToken, nil
}

// errorDescription returns an OAuth error's client-facing description, or the
// error text for any other error.
func errorDescription(err error) string {
	var oe *OAuthError
	if errors.As(err, &oe) {
		return oe.Description
	}
	return err.Error()
}

// federatedClientID is the client_id claim of a token minted from a federated
// client assertion: <iss>#<sub>. Always qualified, even for subjects that
// look globally unique such as an AWS role ARN: any account can add its own
// issuer and bind any subject string, so a bare sub would let one tenant mint
// tokens carrying another tenant's client_id. The issuer is the part an
// assertion cannot fake, since it verifies against that issuer's keys.
// Issuer URLs carry no fragment, so the first '#' always separates the two.
func federatedClientID(issuer, sub string) string {
	return issuer + "#" + sub
}

// federatedAccessTokenMaxTTL is the lifetime (seconds) of a token minted on a
// federated client assertion: 15 minutes, like the other paths where an
// external issuer authenticates the caller (ADR 0042 D9; ID-JAG and ID-token
// exchange set the same). Disabling a binding or an issuer row stops new
// mints but does not revoke tokens already issued, so this bounds how long
// one outlives that change.
const federatedAccessTokenMaxTTL = 900

// federatedAccessTokenTTL is federatedAccessTokenMaxTTL, or the identity
// policy's max_ttl_seconds when that is shorter. IssueCredential holds a
// requested lifetime to the policy as a hard limit, so asking for 15 minutes
// under a stricter policy would refuse the mint instead of shortening it.
func federatedAccessTokenTTL(policy *domain.CredentialPolicy) int {
	if policy != nil && policy.MaxTTLSeconds > 0 && policy.MaxTTLSeconds < federatedAccessTokenMaxTTL {
		return policy.MaxTTLSeconds
	}

	return federatedAccessTokenMaxTTL
}

// federatedServerFailure reports whether a mint failed on the server side
// (the token endpoint answers 5xx), as opposed to a refusal of the request.
func federatedServerFailure(err error) bool {
	var oauthErr *OAuthError
	if errors.As(err, &oauthErr) {
		return oauthErr.HTTPStatus >= http.StatusInternalServerError
	}

	return !issuanceRefusal(err)
}

// clientAssertionReplayReleaser is implemented by replay stores that can
// forget a jti (the Postgres store). A store without it keeps the jti spent.
type clientAssertionReplayReleaser interface {
	Release(ctx context.Context, jti string) error
}

// releaseClientAssertion forgets a spent client-assertion jti, best effort.
func (s *OAuthService) releaseClientAssertion(ctx context.Context, replayKey string) {
	releaser, ok := s.clientAssertionReplay.(clientAssertionReplayReleaser)
	if !ok {
		return
	}
	if err := releaser.Release(ctx, replayKey); err != nil {
		log.Warn().Err(err).Msg("could not release a client assertion after a server error; its retry will be refused as a replay")
	}
}
