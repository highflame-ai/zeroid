package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwt"
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

// workloadIssuerFor reports whether req's client_assertion was issued by an
// enabled workload issuer row, and returns its entry. An assertion whose iss
// names no workload row (a registered client's own private_key_jwt) returns
// ok=false and keeps today's registered-client path. An iss that does name
// workload rows but matches none usably is refused here rather than handed to
// that path: explicit issuer configuration wins, it is never guessed around.
func (s *OAuthService) workloadIssuerFor(ctx context.Context, req TokenRequest) (*ExternalIssuerEntry, bool, error) {
	if req.ClientAssertion == "" || s.externalIssuerRegistry == nil || !s.externalIssuerRegistry.DBMode() {
		return nil, false, nil
	}
	peeked, err := jwt.ParseInsecure([]byte(req.ClientAssertion))
	if err != nil {
		return nil, false, nil
	}
	iss, ok := peeked.Issuer()
	if !ok || iss == "" {
		return nil, false, nil
	}
	entry, err := s.externalIssuerRegistry.ResolveWorkload(ctx, iss, tokenClaimsAsMap(peeked))
	switch {
	case err == nil:
		return entry, true, nil
	case errors.Is(err, ErrUnknownExternalIssuer), errors.Is(err, errIssuerNotWorkload):
		return nil, false, nil
	case errors.Is(err, errIssuerLookupFailed):
		return nil, false, oauthServerError("failed to resolve the client assertion's issuer", err)
	default:
		// Disabled, constraints unmet, or ambiguous. The assertion is not
		// verified yet, so the refusal is the registered path's generic one:
		// a distinct answer would tell an unsigned probe which issuers, and
		// which claim values, an account trusts. The reason goes to the log.
		log.Info().Str("issuer", iss).Err(err).Msg("federated client assertion refused before verification")
		return nil, false, oauthUnauthorized("invalid client credentials", err)
	}
}

// federatedClientCredentials mints a client_credentials token for the agent a
// federated client assertion is bound to.
func (s *OAuthService) federatedClientCredentials(ctx context.Context, req TokenRequest, entry *ExternalIssuerEntry) (*domain.AccessToken, error) {
	row := entry.Row
	if req.ClientAssertionType != clientAssertionTypeJWTBearer {
		return nil, oauthUnauthorized(fmt.Sprintf(
			"client_assertion_type must be %q", clientAssertionTypeJWTBearer), nil)
	}

	// Signature against the row's JWKS, iss, the row's audiences, its claim
	// constraints, sub and exp present, and the row's token-age cap.
	verified, err := validateExternalAssertion(ctx, req.ClientAssertion, entry, "client_assertion", requirePlainSub)
	if err != nil {
		var oe *OAuthError
		if errors.As(err, &oe) && oe.HTTPStatus >= http.StatusInternalServerError {
			return nil, err
		}
		// A client-authentication failure is invalid_client (RFC 6749 §5.2).
		return nil, oauthUnauthorized(errorDescription(err), err)
	}

	// D8: aud is single-valued and names this server: its issuer or its
	// token endpoint (RFC 7523 §3). STS lets one token carry up to ten
	// audiences, and a token minted for several servers, or for a broad
	// audience such as a cluster's API server, can be replayed at each.
	aud, _ := verified.Audience()
	if len(aud) != 1 {
		return nil, oauthUnauthorized("client_assertion aud must name exactly one audience", nil)
	}
	if !s.acceptedClientAssertionAudiences()[aud[0]] {
		return nil, oauthUnauthorized("client_assertion aud must be this server's issuer or token endpoint", nil)
	}

	sub, _ := verified.Subject()
	// RFC 7523 §3 makes sub the client_id. The handler fills an omitted
	// client_id from the assertion's iss, so that value is "not sent".
	if req.ClientID != "" && req.ClientID != row.Issuer && req.ClientID != sub {
		return nil, oauthUnauthorized("client_id must equal the client_assertion's sub", nil)
	}

	// The assertion's whole lifetime, iat to exp, is capped by the row's
	// max_token_age_seconds (600 s by default). That fits STS's 300 s default
	// and Kubernetes' 600 s minimum, and refuses a long-lived token at any
	// point in its life, not only while it is fresh.
	exp, _ := verified.Expiration()
	iat, ok := verified.IssuedAt()
	if !ok {
		return nil, oauthUnauthorized("client_assertion missing required iat claim", nil)
	}
	maxLifetime := time.Duration(row.MaxTokenAgeSeconds) * time.Second
	if maxLifetime <= 0 {
		maxLifetime = time.Duration(domain.DefaultIssuerMaxTokenAgeSeconds) * time.Second
	}
	if exp.Sub(iat) > maxLifetime {
		return nil, oauthUnauthorized(fmt.Sprintf(
			"client_assertion lifetime exceeds the issuer's %s", maxLifetime), nil)
	}
	jti, ok := verified.JwtID()
	if !ok || jti == "" {
		return nil, oauthUnauthorized("client_assertion missing required jti claim", nil)
	}
	if len(jti) > maxClientAssertionJTILength {
		return nil, oauthUnauthorized(fmt.Sprintf(
			"client_assertion jti exceeds %d characters", maxClientAssertionJTILength), nil)
	}

	identity, err := s.bindFederatedAgent(ctx, row, sub, nil, federatedGrantClientCredentials)
	if err != nil {
		return nil, err
	}
	if err := federatedTenant(identity, req.AccountID, req.ProjectID); err != nil {
		return nil, err
	}

	policy, err := s.identitySvc.ResolveCredentialPolicy(ctx, identity)
	if err != nil {
		return nil, oauthServerError("failed to resolve identity credential policy", err)
	}
	// No registered client sets a scope list here; the agent's policy and
	// row ceilings bound the grant, as on the agent's own jwt-bearer grant.
	policyScopes, rowScopes := identityScopeCeilings(policy, identity)
	scopes, err := grantScopes(req.Scope, policyScopes, rowScopes)
	if err != nil {
		return nil, err
	}

	// Single use, recorded after every check this grant makes, so an
	// assertion refused for its scope or binding keeps its jti. Keyed on
	// (iss, sub, jti): a Kubernetes subject repeats across clusters, so the
	// subject alone does not name one client.
	if s.clientAssertionReplay == nil {
		return nil, oauthServerError("client assertion replay store is not configured", nil)
	}
	replayKey := clientAssertionReplayKey("federated\x00"+row.Issuer+"\x00"+sub, jti)
	if err := s.clientAssertionReplay.Insert(ctx, replayKey, exp.Add(clientAssertionClockSkew)); err != nil {
		if errors.Is(err, dpop.ErrReplay) {
			return nil, oauthUnauthorized("client_assertion has already been used (replay)", nil)
		}
		return nil, oauthServerError("client assertion replay check failed", err)
	}

	issue := IssueRequest{
		ScopeCeilingUnbounded: len(policyScopes) == 0 && len(rowScopes) == 0,
		Identity:              identity,
		IdentityPolicyID:      policy.ID,
		Scopes:                scopes,
		GrantType:             domain.GrantTypeClientCredentials,
		DPoPKeyThumbprint:     req.DPoPKeyThumbprint,
		ClientID:              federatedClientID(row.Issuer, sub),
		FederatedClientAuth:   true,
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

// kubernetesSubjectPrefix starts a Kubernetes service account subject,
// system:serviceaccount:<namespace>:<name>.
const kubernetesSubjectPrefix = "system:serviceaccount:"

// federatedClientID is the client_id claim of a token minted from a federated
// client assertion. Where the subject is globally unique (an AWS role ARN
// names its account, a SPIFFE ID its trust domain, an Entra object id its
// tenant), the client is the subject itself (RFC 7523 §3). A Kubernetes
// service account subject repeats across clusters, so there the client is the
// (issuer, subject) pair (ADR 0042 D8): two clusters' agents:foo must not
// share a client_id downstream.
func federatedClientID(issuer, sub string) string {
	if strings.HasPrefix(sub, kubernetesSubjectPrefix) {
		return issuer + "#" + sub
	}
	return sub
}
