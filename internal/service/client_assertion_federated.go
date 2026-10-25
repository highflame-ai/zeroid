package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/oautherror"
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
	// Until the assertion's signature verifies, every refusal is the generic
	// one an unknown client gets, and the reason goes to the log: a distinct
	// answer would tell an unsigned probe that its iss and claims matched an
	// enabled row.
	refuseUnverified := func(reason string, cause error) error {
		log.Info().Str("issuer", row.Issuer).Str("reason", reason).Err(cause).
			Msg("federated client assertion refused before verification")
		return oauthUnauthorized("invalid client credentials", cause)
	}
	if req.ClientAssertionType != clientAssertionTypeJWTBearer {
		return nil, refuseUnverified("client_assertion_type is not jwt-bearer", nil)
	}
	// One client authentication method per request (RFC 6749 §2.3).
	if req.ClientSecret != "" {
		return nil, refuseUnverified("client_secret sent with a client_assertion", nil)
	}

	// Signature against the row's JWKS, iss, the row's audiences, its claim
	// constraints, sub, exp and iat present, and the row's token-age cap.
	verified, err := validateExternalAssertion(ctx, req.ClientAssertion, entry, "client_assertion", requirePlainSub)
	if err != nil {
		var oe *OAuthError
		if errors.As(err, &oe) && oe.HTTPStatus >= http.StatusInternalServerError {
			// A server-side failure keeps its status, so the client retries
			// rather than giving up, but not its description: that can name
			// the issuer ("failed to load JWKS for issuer ..."), which an
			// unsigned probe must not learn is trusted.
			log.Warn().Str("issuer", row.Issuer).Err(err).
				Msg("federated client assertion could not be verified")
			return nil, &OAuthError{Code: oe.Code, Description: federatedAuthUnavailable, HTTPStatus: oe.HTTPStatus, err: err}
		}
		return nil, refuseUnverified(errorDescription(err), err)
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
	clientID := federatedClientID(row.Issuer, sub)
	// RFC 7523 §3 makes sub the client_id; the issued token names the client
	// as <iss>#<sub>. The handler fills an omitted client_id from the
	// assertion's iss, so that value means "not sent".
	if req.ClientID != "" && req.ClientID != row.Issuer && req.ClientID != sub && req.ClientID != clientID {
		return nil, oauthUnauthorized("client_id must equal the client_assertion's sub", nil)
	}

	// The assertion's whole lifetime, iat to exp, is capped by the row's
	// max_token_age_seconds (600 s by default). That fits STS's 300 s default
	// and Kubernetes' 600 s minimum, and refuses a long-lived token at any
	// point in its life, not only while it is fresh.
	// validateExternalAssertion has required exp and iat, and the row's age
	// cap (validated to 1..3600 s) is always set.
	exp, _ := verified.Expiration()
	iat, _ := verified.IssuedAt()
	maxLifetime := time.Duration(row.MaxTokenAgeSeconds) * time.Second
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

	// Single use, spent once the assertion itself has passed every check and
	// before the binding is read, so a captured assertion cannot replay the
	// binding and adoption refusals (and their events) over and over. Keyed on
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

	accessToken, err := s.mintFederatedClientCredentials(ctx, req, row, sub, clientID)
	if err != nil && federatedServerFailure(err) {
		// Nothing was minted, and the caller was told to retry. The assertion
		// is single use, and a Kubernetes or STS token can't be re-signed on
		// demand, so a spent jti would turn that retry into "replay" until the
		// platform token rotates. Releasing it still mints at most one token
		// per assertion. Refusals (4xx) keep it spent, as above.
		s.releaseClientAssertion(ctx, replayKey)
	}

	return accessToken, err
}

// mintFederatedClientCredentials resolves the agent bound to (row, sub) and
// mints its token. The assertion has been verified and its jti spent.
func (s *OAuthService) mintFederatedClientCredentials(
	ctx context.Context, req TokenRequest, row *domain.ExternalIssuer, sub, clientID string,
) (*domain.AccessToken, error) {
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
	// No registered client sets a scope list here, so the agent's policy and
	// row ceilings are the only bound. With neither set, refuse: the
	// registered client_credentials path refuses a client with no scopes for
	// the same reason, and grantScopes would otherwise grant whatever the
	// request names, nhi:manage included (highflame-authn#317).
	policyScopes, rowScopes := identityScopeCeilings(policy, identity)
	if len(policyScopes) == 0 && len(rowScopes) == 0 {
		return nil, oauthBadRequest(oautherror.InvalidScope,
			"the agent has no scope limit: set allowed_scopes on its identity or credential policy")
	}
	scopes, err := grantScopes(req.Scope, policyScopes, rowScopes)
	if err != nil {
		return nil, err
	}

	issue := IssueRequest{
		TTL:                 federatedAccessTokenTTL(policy),
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
