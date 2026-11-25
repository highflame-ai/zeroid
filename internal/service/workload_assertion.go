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
)

// Workload assertions (ADR 0042 D8, path P2) are the tokens a workload's
// platform signs for it in place of a secret: an AWS STS web identity token,
// a Kubernetes service account token, a SPIFFE JWT-SVID. These checks are
// shared by the federated client_credentials grant and the AAuth agent
// provider (internal/aauth), so a platform token means the same thing at both
// endpoints and is spent in one replay namespace: it cannot be redeemed once
// at each.

// WorkloadAssertion is a workload assertion that has passed every check but
// has not been spent.
type WorkloadAssertion struct {
	// Entry is the enabled workload issuer row the assertion verified under.
	Entry *ExternalIssuerEntry
	// Subject is the assertion's sub: an AWS role ARN,
	// system:serviceaccount:<ns>:<name>, a SPIFFE ID.
	Subject string
	// ExpiresAt is the assertion's exp.
	ExpiresAt time.Time
	// Claims are the assertion's verified claims, which first contact
	// records an allowlisted subset of.
	Claims map[string]any
	// ReplayKey names the assertion in the shared single-use store: keyed on
	// (iss, sub, jti), because a Kubernetes subject repeats across clusters,
	// so the subject alone does not name one client.
	ReplayKey string
}

// LookupWorkloadIssuer and the pre-verification refusals keep the
// client_credentials wording ("invalid client credentials") that grant has
// always returned; other callers map every pre-verification refusal to their
// own single generic answer, so the wording never reaches their clients.
//
// The accepted audiences are this server's issuer and token endpoint at every
// caller: platforms mint for "ZeroID", not for one of its endpoints, and the
// shared single-use namespace is what stops one token being redeemed at two.

// LookupWorkloadIssuer reports whether assertion was issued by an enabled
// workload issuer row, and returns its entry. An assertion whose iss names no
// workload row (a registered client's own private_key_jwt) returns ok=false.
// An iss that does name workload rows but matches none usably is refused here:
// explicit issuer configuration wins, it is never guessed around.
func (s *OAuthService) LookupWorkloadIssuer(ctx context.Context, assertion string) (*ExternalIssuerEntry, bool, error) {
	if assertion == "" || s.externalIssuerRegistry == nil || !s.externalIssuerRegistry.DBMode() {
		return nil, false, nil
	}
	peeked, err := jwt.ParseInsecure([]byte(assertion))
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
		// verified yet, so the refusal is the generic one an unknown client
		// gets: a distinct answer would tell an unsigned probe which issuers,
		// and which claim values, an account trusts. The reason goes to the log.
		log.Info().Str("issuer", iss).Err(err).Msg("federated client assertion refused before verification")
		return nil, false, oauthUnauthorized("invalid client credentials", err)
	}
}

// VerifyWorkloadAssertion runs every check on a workload assertion except
// spending it: signature against the row's JWKS, iss, the row's audiences and
// claim constraints, sub, a single aud naming this server, the row's lifetime
// cap and a usable jti. afterAudience, when set, runs once the audience has
// been checked and before the lifetime is; it lets a caller keep its own
// checks in the order it has always made them. field names the request
// parameter in error descriptions.
func (s *OAuthService) VerifyWorkloadAssertion(ctx context.Context, assertion string, entry *ExternalIssuerEntry,
	field string, afterAudience func(sub string) error,
) (*WorkloadAssertion, error) {
	if entry == nil || entry.Row == nil {
		return nil, oauthServerError("no workload issuer row to verify against", nil)
	}
	row := entry.Row

	// Signature against the row's JWKS, iss, the row's audiences, its claim
	// constraints, sub, exp and iat present, and the row's token-age cap.
	verified, err := validateExternalAssertion(ctx, assertion, entry, field, requirePlainSub)
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
		return nil, refuseUnverifiedWorkload(row, errorDescription(err), err)
	}

	// D8: aud is single-valued and names this server: its issuer or its
	// token endpoint (RFC 7523 §3). STS lets one token carry up to ten
	// audiences, and a token minted for several servers, or for a broad
	// audience such as a cluster's API server, can be replayed at each.
	aud, _ := verified.Audience()
	if len(aud) != 1 {
		return nil, oauthUnauthorized(field+" aud must name exactly one audience", nil)
	}
	if !s.acceptedClientAssertionAudiences()[aud[0]] {
		return nil, oauthUnauthorized(field+" aud must be this server's issuer or token endpoint", nil)
	}

	sub, _ := verified.Subject()
	if afterAudience != nil {
		if err := afterAudience(sub); err != nil {
			return nil, err
		}
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
			"%s lifetime exceeds the issuer's %s", field, maxLifetime), nil)
	}
	jti, ok := verified.JwtID()
	if !ok || jti == "" {
		return nil, oauthUnauthorized(field+" missing required jti claim", nil)
	}
	if len(jti) > maxClientAssertionJTILength {
		return nil, oauthUnauthorized(fmt.Sprintf(
			"%s jti exceeds %d characters", field, maxClientAssertionJTILength), nil)
	}

	return &WorkloadAssertion{
		Entry:     entry,
		Subject:   sub,
		ExpiresAt: exp,
		Claims:    tokenClaimsAsMap(verified),
		ReplayKey: clientAssertionReplayKey("federated\x00"+row.Issuer+"\x00"+sub, jti),
	}, nil
}

// refuseUnverifiedWorkload is the refusal for an assertion whose signature
// has not verified: the generic one an unknown client gets, with the reason in
// the log. A distinct answer would tell an unsigned probe that its iss and
// claims matched an enabled row.
func refuseUnverifiedWorkload(row *domain.ExternalIssuer, reason string, cause error) error {
	log.Info().Str("issuer", row.Issuer).Str("reason", reason).Err(cause).
		Msg("federated client assertion refused before verification")
	return oauthUnauthorized("invalid client credentials", cause)
}

// SpendWorkloadAssertion records wa as used in the shared single-use store.
// A second spend of the same assertion, at either endpoint, returns
// dpop.ErrReplay; any other error is the store's.
func (s *OAuthService) SpendWorkloadAssertion(ctx context.Context, wa *WorkloadAssertion) error {
	if wa == nil {
		return oauthServerError("no workload assertion to spend", nil)
	}
	if s.clientAssertionReplay == nil {
		return oauthServerError("client assertion replay store is not configured", nil)
	}
	return s.clientAssertionReplay.Insert(ctx, wa.ReplayKey, wa.ExpiresAt.Add(clientAssertionClockSkew))
}

// ReleaseWorkloadAssertion forgets a spent assertion after a server-side
// failure minted nothing, so a retry with the same platform token works: a
// Kubernetes or STS token can't be re-signed on demand. Best effort.
func (s *OAuthService) ReleaseWorkloadAssertion(ctx context.Context, wa *WorkloadAssertion) {
	if wa == nil {
		return
	}
	s.releaseClientAssertion(ctx, wa.ReplayKey)
}

// ResolveWorkloadAgent returns the active identity an enabled binding maps
// the assertion's subject to, under its issuer row (ADR 0042 D6, D7). grant
// labels the unmatched-agent and adoption metrics. The assertion must have
// been spent: an unbound subject is handled as the row's first_contact says,
// exactly as at the federated client_credentials grant, so a platform token
// means the same thing at both endpoints.
func (s *OAuthService) ResolveWorkloadAgent(ctx context.Context, wa *WorkloadAssertion, grant string) (*domain.Identity, error) {
	if wa == nil || wa.Entry == nil || wa.Entry.Row == nil {
		return nil, oauthServerError("no workload assertion to resolve", nil)
	}
	row := wa.Entry.Row
	firstContact := s.firstContactFor(row, wa.Subject, grant, wa.Claims, nil)
	return s.bindFederatedAgent(ctx, row, wa.Subject, nil, grant, firstContact)
}

// WorkloadGrant is what a workload's identity may be issued on its own
// authority: its governing policy, the requested scopes narrowed to its
// ceilings, and the lifetime.
type WorkloadGrant struct {
	Policy *domain.CredentialPolicy
	Scopes []string
	TTL    int
}

// ResolveWorkloadGrant narrows requestedScope to identity's policy and row
// ceilings. With neither set it refuses: a workload with no scope limit would
// otherwise be issued whatever the request names, nhi:manage included
// (highflame-authn#317).
func (s *OAuthService) ResolveWorkloadGrant(ctx context.Context, identity *domain.Identity, requestedScope string) (*WorkloadGrant, error) {
	policy, err := s.identitySvc.ResolveCredentialPolicy(ctx, identity)
	if err != nil {
		return nil, oauthServerError("failed to resolve identity credential policy", err)
	}
	policyScopes, rowScopes := identityScopeCeilings(policy, identity)
	if len(policyScopes) == 0 && !identity.ScopeCeilingRestricts() {
		return nil, oauthBadRequest(oautherror.InvalidScope,
			"the agent has no scope limit: set allowed_scopes on its identity or credential policy")
	}
	// The request's scope trace, when one was started, records both ceilings.
	trace := scopeTraceFrom(ctx)
	trace.ceiling(policyCeilingName(ownerIdentity, false), policyScopes)
	trace.identityCeiling(ceilingIdentityScopes, identity)
	scopes, err := grantIdentityScopes(requestedScope, identity, policyScopes, rowScopes)
	if err != nil {
		return nil, err
	}
	return &WorkloadGrant{Policy: policy, Scopes: scopes, TTL: federatedAccessTokenTTL(policy)}, nil
}
