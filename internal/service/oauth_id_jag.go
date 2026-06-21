package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/oautherror"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// idJAGTyp is the JWS `typ` header value that identifies an assertion as an
// MCP Enterprise-Managed-Authorization ID-JAG (Identity Assertion Authorization
// Grant), per the ext-auth STABLE spec
// (draft-ietf-oauth-identity-assertion-authz-grant §4.4.1 / ADR 0010). The
// jwt-bearer grant branches on this value: an assertion carrying it is an
// ID-JAG signed by a corporate IdP and MUST be validated against that IdP's
// JWKS via the #88 external-issuer substrate, NOT the NHI self-signed
// registered-key path.
const idJAGTyp = "oauth-id-jag+jwt"

// idJAGGrantProfile is the authorization grant profile URN ZeroID advertises in
// the AS metadata's authorization_grant_profiles_supported field (ADR 0010 D6).
const idJAGGrantProfile = "urn:ietf:params:oauth:grant-profile:id-jag"

// isIDJAGAssertion reports whether the compact JWS in assertion carries the
// ID-JAG typ header. An unreadable header returns false — such an assertion
// falls through to the NHI self-signed jwt-bearer path, which then rejects it
// during its own parse/validate (fail closed; never silently treated as
// external).
func isIDJAGAssertion(assertion string) bool {
	hdr, ok := decodeJWTHeader(assertion)
	if !ok {
		return false
	}
	return hdr.Typ == idJAGTyp
}

// idJAGBearer mints an audience-restricted ZeroID access token from an MCP
// ID-JAG presented at POST /oauth2/token with
// grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer (ADR 0010 D2-D4).
//
// ZeroID plays the MCP Authorization Server role: the corporate IdP (Okta /
// Entra) has already evaluated admission policy and minted the ID-JAG carrying
// the target MCP server (`resource`) and the IdP-scoped `scope`. ZeroID
// validates the ID-JAG against that IdP's JWKS (reusing validateExternalAssertion
// — the same #88 substrate the id_token-exchange path uses), maps the external
// identity to a Highflame principal, and mints a ZeroID access token
// audience-restricted to `resource`. The ID-JAG terminates here; only the minted
// ZeroID token travels downstream to Firehog/Shield (ADR 0010 D5).
//
// Fail closed (OAuth invalid_grant, never mint) when: the issuer is not a
// configured external issuer, the AllowedAccounts tenant binding does not permit
// the request, signature/claim validation fails, the external identity cannot be
// mapped, or the `resource` audience claim is absent (D3, D4).
func (s *OAuthService) idJAGBearer(ctx context.Context, req TokenRequest) (*domain.AccessToken, error) {
	if s.externalIssuerRegistry == nil || !s.externalIssuerRegistry.HasAny() {
		// No external issuers configured → ID-JAG federation is disabled. The
		// IdP is the trust anchor; without one there is nothing to validate the
		// ID-JAG against, so fail closed rather than fall back to any other path.
		return nil, oauthBadRequest(oautherror.InvalidGrant, "ID-JAG federation is not configured (no external issuers)")
	}
	// account_id / project_id are caller-supplied form fields (same as the
	// id_token-exchange path) — they are the tenant the AllowedAccounts binding
	// gates against. Tenant cannot be derived from the ID-JAG: it is born at the
	// corporate IdP, which has no notion of a Highflame tenant.
	if req.AccountID == "" || req.ProjectID == "" {
		return nil, oauthBadRequest(oautherror.InvalidRequest, "account_id and project_id are required for the ID-JAG jwt-bearer grant")
	}

	// Peek at the assertion to extract iss without verifying — we need iss to
	// look up which IdP's JWKS to validate against. (typ was already confirmed
	// as oauth-id-jag+jwt by the caller's isIDJAGAssertion branch.)
	peeked, err := jwt.ParseInsecure([]byte(req.Subject))
	if err != nil {
		return nil, oauthBadRequestCause(oautherror.InvalidGrant, "ID-JAG assertion is malformed", err)
	}
	upstreamIss, ok := peeked.Issuer()
	if !ok || upstreamIss == "" {
		return nil, oauthBadRequest(oautherror.InvalidGrant, "ID-JAG assertion missing iss claim")
	}

	entry := s.externalIssuerRegistry.Lookup(upstreamIss)
	if entry == nil {
		// Unknown issuer. Unlike the id_token-exchange path (which classifies
		// this as invalid_request because the token may be valid against its
		// real IdP and the failure is purely a deployer-config gap), ADR 0010
		// D3 mandates fail-closed with invalid_grant for the ID-JAG path: an
		// ID-JAG from an unconfigured IdP cannot be mapped to a Highflame
		// principal, so the grant is invalid. Wrap the sentinel so callers can
		// still errors.Is it for logging/branching.
		return nil, oauthBadRequestCause(
			oautherror.InvalidGrant,
			fmt.Sprintf("issuer %s is not a configured external issuer", upstreamIss),
			fmt.Errorf("%w: %s", ErrUnknownExternalIssuer, upstreamIss),
		)
	}
	cfg := entry.Config

	// Tenant binding — the only thing that ties an upstream ID-JAG to a
	// Highflame tenant. AllowedAccounts is required+non-empty at config load;
	// a request whose account_id is not listed fails closed (D3).
	if !cfg.AccountAllowed(req.AccountID) {
		return nil, oauthBadRequest(oautherror.InvalidGrant, fmt.Sprintf("account %s is not allowed to use issuer %s", req.AccountID, upstreamIss))
	}

	// Confidential-client authentication (ADR 0010 D2b). A leaked ID-JAG must
	// not be redeemable by another party: the draft (with §9.1) requires
	// redemption to come from an authenticated confidential client. Require
	// client_id (no client auth presented → invalid_client) and verify the
	// secret via the same path client_credentials uses, mirroring its sentinel
	// mapping. The client_id-binding half of D2b runs after the ID-JAG is
	// verified (we need its client_id claim).
	if req.ClientID == "" {
		return nil, oauthUnauthorized("ID-JAG redemption requires confidential client authentication", nil)
	}
	authedClient, err := s.oauthClientSvc.VerifyClientSecret(ctx, req.ClientID, req.ClientSecret)
	if err != nil {
		if errors.Is(err, ErrOAuthClientNotFound) || errors.Is(err, ErrInvalidClientSecret) {
			return nil, oauthUnauthorized("invalid client credentials", err)
		}
		return nil, oauthUnauthorized("client verification failed", err)
	}

	// Verify the ID-JAG against its IdP — signature (JWKS), iss, aud, exp/nbf,
	// alg allow-list, MaxTokenAge, sub/exp/iat presence. Shared verbatim with
	// the id_token-exchange path (validateExternalAssertion); "assertion" names
	// the wire field for ID-JAG callers.
	verified, err := s.validateExternalAssertion(ctx, req.Subject, entry, "assertion")
	if err != nil {
		return nil, err
	}

	rawClaims := tokenClaimsAsMap(verified)

	// client_id binding (ADR 0010 D2b). Signature validity alone is not enough:
	// the ID-JAG's `client_id` claim MUST equal the authenticated client, so a
	// stolen-but-validly-signed ID-JAG cannot be redeemed by a different client
	// at the mint boundary. This binding (not the signature) is the control.
	idJAGClientID, _ := extractMappedClaimString(rawClaims, "client_id")
	if idJAGClientID == "" {
		return nil, oauthBadRequest(oautherror.InvalidGrant, "ID-JAG missing client_id claim")
	}
	if idJAGClientID != authedClient.ClientID {
		return nil, oauthBadRequest(oautherror.InvalidGrant, "ID-JAG client_id does not match the authenticated client")
	}

	// Identity mapping (D3). user_id is required (validated at config load);
	// resolve the external subject through ClaimMapping. Fail closed when it is
	// absent or empty — an unmappable identity must never mint a token (an
	// admitted-but-unidentifiable agent matches no Cedar policy).
	userID, ok := extractMappedClaimString(rawClaims, cfg.ClaimMapping["user_id"])
	if !ok || userID == "" {
		return nil, oauthBadRequest(oautherror.InvalidGrant, fmt.Sprintf("ID-JAG missing claim %q (mapped to user_id) — cannot map to a Highflame principal", cfg.ClaimMapping["user_id"]))
	}
	userEmail, _ := extractMappedClaimString(rawClaims, cfg.ClaimMapping["email"])
	userName, _ := extractMappedClaimString(rawClaims, cfg.ClaimMapping["name"])

	// Audience restriction (D4, MUST). The minted token's aud is the ID-JAG's
	// `resource` claim — the target MCP server(s). Fail closed if absent/empty:
	// an unbound MCP access token could be replayed against any resource server.
	// Per RFC 8707 `resource` is a single URI string OR an array of them — a
	// string is ONE resource (taken atomically, NOT space-split like `scope`).
	// extractResourceClaim handles both shapes; we audience-restrict to the full
	// set the IdP authorized. `resource` is a standard claim named directly by
	// the spec, not a ClaimMapping target.
	resources, ok := extractResourceClaim(rawClaims)
	if !ok || len(resources) == 0 {
		return nil, oauthBadRequest(oautherror.InvalidGrant, "ID-JAG missing required resource claim — cannot audience-restrict the minted token")
	}

	// Resolve the application identity if requested (IDOR-guarded, same as the
	// id_token-exchange path); otherwise synthesize a service identity for the
	// external principal.
	identity, err := s.resolveExternalPrincipalIdentity(ctx, req)
	if err != nil {
		return nil, err
	}

	// Map IdP group/role claims into Cedar principal attributes (D3). These are
	// OPTIONAL — present only when the ID-JAG carries the claim AND ClaimMapping
	// routes it. role and privilege_scope are reservedClaims (an untrusted
	// caller can never inject them via additional_claims), but here ZeroID
	// itself sources them from the IdP-verified ID-JAG, so we set them directly
	// into CustomClaims (which bypasses the additional_claims blocklist by
	// design — same pattern the trusted broker path uses for role/privilege_scope).
	customClaims := map[string]any{
		"token_exchange": "id_jag",
		"user_id_iss":    upstreamIss,
	}
	if role, ok := extractMappedClaimString(rawClaims, cfg.ClaimMapping["role"]); ok && role != "" {
		customClaims["role"] = role
	}
	if ps, ok := extractMappedClaimStrings(rawClaims, cfg.ClaimMapping["privilege_scope"]); ok && len(ps) > 0 {
		customClaims["privilege_scope"] = ps
	}
	// trust_level, when the IdP supplies it via ClaimMapping, overrides the
	// synthetic identity's default so the minted trust_level claim reflects the
	// IdP's assessment (e.g. an Okta group → verified_third_party).
	if tl, ok := extractMappedClaimString(rawClaims, cfg.ClaimMapping["trust_level"]); ok && tl != "" {
		identity.TrustLevel = domain.TrustLevel(tl)
	}

	// Honest propagation of RFC 9068 authentication-context claims — only
	// forward auth_time/acr/amr when the deployer asked for them AND the ID-JAG
	// actually set them. Never default-fill.
	for _, claim := range cfg.PropagateClaims {
		if v, present := rawClaims[claim]; present {
			customClaims[claim] = v
		}
	}

	// Resolve the identity's credential policy when we have a real identity row
	// so issuance enforces the same policy ceiling (allowed scopes, max TTL,
	// trust level, policy expiry) as every other grant.
	var identityPolicyID string
	if identity.ID != "" {
		policy, err := s.identitySvc.ResolveCredentialPolicy(ctx, identity)
		if err != nil {
			return nil, oauthServerError("failed to resolve identity credential policy", err)
		}
		identityPolicyID = policy.ID
	}

	// Scopes come from the ID-JAG's scope claim — the IdP already evaluated
	// policy and scoped the grant (ADR 0010). The minted token's scopes are
	// that set, gated through the identity-policy ceiling as defense in depth
	// (a real identity row enforces it via IssueCredential; the synthetic
	// service-identity carrier is governed by the tenant default policy through
	// ResolveIdentityPolicy below). The value may be a space-delimited string
	// (standard) or an array — extractMappedClaimStrings handles both. The claim
	// NAME is configurable via ClaimMapping["scope"] (some IdPs emit it under a
	// non-standard name, e.g. Microsoft Entra's `scp`), defaulting to "scope".
	scopeClaim := cfg.ClaimMapping["scope"]
	if scopeClaim == "" {
		scopeClaim = "scope"
	}
	scopes, _ := extractMappedClaimStrings(rawClaims, scopeClaim)

	// Single-use enforcement (ADR 0010 D2a) — CONSUMED LAST, only after every
	// other check (D2b client auth + client_id binding, ID-JAG validation,
	// identity mapping, resource, policy resolution) has passed and immediately
	// before issuance. A request that fails an earlier check must NOT consume the
	// jti, or an attacker could burn a victim's single-use grant by deliberately
	// failing a later-but-not-last check. The store INSERT is the atomic
	// check-and-mark: a replay surfaces as ErrIDJAGReplay.
	if s.idJAGReplayStore == nil {
		// Fail closed: ID-JAG is single-use and we cannot enforce that without a
		// replay store. Never mint while replay protection is unavailable.
		return nil, oauthServerError("ID-JAG replay store is not configured", nil)
	}
	jti, ok := verified.JwtID()
	if !ok || jti == "" {
		return nil, oauthBadRequest(oautherror.InvalidGrant, "ID-JAG missing jti — single-use grants require jti")
	}
	// expires_at is the ID-JAG's own exp: past it the grant fails its exp check
	// before the jti is consulted, so the row is no longer load-bearing and the
	// cleanup worker may reap it. validateExternalAssertion already required exp
	// to be present, so this lookup succeeds.
	jtiExpiry, _ := verified.Expiration()
	if err := s.idJAGReplayStore.Insert(ctx, jti, jtiExpiry); err != nil {
		if errors.Is(err, postgres.ErrIDJAGReplay) {
			return nil, oauthBadRequest(oautherror.InvalidGrant, "ID-JAG has already been redeemed")
		}
		return nil, oauthServerError("failed to record ID-JAG single-use jti", err)
	}

	accessToken, _, err := s.credentialSvc.IssueCredential(ctx, IssueRequest{
		Identity:         identity,
		IdentityPolicyID: identityPolicyID,
		// Govern the synthetic-carrier path (no application_id → no identity row
		// and no IdentityPolicyID) by the tenant default policy, mirroring the
		// id_token-exchange path. Without this, any holder of a valid ID-JAG
		// could request arbitrary scopes ungated on the no-application_id path.
		ResolveIdentityPolicy: true,
		GrantType:             domain.GrantTypeJWTBearer,
		Scopes:                scopes,
		// Audience-restrict to the ID-JAG resource(s) (D4). IssueCredential stamps
		// these verbatim as the aud claim instead of defaulting to the issuer URL.
		Audience:          resources,
		UseRS256:          true,
		SubjectOverride:   userID,
		UserEmail:         userEmail,
		UserName:          userName,
		ApplicationID:     req.ApplicationID,
		TTL:               900, // 15 minutes — short-lived, matching the external-IdP paths
		CustomClaims:      customClaims,
		DPoPKeyThumbprint: req.DPoPKeyThumbprint,
	})
	if err != nil {
		return nil, err
	}

	accessToken.AccountID = req.AccountID
	accessToken.ProjectID = req.ProjectID
	accessToken.UserID = userID

	log.Info().
		Str("upstream_iss", upstreamIss).
		Str("account_id", req.AccountID).
		Str("project_id", req.ProjectID).
		Str("user_id", userID).
		Strs("resources", resources).
		Msg("ID-JAG jwt-bearer exchange succeeded")

	return accessToken, nil
}
