package service

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

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

// buildIDJAGCustomClaims assembles the custom claim set for an ID-JAG-minted
// access token. Extracted from idJAGBearer so the claim set — notably the
// RFC 8707 resource binding, which is security-load-bearing — is unit-testable
// without a full mint (the repo's other ID-JAG tests are all fail-closed and
// never reach issuance).
//
// role and privilege_scope are reservedClaims (an untrusted caller can never
// inject them via additional_claims), but here ZeroID itself sources them from
// the IdP-verified ID-JAG, so they are set directly into CustomClaims — which
// bypasses the additional_claims blocklist by design, the same pattern the
// trusted broker path uses.
func buildIDJAGCustomClaims(
	rawClaims map[string]any,
	cfg domain.ExternalIssuerConfig,
	upstreamIss string,
	resources []string,
) map[string]any {
	customClaims := map[string]any{
		"token_exchange": "id_jag",
		"user_id_iss":    upstreamIss,
	}

	// Map IdP group/role claims into Cedar principal attributes (D3). OPTIONAL —
	// present only when the ID-JAG carries the claim AND ClaimMapping routes it.
	if role, ok := extractMappedClaimString(rawClaims, cfg.ClaimMapping["role"]); ok && role != "" {
		customClaims["role"] = role
	}

	if ps, ok := extractMappedClaimStrings(rawClaims, cfg.ClaimMapping["privilege_scope"]); ok && len(ps) > 0 {
		customClaims["privilege_scope"] = ps
	}

	// Honest propagation of RFC 9068 authentication-context claims — only
	// forward auth_time/acr/amr when the deployer asked for them AND the ID-JAG
	// actually set them. Never default-fill.
	// Reserved claims are skipped for the same reason as on the ID-token
	// exchange: config restricts the list today, but that guarantee is held
	// one file away.
	for _, claim := range cfg.PropagateClaims {
		if reservedClaims[claim] {
			continue
		}
		if v, present := rawClaims[claim]; present {
			customClaims[claim] = v
		}
	}

	// RFC 8707 resource binding (D4), stamped as its own claim so downstream PEPs
	// have an EXPLICIT signal that this token was resource-bound at the mint.
	// `aud` carries the same value for RFC 8707 §2 conformance, but it cannot
	// serve as the signal: ZeroID stamps `aud` on every token it issues,
	// defaulting to the issuer URL to satisfy JWT-SVID §3, so a non-empty `aud`
	// says nothing about whether a binding exists. Shield treating it as if it did
	// denied every MCP-targeted request in prod (shield#366). Presence of THIS
	// claim is the discriminator; its absence means "not resource-bound".
	//
	// Set LAST, after the PropagateClaims loop, so a deployer who lists "resource"
	// in propagate_claims cannot clobber the value validated by the caller. Also
	// in reservedClaims, so additional_claims cannot inject or widen it.
	customClaims["resource"] = resources

	return customClaims
}

// idJAGActors returns the RFC 8693 §4.1 actor chain for an ID-JAG-minted
// token: the redeeming application identity as the single current actor, in
// the same shape token exchange gives its actor. The token's `sub` is the
// person, so without this a resource server sees an undelegated person token
// and cannot tell two agents acting for the same person apart.
//
// The synthetic carrier (no application_id, so no identity row) has no WIMSE
// URI to name and yields no actor. Only the rfc8693 profile reads Actors; the
// legacy shape is unchanged.
func idJAGActors(identity *domain.Identity) []domain.Actor {
	if identity == nil || identity.ID == "" || identity.WIMSEURI == "" {
		return nil
	}
	return []domain.Actor{{
		Sub:          identity.WIMSEURI,
		IdentityType: string(identity.IdentityType),
		TrustLevel:   string(identity.TrustLevel),
		ExternalID:   identity.ExternalID,
	}}
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
// configured external issuer, no tenant can be derived from the issuer's
// AllowedAccounts and the authenticated client's registration (or the request
// names a different one; see deriveIDJAGTenant), signature/claim validation
// fails, the external identity cannot be mapped, or the `resource` audience
// claim is absent (D3, D4).
func (s *OAuthService) idJAGBearer(ctx context.Context, req TokenRequest) (*domain.AccessToken, error) {
	// No account_id / project_id requirement. The tenant is derived below from
	// the issuer and the authenticated client (ADR 0042 D5); a conformant
	// client sends neither field (draft §4.4, EMA §5).

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
	// Same shared enforcement client_credentials uses: the registered
	// token_endpoint_auth_method decides which credential is acceptable, so a
	// key-based client can redeem an ID-JAG and a secret from one is refused.
	//
	// A client that is not pre-registered may use its Client ID Metadata
	// Document URL as its client_id (MCP Enterprise-Managed Authorization §5),
	// so this grant opts into the CIMD fallback. A registry row for the URL
	// still wins over its document, and a deactivated row still blocks it.
	// The opt-in is safe only because of the gate right after it and the
	// client_id binding below: the document must declare private_key_jwt (so
	// the caller proved control of the URL's key), and the IdP-signed ID-JAG
	// must name this exact client_id.
	authedClient, err := s.authenticateRegisteredClient(ctx, req, true)
	if err != nil {
		return nil, err
	}
	if authedClient.SelfAsserted() {
		if err := requireCIMDClientFitForIDJAG(authedClient); err != nil {
			return nil, err
		}
	}

	if s.externalIssuerRegistry == nil || !s.externalIssuerRegistry.HasAny() {
		// No external issuers configured → ID-JAG federation is disabled. The
		// IdP is the trust anchor; without one there is nothing to validate the
		// ID-JAG against, so fail closed rather than fall back to any other path.
		return nil, oauthBadRequest(oautherror.InvalidGrant, "ID-JAG federation is not configured (no external issuers)")
	}
	// Any issuer refusal is one generic invalid_grant (ADR 0010 D3 fails
	// closed here); resolved only after the client authenticated.
	entry, upstreamIss, err := s.resolvePersonIssuer(ctx, req.Assertion, "ID-JAG assertion")
	if err != nil {
		return nil, err
	}
	cfg := entry.Config

	// Verify the ID-JAG against its IdP — signature (JWKS), iss, aud, exp/nbf,
	// alg allow-list, MaxTokenAge, sub/exp/iat presence. Shared verbatim with
	// the id_token-exchange path (validateExternalAssertion); "assertion" names
	// the wire field for ID-JAG callers.
	// On an issuer row ZeroID's own issuer is the ID-JAG audience (checked
	// as required below); the row's audiences add nothing here.
	var issuerAudience []string
	if entry.Row != nil {
		issuerAudience = []string{s.issuer}
	}
	verified, err := s.validateExternalAssertion(ctx, req.Assertion, entry, "assertion", allowSubjectIdentifier, issuerAudience...)
	if err != nil {
		return nil, err
	}

	rawClaims := tokenClaimsAsMap(verified)

	// An ID-JAG's aud MUST be the resource authorization server's issuer
	// (draft §4.3). A person row may also list agents' app ids for the
	// ID-token exchange, so the row's audiences alone are not enough here.
	if entry.Row != nil {
		if aud, _ := verified.Audience(); !slices.Contains(aud, s.issuer) {
			return nil, oauthBadRequest(oautherror.InvalidGrant, "ID-JAG is not addressed to this authorization server (aud)")
		}
	}

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

	// Tenant binding (ADR 0042 D5). Derived from the issuer's allowed_accounts
	// and the authenticated client's registration, never chosen by the request;
	// a request that also names a tenant must name this one. Runs after the
	// client_id binding, so a CIMD client is held to the same binding before
	// its missing tenant is reported, and before the jti is consumed so a
	// refused tenant does not burn the grant. From here on
	// req.AccountID / req.ProjectID ARE the derived tenant, so every later use
	// (identity resolution, the mint, the observed-resource inventory) reads
	// the derived value and nothing can reach back to what the caller sent.
	//
	// For an issuer row the agent is the ID-JAG's act.sub mapped through an
	// enabled binding (ADR 0042 D6), and the tenant is that identity's; a
	// registered client linked to another identity is refused. This also
	// gives a CIMD client its tenant.
	var boundAgent *domain.Identity
	if entry.Row != nil {
		boundAgent, err = s.bindFederatedAgent(ctx, entry.Row, actorSubject(rawClaims), authedClient, federatedGrantIDJAG)
		if err != nil {
			return nil, err
		}
		if err := federatedTenant(boundAgent, req.AccountID, req.ProjectID); err != nil {
			return nil, err
		}
		if req.ApplicationID != "" && req.ApplicationID != boundAgent.ID {
			return nil, oauthBadRequest(oautherror.InvalidGrant, "application_id is not the agent the ID-JAG's act.sub is bound to")
		}
		req.AccountID, req.ProjectID = boundAgent.AccountID, boundAgent.ProjectID
	} else {
		tenant, err := deriveIDJAGTenant(ctx, &cfg, authedClient,
			s.identitySvc.repo.GetByIDInAccounts, req.AccountID, req.ProjectID)
		if err != nil {
			return nil, err
		}
		req.AccountID, req.ProjectID = tenant.AccountID, tenant.ProjectID
	}

	// Identity mapping (D3). user_id is required (validated at config load);
	// resolve the external subject through ClaimMapping. Fail closed when it is
	// absent or empty — an unmappable identity must never mint a token (an
	// admitted-but-unidentifiable agent matches no Cedar policy).
	userID, _ := extractMappedClaimString(rawClaims, cfg.ClaimMapping["user_id"])

	// RFC 9493 `sub_id` (zeroid#265). An IdP may name the subject with a
	// structured identifier instead of, or as well as, the plain mapped claim.
	// Resolved here rather than inside the mapping helper because it is a
	// spec-named claim with its own shape, not another path ClaimMapping could
	// point at. upstreamIss is the verified issuer, which `iss_sub` is pinned to.
	subID, err := parseSubjectIdentifier(rawClaims, upstreamIss)
	switch {
	case err == nil:
	case errors.Is(err, errSubjectIdentifierUnsupported) && userID != "":
		// A well-formed sub_id in a format we do not resolve, beside a present
		// mapped claim. The mapped claim is the principal, and a format we
		// cannot read can neither supply nor contradict it, so it is set aside
		// rather than allowed to sink an otherwise valid assertion — an IdP
		// emitting RFC 9493's `account` or `phone_number` next to an ordinary
		// sub is conformant, not broken.
		log.Debug().Err(err).Str("user_id_iss", upstreamIss).
			Msg("ID-JAG sub_id format not resolved; mapped claim is authoritative")
		subID = nil
	default:
		// Everything else fails the redemption outright: a MALFORMED sub_id,
		// a foreign-issuer iss_sub, or an unsupported one we would have needed
		// as the principal. It must NOT fall back to the plain subject: an IdP
		// that meant to name a subject and produced something we cannot read
		// has told us its identity claim is broken, and quietly minting on a
		// different claim is how an assertion ends up authorising someone other
		// than whoever it was written for.
		return nil, oauthBadRequest(oautherror.InvalidGrant, fmt.Sprintf("ID-JAG has an unusable sub_id: %v", err))
	}
	if subID != nil {
		// A same-kind contradiction is refused, never merged and never ranked:
		// two different principals in one assertion is either a broken IdP or
		// an attempt to have one identity pass the checks while another reaches
		// the mint. Only identifiers of the same kind are compared — an opaque
		// `sub` beside an email `sub_id` is two names for one person, not two
		// people, and refusing it would reject the most common IdP shape.
		if claim := subID.conflictingClaim(rawClaims); claim != "" {
			return nil, oauthBadRequest(oautherror.InvalidGrant,
				fmt.Sprintf("ID-JAG sub_id and the %q claim name different principals", claim))
		}
		// The deployer's mapping stays authoritative. sub_id supplies the
		// principal only when the mapped claim is absent, so the same person
		// keeps one user_id whether or not their IdP emits sub_id.
		if userID == "" {
			userID = subID.principal
		}
	}

	if userID == "" {
		return nil, oauthBadRequest(oautherror.InvalidGrant, fmt.Sprintf("ID-JAG missing claim %q (mapped to user_id) and has no usable sub_id — cannot map to a Highflame principal", cfg.ClaimMapping["user_id"]))
	}
	// The ID-JAG names a person; a workload subject would mint
	// principal_type=user for a machine (zeroid#415, ADR 0043 D3).
	if err := refuseWorkloadSubject(rawClaims, userID); err != nil {
		return nil, err
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

	// RFC 8707 `resource` on the token request NARROWS the binding to a subset of
	// what the IdP authorized (CAP-IDN-026). Where an ID-JAG names several
	// servers, the client — which knows which one it is about to call — selects;
	// without the parameter the claim decides for it and the token is minted good
	// for every server in the assertion, which is wider than any single call
	// needs. Every requested value must appear in the claim, so this can only
	// shrink the set, never extend it: the IdP remains the sole source of
	// authority and the client only spends less of it.
	//
	// Placed AFTER the missing-claim check so an assertion with no resource fails
	// with the D4 error regardless of what the request asked for, and BEFORE the
	// single-use jti is consumed so a bad `resource` does not burn the grant.
	resources, err = narrowResourcesTo(resources, req.Resource)
	if err != nil {
		return nil, err
	}

	// Resolve the application identity if requested (IDOR-guarded, same as the
	// id_token-exchange path); otherwise synthesize a service identity for the
	// external principal.
	identity := boundAgent
	if identity == nil {
		identity, err = s.resolveExternalPrincipalIdentity(ctx, req)
		if err != nil {
			return nil, err
		}
	}

	// Map IdP group/role claims into Cedar principal attributes (D3). These are
	// OPTIONAL — present only when the ID-JAG carries the claim AND ClaimMapping
	// routes it. role and privilege_scope are reservedClaims (an untrusted
	// caller can never inject them via additional_claims), but here ZeroID
	// itself sources them from the IdP-verified ID-JAG, so we set them directly
	// into CustomClaims (which bypasses the additional_claims blocklist by
	// design — same pattern the trusted broker path uses for role/privilege_scope).
	customClaims := buildIDJAGCustomClaims(rawClaims, cfg, upstreamIss, resources)

	// trust_level, when the IdP supplies it via ClaimMapping, overrides the
	// synthetic identity's default so the minted trust_level claim reflects the
	// IdP's assessment (e.g. an Okta group → verified_third_party).
	if tl, ok := extractMappedClaimString(rawClaims, cfg.ClaimMapping["trust_level"]); ok && tl != "" {
		identity.TrustLevel = domain.TrustLevel(tl)
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

	issue := IssueRequest{
		Identity:         identity,
		IdentityPolicyID: identityPolicyID,
		// Govern the synthetic-carrier path (no application_id → no identity row
		// and no IdentityPolicyID) by the tenant default policy, mirroring the
		// id_token-exchange path. Without this, any holder of a valid ID-JAG
		// could request arbitrary scopes ungated on the no-application_id path.
		ResolveIdentityPolicy: true,
		GrantType:             domain.GrantTypeJWTBearer,
		Scopes:                scopes,
		// The IdP's policy decision bounds an ID-JAG's scopes, so the
		// application identity's user-grant ceiling applies rather than its
		// own allowed_scopes, which would reject scopes the IdP granted (D10).
		UserGrantBounded: true,
		// Audience-restrict to the ID-JAG resource(s) (D4). IssueCredential stamps
		// these verbatim as the aud claim instead of defaulting to the issuer URL.
		Audience:        resources,
		UseRS256:        true,
		SubjectOverride: userID,
		UserEmail:       userEmail,
		UserName:        userName,
		ApplicationID:   req.ApplicationID,
		// RFC 9068 §2.2 client_id (D8). The grant has already authenticated
		// this client and bound the ID-JAG's own client_id claim to it, so it
		// is exactly the client the token is issued to.
		ClientID: authedClient.ClientID,
		// The redeeming agent is the current actor (RFC 8693 §4.1). Built
		// after the trust_level mapping above, so act.trust_level carries the
		// value the legacy shape emits at the top level.
		Actors:            idJAGActors(identity),
		TTL:               900, // 15 minutes — short-lived, matching the external-IdP paths
		CustomClaims:      customClaims,
		DPoPKeyThumbprint: req.DPoPKeyThumbprint,
	}
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
	// The person's ceiling can refuse too, so it is decided before the burn
	// and reused at the mint. A replay is refused first, so it never reaches
	// the deployer's resolver; Insert below is still the single-use gate.
	redeemed, err := s.idJAGReplayStore.Redeemed(ctx, jti)
	if err != nil {
		return nil, oauthServerError("failed to check ID-JAG single-use jti", err)
	}
	if redeemed {
		return nil, oauthBadRequest(oautherror.InvalidGrant, "ID-JAG has already been redeemed")
	}
	// The person must be a member of the tenant (ADR 0042 D5a). Resolved here,
	// before the burn, so a non-member does not consume the grant, and before
	// the ceiling, which is keyed on the resolved user.
	person, err := s.resolveFederatedPerson(ctx, entry.Row != nil, FederatedPersonRequest{
		GrantType:       PersonGrantIDJAG,
		AccountID:       req.AccountID,
		ProjectID:       req.ProjectID,
		Issuer:          upstreamIss,
		IssuerID:        issuerRowID(entry),
		Subject:         userID,
		Email:           userEmail,
		EmailVerified:   emailVerified(rawClaims, cfg.ClaimMapping["email_verified"]),
		ClientID:        authedClient.ClientID,
		AgentIdentityID: identity.ID,
	})
	if err != nil {
		return nil, err
	}
	person.apply(&issue)
	if err := s.credentialSvc.decidePersonGrant(ctx, &issue); err != nil {
		return nil, personGrantOAuthError(err, oautherror.InvalidScope)
	}
	if err := s.idJAGReplayStore.Insert(ctx, jti, jtiExpiry); err != nil {
		if errors.Is(err, postgres.ErrIDJAGReplay) {
			return nil, oauthBadRequest(oautherror.InvalidGrant, "ID-JAG has already been redeemed")
		}
		return nil, oauthServerError("failed to record ID-JAG single-use jti", err)
	}

	accessToken, _, err := s.credentialSvc.IssueCredential(ctx, issue)
	if err != nil {
		return nil, err
	}

	accessToken.AccountID = req.AccountID
	accessToken.ProjectID = req.ProjectID
	accessToken.UserID = person.sub

	// Record the MCP servers this exchange authorized (zeroid#259). We just
	// audience-restricted a token to them, which makes this the authoritative
	// answer to "which MCP servers do our agents actually reach" — the one
	// inventory that sees an enterprise's PRIVATE servers, which no public
	// registry knows and no reachability probe can necessarily resolve.
	//
	// Deliberately AFTER issuance. Placement is the security control: reaching
	// here means every gate above passed, so a rejected exchange can never plant
	// an entry in a tenant's inventory.
	if s.observedIDJAGResources != nil {
		s.recordObservedResources(ctx, req.AccountID, req.ProjectID, upstreamIss, resources)
	}

	log.Info().
		Str("upstream_iss", upstreamIss).
		Str("account_id", req.AccountID).
		Str("project_id", req.ProjectID).
		Str("user_id", person.sub).
		Strs("resources", resources).
		Msg("ID-JAG jwt-bearer exchange succeeded")

	return accessToken, nil
}

// observedResourceRecordTimeout bounds the inventory write. It is generous
// relative to a healthy upsert and tight relative to anything a client would
// notice: the token is already minted, so this is the maximum extra latency a
// degraded database can add to a request that has already succeeded.
const observedResourceRecordTimeout = 2 * time.Second

// recordObservedResources writes the observed-MCP-server inventory for a
// successful exchange (zeroid#259), off the critical path.
//
// Three properties, each load-bearing:
//
//   - context.WithoutCancel. The caller's context is cancelled the moment the
//     HTTP response is written. Inheriting it would race the response and drop
//     observations non-deterministically — and on a fast client, drop most of
//     them, which looks like an inventory that mysteriously under-reports.
//   - A bounded timeout. Every exchange for a given MCP server UPDATEs the same
//     row by design (one row per resource), so concurrent redemptions for a
//     popular server serialize on that row lock. Without a deadline, lock waits
//     or pool exhaustion would add unbounded latency to a token that is already
//     issued — exactly the availability risk this is supposed to avoid.
//   - Errors are logged, never returned. The token exists; withholding it over a
//     bookkeeping row would turn an inventory feature into an auth-path outage.
func (s *OAuthService) recordObservedResources(
	ctx context.Context,
	accountID, projectID, upstreamIss string,
	resources []string,
) {
	recordCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), observedResourceRecordTimeout)
	defer cancel()

	if err := s.observedIDJAGResources.Record(recordCtx, accountID, projectID, upstreamIss, resources); err != nil {
		log.Warn().Err(err).
			Str("account_id", accountID).
			Str("project_id", projectID).
			Strs("resources", resources).
			Msg("failed to record observed ID-JAG resources (token was still issued)")
	}
}

// requireCIMDClientFitForIDJAG gates a Client ID Metadata Document client on
// the ID-JAG grant. It runs after the client has authenticated, so every
// refusal here is about what the document declared, not who the caller is.
//
//   - token_endpoint_auth_method must be private_key_jwt. The profile "SHOULD
//     only be supported for confidential clients" (draft-ietf-oauth-identity-
//     assertion-authz-grant-04 §9.1), ADR 0010 D2b requires an authenticated
//     redeeming client, and a document can carry no shared secret (CIMD §4.1),
//     so a key is the only credential it can have. authenticateRegisteredClient
//     already refuses a CIMD client with any other method; this re-states it at
//     the grant that depends on it.
//   - A document that claims the ID-JAG profile must not contradict itself
//     (draft §8: it MUST then list both token-exchange and jwt-bearer). That
//     is a refusal of an explicit, wrong declaration.
//
// A document that simply does not list jwt-bearer is NOT refused. It used to
// be, and that broke real clients for no security gain: WSO2's MCP playground
// publishes grant_types [authorization_code, refresh_token,
// client_credentials] and redeems ID-JAGs with the same document. The grant
// list is the publisher's own unauthenticated statement, so an attacker can put
// jwt-bearer in it as easily as leave it out. What makes the redemption safe is
// what the caller cannot choose: the private_key_jwt assertion proves control
// of the document's key, the IdP-signed ID-JAG must name this exact client_id,
// and the tenant must be derived server-side (deriveIDJAGTenant).
func requireCIMDClientFitForIDJAG(client *domain.OAuthClient) error {
	if client.TokenEndpointAuthMethod != clientAuthMethodPrivateKeyJWT {
		return oauthUnauthorized(
			"a client metadata document client must authenticate with private_key_jwt to redeem an ID-JAG", nil)
	}
	if client.IDJAGProfileContradicted {
		return oauthBadRequest(oautherror.UnauthorizedClient,
			"the client metadata document claims the ID-JAG grant profile without listing both "+
				grantTypeTokenExchangeURN+" and "+grantTypeJWTBearerURN+" in grant_types")
	}
	return nil
}
