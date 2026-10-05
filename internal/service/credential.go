package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/rs/zerolog/log"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/signing"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
	"github.com/highflame-ai/zeroid/internal/telemetry"
)

// CredentialService handles JWT issuance, rotation, and revocation.
type CredentialService struct {
	repo            *postgres.CredentialRepository
	jwksSvc         *signing.JWKSService
	policySvc       *CredentialPolicyService
	attestationRepo *postgres.AttestationRepository
	issuer          string
	defaultTTL      int
	maxTTL          int
	// auditRetention is how long past expiry an issued_credentials row
	// stays queryable (the evidence clock the cleanup worker prunes on),
	// so the delegation graph survives token expiry. From
	// token.audit_retention_days.
	auditRetention time.Duration
	// revocationDispatcher fans out a RevocationEvent per revoked JTI to the
	// deployer-supplied RevocationNotifier after each revocation commits.
	// Shared with RefreshTokenService so one Server.SetRevocationNotifier call
	// wires every revocation path. Nil-safe: when no dispatcher is attached, or
	// no notifier is set on it, revocation behaviour is unchanged.
	revocationDispatcher *RevocationDispatcher
	// tenantSettings resolves each tenant's token profile, which decides the
	// claim shape of every token this service issues. Nil-safe: when unset,
	// every tenant is on the legacy profile.
	tenantSettings *TenantSettingsService
}

// SetTenantSettingsService wires the per-tenant settings the issuance
// chokepoint reads (the token profile). Wired once at server construction.
func (s *CredentialService) SetTenantSettingsService(ts *TenantSettingsService) {
	s.tenantSettings = ts
}

// NewCredentialService creates a new CredentialService.
func NewCredentialService(
	repo *postgres.CredentialRepository,
	jwksSvc *signing.JWKSService,
	policySvc *CredentialPolicyService,
	attestationRepo *postgres.AttestationRepository,
	issuer string,
	defaultTTL, maxTTL, auditRetentionDays int,
) *CredentialService {
	// Clamp defensively: this constructor is also reached from tests and
	// external tools that bypass Config.Validate. A non-positive value would
	// stamp AuditRetentionUntil at or before expiry (degrading the graph back
	// to delete-at-expiry); an enormous value would overflow the
	// days→Duration multiplication into a negative duration (same effect,
	// worse). Both collapse to safe bounds — misconfiguration must never
	// erase evidence. Bounds shared with Config.Validate via domain.
	if auditRetentionDays <= 0 {
		auditRetentionDays = domain.DefaultAuditRetentionDays
	} else if auditRetentionDays > domain.MaxAuditRetentionDays {
		auditRetentionDays = domain.MaxAuditRetentionDays
	}
	return &CredentialService{
		repo:            repo,
		jwksSvc:         jwksSvc,
		policySvc:       policySvc,
		attestationRepo: attestationRepo,
		issuer:          issuer,
		defaultTTL:      defaultTTL,
		maxTTL:          maxTTL,
		auditRetention:  time.Duration(auditRetentionDays) * 24 * time.Hour,
	}
}

// IssueRequest holds parameters for credential issuance.
// TTL defaults to the service default and is capped at MaxTTL.
//
// Authority is enforced through one or two policy layers. IdentityPolicyID
// is the authority ceiling assigned to the identity at registration time
// and is checked for every grant type. CredentialPolicyID is the API
// key's own (optional) restriction and is checked in addition whenever a
// request is api_key-backed. Both must permit the request for issuance
// to succeed (intersection semantics, AWS/GCP/Azure pattern).
type IssueRequest struct {
	Identity           *domain.Identity
	IdentityPolicyID   string // Identity policy — authority ceiling.
	CredentialPolicyID string // API key policy — per-credential restriction (optional).
	Scopes             []string
	TTL                int
	GrantType          domain.GrantType
	Audience           []string
	// DelegatedBy is the WIMSE URI of the orchestrator delegating authority.
	// Set only for token_exchange (RFC 8693) grants.
	DelegatedBy string
	// ParentJTI is the JTI of the orchestrator's credential being exchanged.
	// Used for cascade revocation of delegated credentials.
	ParentJTI string
	// DelegationDepth tracks how deep this credential is in the delegation chain.
	// 0 = direct credential, 1 = first delegation, etc.
	DelegationDepth int
	// UseRS256 requests RS256 signing instead of the default ES256.
	// Set for api_key grant to produce compatible tokens.
	UseRS256 bool
	// ApplicationID is the optional application scope (set when API key is linked to an application).
	ApplicationID string
	// ClientID is the OAuth client that requested this token, emitted as the
	// RFC 9068 §2.2 `client_id` claim.
	//
	// Deliberately separate from ApplicationID even though the
	// authorization_code path passes the same value to both today. They mean
	// different things: ApplicationID is a Highflame application scope an API
	// key may be linked to, and widening it to also mean "OAuth client" would
	// stamp `client_id` onto api_key tokens that have no OAuth client at all.
	// Set only on grants where an OAuth client authenticated or was resolved.
	//
	// This is the claim a resource server looks for to attribute a call to a
	// client — including a partner's, in the MCP interop work. For a CIMD
	// client it is the metadata-document URL, which is the whole of that
	// client's identity, since there is no registration row (issue #325).
	ClientID string
	// SubjectOverride, when non-empty, replaces the default WIMSE URI as the JWT "sub" claim.
	// Used for external principal exchange (sub = external user ID) and authorization_code
	// (sub = authenticated user ID). For NHI grants, leave empty to use the WIMSE URI.
	SubjectOverride string
	// OwnerUserIDOverride sources the owner_user_id claim from the credential's
	// own provenance instead of Identity.OwnerUserID. Set by the api_key grant
	// for auto-provisioned service placeholders: those rows are shared by every
	// key for a product, so their owner is only whoever created the first key.
	OwnerUserIDOverride string
	// ActingUserID is the end user the principal is acting on behalf of (runtime, per-request).
	// Distinct from the identity owner (Identity.OwnerUserID) who registered the agent.
	// For NHI tokens where an agent serves a specific user, this populates the RFC 8693 "act" claim.
	// For human tokens, this is typically empty (the user IS the principal, not acting for someone else).
	ActingUserID string
	// UserEmail and UserName are set for human user tokens.
	UserEmail string
	UserName  string
	// CustomClaims allows callers to add arbitrary key-value pairs to the JWT.
	// This is the extensibility hook for deployment-specific claims.
	CustomClaims map[string]any
	// CredentialExpiresAt is the upper bound on the issued token's exp claim
	// derived from the credential material itself — typically the API key's
	// expires_at for api_key grants. The chokepoint clamps TTL by
	// min(CredentialExpiresAt, Identity.ExpiresAt) so the JWT exp never
	// outlives the authority. Nil means "no per-credential bound."
	CredentialExpiresAt *time.Time
	// MissionID is the delegation-tree-scoped opaque identifier (issue #81).
	// Empty on first issuance — IssueCredential will default it to the new
	// credential's own JTI (this credential becomes the root of a new
	// mission). Non-empty on token_exchange — the caller has resolved the
	// subject_token's mission and is propagating it down the chain.
	MissionID string
	// DPoPKeyThumbprint is the base64url JWK thumbprint (RFC 7638 SHA-256) of
	// the client's DPoP public key. When non-empty, the issued JWT carries a
	// cnf.jkt claim binding the token to that key, and token_type is returned
	// as "DPoP" instead of "Bearer" (RFC 9449 §6.1).
	DPoPKeyThumbprint string
	// ResolveIdentityPolicy asks IssueCredential to resolve and enforce the
	// identity's policy when IdentityPolicyID is empty. The OAuth grant paths
	// resolve the policy themselves (and only for grants gated at the identity
	// layer — authorization_code/refresh_token/CIBA tokens minted for a client
	// with no linked identity are deliberately governed by the client, not an
	// identity policy). The three issuance paths that historically bypassed the
	// ceiling — RotateCredential, the admin issue handler, and post-attestation
	// verification — set this so the chokepoint resolves the identity's policy
	// (own CredentialPolicyID, else tenant default) and enforces it. Leaving it
	// false preserves the prior behavior for every other caller.
	ResolveIdentityPolicy bool

	// PrincipalType, PrincipalSub and PrincipalIss name the principal whose
	// authority the chain uses (RFC 8693 §4.1). Token exchange sets all three
	// from the parent, because a child inherits its chain's principal and
	// never re-derives it. Every other path leaves PrincipalType and
	// PrincipalSub empty and IssueCredential derives them: a user when
	// SubjectOverride is set (exactly the six grants that mint for a person),
	// a workload otherwise. PrincipalIss may be set on its own, by the refresh
	// grant, to carry a federated user's issuer across rotation.
	PrincipalType domain.PrincipalType
	PrincipalSub  string
	PrincipalIss  string

	// Actors is the RFC 8693 §4.1 actor chain for an exchanged token under the
	// rfc8693 profile: the current actor first, prior actors after it, most
	// recent first. Ignored under the legacy profile, which keeps its
	// single-level `act`. Capped at domain.MaxActorChainDepth.
	Actors []domain.Actor

	// UserGrantBounded marks a grant whose user principal's grant is itself
	// bounded — a delegated user chain (by its parent), ID-JAG (by the IdP),
	// authorization_code and refresh (by consent) — so a user-subject token
	// is capped by the policy's user_grant_scopes instead of allowed_scopes
	// (D10). Left false on the trusted-broker, ID-token and CIBA roots, which
	// are bounded only by the caller's request and so keep allowed_scopes
	// until the ceiling rule enforces on them. No effect on a workload
	// principal.
	UserGrantBounded bool

	// ScopeCeilingUnbounded is set by the api_key and NHI jwt_bearer grants
	// when every scope ceiling they applied was empty (the key, the key's
	// policy, the identity's policy, the deprecated identity list), so a
	// workload subject got whatever scope it named. RequestBoundedRoot is set
	// by the user-subject roots the design calls bounded only by the
	// caller's request: the trusted broker (without a server-defined audience
	// profile), ID-token exchange and CIBA. Both feed the ceiling rule (P1),
	// which counts in phase 1 and refuses in phase 2.
	ScopeCeilingUnbounded bool
	RequestBoundedRoot    bool
}

// actorChainClaim renders an actor chain as the nested RFC 8693 §4.1 `act`
// claim. The current actor (actors[0]) carries its own attributes; prior
// actors carry only `sub`, since they are informational and access control
// uses only the top-level claims and the current actor. Past
// domain.MaxActorChainDepth the deepest prior actors are dropped, which §4.1
// allows for the same reason.
func actorChainClaim(actors []domain.Actor) map[string]any {
	if len(actors) > domain.MaxActorChainDepth {
		actors = actors[:domain.MaxActorChainDepth]
	}
	var nested map[string]any
	for i := len(actors) - 1; i >= 0; i-- {
		a := map[string]any{"sub": actors[i].Sub}
		if i == 0 {
			if actors[i].IdentityType != "" {
				a["identity_type"] = actors[i].IdentityType
			}
			if actors[i].TrustLevel != "" {
				a["trust_level"] = actors[i].TrustLevel
			}
			if actors[i].ExternalID != "" {
				a["external_id"] = actors[i].ExternalID
			}
		}
		if nested != nil {
			a["act"] = nested
		}
		nested = a
	}
	return nested
}

// recordUnboundedScope implements the ceiling rule's first phase (P1): it
// counts, without refusing, a token issued for a named scope that nothing
// other than the requester bounded. Somewhere in the chain, something other
// than the requester must bound the scopes; these are the issuances where
// nothing did.
//
//   - A workload subject whose every scope ceiling was empty: it got whatever
//     it asked for (api_key, NHI jwt_bearer).
//   - A user-subject root bounded only by the caller's request (trusted
//     broker, ID-token exchange, CIBA) whose governing policy sets neither
//     allowed_scopes nor user_grant_scopes, and no Cedar decision exists yet.
//
// Phase 2 refuses these with invalid_scope behind
// workload_subject_requires_ceiling. Counting first, per identity, lets
// owners see in advance which agents enforcement will break.
func (s *CredentialService) recordUnboundedScope(ctx context.Context, req IssueRequest, principal resolvedPrincipal, identityPolicy *domain.CredentialPolicy) {
	if len(req.Scopes) == 0 {
		return
	}
	var root string
	switch {
	case req.ScopeCeilingUnbounded && principal.Type == domain.PrincipalWorkload:
		root = "workload"
	case req.RequestBoundedRoot && principal.Type == domain.PrincipalUser:
		bounded := len(req.Identity.AllowedScopes) > 0
		if identityPolicy != nil {
			bounded = bounded || len(identityPolicy.AllowedScopes) > 0 || len(identityPolicy.UserGrantScopes) > 0
		}
		if bounded {
			return
		}
		root = "user"
	default:
		return
	}
	telemetry.WorkloadUnboundedScope.Add(ctx, 1, metric.WithAttributes(
		attribute.String("account_id", req.Identity.AccountID),
		attribute.String("project_id", req.Identity.ProjectID),
		attribute.String("identity_id", req.Identity.ID),
		attribute.String("grant_type", string(req.GrantType)),
		attribute.String("principal_type", root),
	))
	log.Warn().
		Str("identity_id", req.Identity.ID).
		Str("grant_type", string(req.GrantType)).
		Str("principal_type", root).
		Strs("scopes", req.Scopes).
		Msg("ceiling rule: issued named scopes with no configured ceiling; this will be refused once the rule is enforced — configure allowed_scopes, or user_grant_scopes for a user grant")
}

// accessTokenTyp chooses the access token's JOSE typ header (D9).
//
// Two specs ZeroID follows disagree, and a token can satisfy only one:
// RFC 9068 §2.1 types a JWT access token "at+jwt", so a resource server can
// tell it apart from an ID token; JWT-SVID §2.3 allows only "JWT" or "JOSE".
// Every access token is "at+jwt" by default, whatever the tenant's token
// profile, or "JWT" when the identity's governing policy chooses it, for
// agents whose tokens must stay valid JWT-SVIDs. A grant with no identity
// policy gets the default.
//
// Only the governing (identity) policy decides. A header has no
// narrowest-wins meaning, so an API key's own policy does not override it.
func accessTokenTyp(identityPolicy *domain.CredentialPolicy) string {
	if identityPolicy != nil && identityPolicy.JWTTyp == domain.JWTTypJWT {
		return domain.JWTTypJWT
	}
	return domain.JWTTypAccessToken
}

// resolvedPrincipal is the principal a credential's chain acts for.
type resolvedPrincipal struct {
	Type domain.PrincipalType
	Sub  string
	Iss  string
}

// resolvePrincipal decides the principal for a credential. The subject is
// decided once, here, for every issuance path, so no grant can disagree with
// another about who a chain acts for.
//
//   - An exchange passes its parent's principal through unchanged.
//   - SubjectOverride is set by exactly the six grants that mint for a person
//     (authorization_code, refresh_token, CIBA, ID-JAG, ID-token exchange, the
//     trusted-broker principal exchange), so its presence means a user subject.
//   - Every other grant mints for the identity itself: a workload subject.
//
// The issuer of a user subject is the upstream IdP's when the grant is
// federated (the reserved user_id_iss claim the federated grants set), so the
// pair is an RFC 9493 iss_sub identifier and two IdPs' `alice` never collide.
// A user ZeroID resolved locally, and every workload, take ZeroID's own issuer.
func (s *CredentialService) resolvePrincipal(req IssueRequest) resolvedPrincipal {
	if req.PrincipalType != "" {
		return resolvedPrincipal{Type: req.PrincipalType, Sub: req.PrincipalSub, Iss: req.PrincipalIss}
	}
	if req.SubjectOverride == "" {
		return resolvedPrincipal{Type: domain.PrincipalWorkload, Sub: req.Identity.WIMSEURI, Iss: s.issuer}
	}
	iss := req.PrincipalIss
	if iss == "" {
		if upstream, ok := req.CustomClaims["user_id_iss"].(string); ok && upstream != "" {
			iss = upstream
		}
	}
	if iss == "" {
		iss = s.issuer
	}
	return resolvedPrincipal{Type: domain.PrincipalUser, Sub: req.SubjectOverride, Iss: iss}
}

// ErrScopesNotAllowed is returned when one or more requested scopes are not in the identity's AllowedScopes list.
var ErrScopesNotAllowed = fmt.Errorf("one or more requested scopes are not permitted for this identity")

// IssueCredential issues a short-lived JWT for an identity.
//
// Gate: identities not in a usable status never receive a fresh credential.
// This is the authoritative chokepoint — every issuance path in the codebase
// (admin /credentials/issue, oauth grants, RotateCredential, attestation
// verification) funnels through here. Per-grant checks elsewhere remain as
// defense-in-depth and for better error messages, but this gate is the
// guarantee that bypasses via a new or forgotten path still fail closed.
func (s *CredentialService) IssueCredential(ctx context.Context, req IssueRequest) (*domain.AccessToken, *domain.IssuedCredential, error) {
	if req.Identity == nil {
		return nil, nil, fmt.Errorf("identity is required")
	}
	if !req.Identity.Status.IsUsable() {
		return nil, nil, fmt.Errorf("%w (status: %s)", domain.ErrIdentityNotUsable, req.Identity.Status)
	}
	if req.Identity.IsExpired() {
		// Fail-closed even when the cleanup worker hasn't yet swept the
		// identity into status=deactivated. The check at this chokepoint
		// is what guarantees no grant path can mint a token past the
		// authority's expiry window, regardless of worker timing.
		return nil, nil, fmt.Errorf("%w: identity expired at %s", domain.ErrIdentityExpired, req.Identity.ExpiresAt.Format(time.RFC3339))
	}

	ttl := req.TTL
	if ttl <= 0 {
		ttl = s.defaultTTL
	}
	if ttl > s.maxTTL {
		ttl = s.maxTTL
	}
	// Clamp TTL by the authority's remaining lifetime. A JWT whose exp
	// claim outlives its authority window would still verify locally
	// (tokens.verify() doesn't check revocation) for the gap between
	// authority-expiry and JWT-exp. Clamping here makes time-bound
	// authority an enforced invariant on the issued token itself, not
	// just on the cascade-revocation side.
	//
	// Both bounds (identity + per-credential) are min-combined with the
	// requested TTL. Already-expired authority short-circuits to error
	// — the IsExpired() check above caught the identity case; here we
	// defend against per-credential expiry that the chokepoint doesn't
	// otherwise see.
	clampNow := time.Now()
	if req.Identity.ExpiresAt != nil {
		remaining := int(req.Identity.ExpiresAt.Sub(clampNow).Seconds())
		if remaining <= 0 {
			return nil, nil, fmt.Errorf("%w: identity expired at %s", domain.ErrIdentityExpired, req.Identity.ExpiresAt.Format(time.RFC3339))
		}
		if ttl > remaining {
			// Debug level: a busy agent making frequent requests near its
			// expiry would emit this on every issuance — that's normal
			// near-end-of-life behavior, not something operators need
			// flagged at Info. Enable debug logging when diagnosing
			// surprises about shorter-than-expected token lifetimes.
			log.Debug().
				Str("identity_id", req.Identity.ID).
				Int("requested_ttl", ttl).
				Int("identity_remaining_seconds", remaining).
				Msg("clamping token TTL to identity remaining lifetime")
			ttl = remaining
		}
	}
	if req.CredentialExpiresAt != nil {
		remaining := int(req.CredentialExpiresAt.Sub(clampNow).Seconds())
		if remaining <= 0 {
			return nil, nil, fmt.Errorf("%w: credential expired at %s", domain.ErrCredentialExpired, req.CredentialExpiresAt.Format(time.RFC3339))
		}
		if ttl > remaining {
			log.Debug().
				Str("identity_id", req.Identity.ID).
				Int("requested_ttl", ttl).
				Int("credential_remaining_seconds", remaining).
				Msg("clamping token TTL to credential remaining lifetime")
			ttl = remaining
		}
	}
	if req.GrantType == "" {
		req.GrantType = domain.GrantTypeClientCredentials
	}

	// Dual-read legacy fallback: if the identity has a non-empty AllowedScopes
	// list, requested scopes must still be a subset. This is retained for one
	// deprecation cycle so tenants that set scope ceilings on the identity row
	// (pre-migration-008) keep working until they migrate the restriction onto
	// their credential policy's allowed_scopes. New callers should not rely on
	// this path.
	// The deprecated identity list is the old allowed_scopes, so the split
	// ceiling (D10) skips it for a bounded user-subject chain too.
	splitCeiling := req.UserGrantBounded && s.resolvePrincipal(req).Type == domain.PrincipalUser
	if !splitCeiling && len(req.Identity.AllowedScopes) > 0 && len(req.Scopes) > 0 {
		allowed := make(map[string]bool, len(req.Identity.AllowedScopes))
		for _, s := range req.Identity.AllowedScopes {
			allowed[s] = true
		}
		for _, requested := range req.Scopes {
			if !allowed[requested] {
				return nil, nil, fmt.Errorf("%w: %q not in allowed_scopes", ErrScopesNotAllowed, requested)
			}
		}
	}

	// Enforce credential policies. The identity policy is the authority
	// ceiling attached at identity registration time; the API key policy is
	// an additional per-credential restriction. Both are checked — the
	// issued token is valid only if it satisfies every assigned policy.
	// Intersection semantics fall out naturally: the narrowest policy wins.
	//
	// Why check both even though the subset invariant guarantees
	// key.policy ⊆ identity.policy at creation time?
	//
	// The subset invariant is a point-in-time check. Two writes can break
	// it after the key is created:
	//
	//   1. Admin tightens the identity policy later. Every existing key
	//      whose policy was a valid subset at creation may now be broader
	//      than the current identity policy. If we only enforce the key
	//      policy, those keys keep minting tokens with scopes/TTLs the
	//      security team has since revoked — the tightening never takes
	//      effect until every key is manually rotated.
	//
	//   2. Admin edits an existing key's policy. Unless every update path
	//      re-validates the subset invariant against the current identity
	//      policy (easy to forget; and cross-admin races make this racy
	//      anyway), a bad edit can leave an over-privileged key.
	//
	// Enforcing both layers at every token issuance makes policy drift
	// self-healing: the narrowest currently-active policy wins, without
	// any reconciliation job or per-key migration. This mirrors how AWS
	// STS re-intersects session policies with the IAM policy on every
	// call (not just AssumeRole) — "session policies cannot grant more
	// permissions than those allowed by the identity-based policy."
	//
	// The extra cost is one GetPolicy lookup per token, and we skip even
	// that when the key inherits the identity policy verbatim (the common
	// case: CredentialPolicyID == IdentityPolicyID), so the hot path pays
	// for exactly one enforcement pass.
	// The principal is decided before enforcement because a policy can require
	// a user subject (required_principal_type).
	principal := s.resolvePrincipal(req)

	// The identity's governing policy, kept for choices beyond enforcement
	// (the token's typ header). Nil when no identity policy governs the grant.
	var identityPolicy *domain.CredentialPolicy
	if s.policySvc != nil {
		var attestationLevel string
		if s.attestationRepo != nil && req.Identity.ID != "" {
			attestationLevel, _ = s.attestationRepo.GetHighestVerifiedLevel(ctx, req.Identity.ID)
		}
		enforceReq := EnforcePolicyRequest{
			TTL:              ttl,
			GrantType:        req.GrantType,
			Scopes:           req.Scopes,
			TrustLevel:       req.Identity.TrustLevel,
			AttestationLevel: attestationLevel,
			DelegationDepth:  req.DelegationDepth,
			PrincipalType:    principal.Type,
			UserGrantBounded: req.UserGrantBounded,
		}

		// Identity policy — governance ceiling.
		//
		// Callers on the OAuth grant paths resolve the identity's policy
		// themselves (via IdentityService.ResolveCredentialPolicy) and pass
		// its ID in IdentityPolicyID — and only do so for grants gated at the
		// identity layer. Three other issuance paths — RotateCredential, the
		// admin issue handler, and post-attestation verification — historically
		// left IdentityPolicyID empty, which turned this "authoritative
		// chokepoint" into a no-op for them and let a since-tightened ceiling be
		// bypassed. They now set ResolveIdentityPolicy so the chokepoint
		// resolves the governing policy when none was supplied, mirroring
		// ResolveCredentialPolicy: prefer the identity's own CredentialPolicyID,
		// else the tenant default (EnsureDefaultPolicy, which always yields a
		// policy so a tenant that never configured one is governed by the
		// default rather than rejected). Callers that pass IdentityPolicyID keep
		// using exactly that policy; we never re-resolve or override it. Callers
		// that neither pass an ID nor opt in are unaffected — preserving the
		// client-gated behavior of authorization_code/refresh_token/CIBA tokens
		// minted for clients with no linked identity.
		identityPolicyID := req.IdentityPolicyID
		if identityPolicyID == "" && req.ResolveIdentityPolicy {
			resolved, err := s.resolveIdentityPolicyID(ctx, req.Identity)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to resolve identity credential policy: %w", err)
			}
			identityPolicyID = resolved
		}

		if identityPolicyID != "" {
			policy, err := s.policySvc.GetPolicy(ctx, identityPolicyID, req.Identity.AccountID, req.Identity.ProjectID)
			if err != nil {
				return nil, nil, fmt.Errorf("identity credential policy %s not found: %w", identityPolicyID, err)
			}
			if err := s.policySvc.EnforcePolicy(ctx, policy, enforceReq); err != nil {
				log.Warn().
					Err(err).
					Str("identity_id", req.Identity.ID).
					Str("policy_id", identityPolicyID).
					Str("policy_layer", "identity").
					Msg("Identity policy enforcement denied issuance")
				return nil, nil, err
			}
			identityPolicy = policy
		}

		// API key policy — per-credential restriction. Checked only when a
		// distinct policy is supplied; if the API key inherits the identity
		// policy we skip the redundant enforcement. Compared against the
		// resolved identity policy (not the raw request field) so the skip
		// still fires when the identity policy was resolved at this layer.
		if req.CredentialPolicyID != "" && req.CredentialPolicyID != identityPolicyID {
			policy, err := s.policySvc.GetPolicy(ctx, req.CredentialPolicyID, req.Identity.AccountID, req.Identity.ProjectID)
			if err != nil {
				return nil, nil, fmt.Errorf("credential policy %s not found: %w", req.CredentialPolicyID, err)
			}
			if err := s.policySvc.EnforcePolicy(ctx, policy, enforceReq); err != nil {
				log.Warn().
					Err(err).
					Str("identity_id", req.Identity.ID).
					Str("policy_id", req.CredentialPolicyID).
					Str("policy_layer", "credential").
					Msg("Credential policy enforcement denied issuance")
				return nil, nil, err
			}
		}
	}

	now := time.Now()
	expiresAt := now.Add(time.Duration(ttl) * time.Second)
	jti := uuid.New().String()

	// The tenant's token profile decides the claim shape. A read failure
	// fails the issuance: minting in the wrong shape after a tenant has
	// switched is the inconsistency a staged rollout has to rule out.
	profile := domain.TokenProfileLegacy
	if s.tenantSettings != nil {
		p, err := s.tenantSettings.TokenProfile(ctx, req.Identity.AccountID, req.Identity.ProjectID)
		if err != nil {
			return nil, nil, err
		}
		profile = p
	}
	rfc8693 := profile == domain.TokenProfileRFC8693
	// Under rfc8693 an exchanged token's top level describes the principal,
	// so the actor's own attributes move inside the outermost `act`.
	actorsInAct := rfc8693 && len(req.Actors) > 0

	// Resolve mission_id (issue #81). Caller (token_exchange) propagates it
	// from the subject_token; first-issuance grants leave it empty and we
	// default to this credential's own JTI — making this credential the
	// root of a new delegation tree. The value is opaque to consumers; the
	// "happens to be a JTI" detail must not leak through any API.
	missionID := req.MissionID
	if missionID == "" {
		missionID = jti
	}

	// Build JWT
	token := jwt.New()
	_ = token.Set(jwt.IssuerKey, s.issuer)
	sub := req.Identity.WIMSEURI
	if req.SubjectOverride != "" {
		sub = req.SubjectOverride
	}
	if rfc8693 {
		// RFC 8693 §4.1 / RFC 9068 §2.2: `sub` is the principal whose
		// authority is used, fixed for the life of the chain. Equal to the
		// legacy value on every non-exchange grant; on an exchange it is the
		// parent's principal rather than the actor.
		sub = principal.Sub
	}
	_ = token.Set(jwt.SubjectKey, sub)
	_ = token.Set(jwt.IssuedAtKey, now)
	_ = token.Set(jwt.ExpirationKey, expiresAt)
	_ = token.Set(jwt.JwtIDKey, jti)
	_ = token.Set("account_id", req.Identity.AccountID)
	_ = token.Set("project_id", req.Identity.ProjectID)
	_ = token.Set("grant_type", string(req.GrantType))

	// Identity claims. external_id, identity_type and trust_level are the
	// actor's own attributes; on an rfc8693 exchange they are carried inside
	// the outermost `act` instead, because the top level describes the person.
	if !actorsInAct {
		_ = token.Set("external_id", req.Identity.ExternalID)
		_ = token.Set("identity_type", string(req.Identity.IdentityType))
		_ = token.Set("trust_level", string(req.Identity.TrustLevel))
	}
	_ = token.Set("sub_type", string(req.Identity.SubType))
	_ = token.Set("status", string(req.Identity.Status))

	// Owner: the human accountable for this credential. Distinct from:
	//   - sub (the principal itself)
	//   - act.sub (the end user the principal is acting on behalf of)
	//
	// Normally the identity's registered owner. OwnerUserIDOverride wins when
	// set, because a shared placeholder identity's owner is not accountable for
	// a credential someone else provisioned under it (see the field doc).
	owner := req.Identity.OwnerUserID
	if req.OwnerUserIDOverride != "" {
		owner = req.OwnerUserIDOverride
	}
	if owner != "" {
		_ = token.Set("owner_user_id", owner)
	}

	if req.DelegationDepth > 0 {
		_ = token.Set("delegation_depth", req.DelegationDepth)
	}

	// Identity metadata — embedded so downstream services can
	// make identity-aware decisions without calling back to ZeroID.
	if req.Identity.Name != "" {
		_ = token.Set("name", req.Identity.Name)
	} else if req.UserName != "" {
		// No principal-specific name (e.g. the trusted external-principal
		// exchange, where the minted principal is an ephemeral service
		// identity acting on behalf of a human). Fall back to the acting
		// user's display name so the OIDC-standard `name` claim (RFC 7519 /
		// OpenID Connect) is populated for spec-compliant clients that read
		// it. `user_name` below still carries the value verbatim; this only
		// mirrors it into the reserved `name` claim when nothing else owns it.
		_ = token.Set("name", req.UserName)
	}
	if req.Identity.Framework != "" {
		_ = token.Set("framework", req.Identity.Framework)
	}
	if req.Identity.Version != "" {
		_ = token.Set("version", req.Identity.Version)
	}
	if req.Identity.Publisher != "" {
		_ = token.Set("publisher", req.Identity.Publisher)
	}
	if len(req.Identity.Capabilities) > 0 && string(req.Identity.Capabilities) != "[]" {
		_ = token.Set("capabilities", req.Identity.Capabilities)
	}

	// JWT-SVID §3 requires `aud` to be present on every issued token. Default
	// to the issuer URL when no audience was supplied so tokens remain
	// interoperable with spec-compliant verifiers (e.g., pkg/authjwt).
	aud := req.Audience
	if len(aud) == 0 {
		aud = []string{s.issuer}
	}
	_ = token.Set(jwt.AudienceKey, aud)
	if len(req.Scopes) > 0 {
		_ = token.Set("scopes", req.Scopes)
	}
	// Generic claims for RS256 tokens (api_key grant).
	if req.ApplicationID != "" {
		_ = token.Set("application_id", req.ApplicationID)
	}
	// RFC 9068 §2.2. Emitted alongside `application_id` rather than replacing
	// it: the authorization_code path has been setting `application_id` to the
	// client_id since long before this claim existed, so anything already
	// keying on that keeps working. New consumers should read `client_id` —
	// the registered name, and the one a resource server that has never seen
	// our stack will look for.
	if req.ClientID != "" {
		_ = token.Set("client_id", req.ClientID)
	}
	if req.UserEmail != "" {
		_ = token.Set("user_email", req.UserEmail)
	}
	if req.UserName != "" {
		_ = token.Set("user_name", req.UserName)
	}

	// Custom claims — extensibility hook for deployment-specific data.
	for k, v := range req.CustomClaims {
		_ = token.Set(k, v)
	}

	// mission_id is set after CustomClaims, not before: every grant filters
	// caller input against reservedClaims, but internal callers also pass
	// CustomClaims, and the lineage a token is grafted onto must come from the
	// exchange's own resolution of the parent and nothing else.
	_ = token.Set("mission_id", missionID)

	if rfc8693 {
		// The principal's type is a private claim (RFC 7519 §4.3): no standard
		// claim says whether `sub` is a person or a workload. Reserved, and set
		// after CustomClaims, so it is only ever ZeroID's own derivation.
		_ = token.Set("principal_type", string(principal.Type))
		// With `sub`, the issuer forms the RFC 9493 iss_sub identifier, so two
		// IdPs' `alice` never collide. Carried on every user-subject token,
		// including exchanged ones, which previously dropped it.
		if principal.Type == domain.PrincipalUser {
			_ = token.Set("user_id_iss", principal.Iss)
		}
		// RFC 9068 §2.2.3 `scope`: the space-delimited string a 9068 resource
		// server reads, emitted beside the `scopes` array until consumers move.
		if len(req.Scopes) > 0 {
			_ = token.Set("scope", strings.Join(req.Scopes, " "))
		}
		// RFC 8693 §4.1 `act`: the current actor outermost, prior actors
		// nested. Only workloads appear; the person is `sub`, never an actor.
		//
		// ActingUserID never becomes `act` here (D6). Only the api_key grant
		// sets it, to the key's creator, and the creator is not acting: §4.1
		// reserves `act` for the party currently acting, and reading it as
		// "the human" is what let one person's brokered credentials be used
		// for every agent whose key they created (highflame-firehog#669). An
		// api-key token is a workload-subject token with no actor; the creator
		// stays identity metadata, carried in owner_user_id and returned by
		// introspection.
		if len(req.Actors) > 0 {
			_ = token.Set("act", actorChainClaim(req.Actors))
		}
	} else {
		// Legacy "act" claim — two use cases:
		//   1. NHI delegation: orchestrator delegates to sub-agent. act.sub = orchestrator WIMSE URI.
		//   2. User context: NHI acts on behalf of an end user. act.sub = user ID.
		// These are mutually exclusive per token — a delegated token already has act from the orchestrator.
		if req.DelegatedBy != "" {
			_ = token.Set("act", map[string]string{"sub": req.DelegatedBy})
		} else if req.ActingUserID != "" {
			_ = token.Set("act", map[string]string{"sub": req.ActingUserID})
		}
	}

	// DPoP binding: embed cnf.jkt so resource servers can match the proof key (RFC 9449 §6.1).
	if req.DPoPKeyThumbprint != "" {
		_ = token.Set("cnf", map[string]string{"jkt": req.DPoPKeyThumbprint})
	}

	// Sign: RS256 for api_key grant (compatible), ES256 for all agent/NHI flows.
	// kid lets verifiers pick the right key from the JWKS. jwx doesn't default
	// typ, so it is always set explicitly (see accessTokenTyp).
	typ := accessTokenTyp(identityPolicy)
	var signed []byte
	var signErr error
	if req.UseRS256 && s.jwksSvc.HasRSAKeys() {
		hdrs := jws.NewHeaders()
		_ = hdrs.Set(jws.KeyIDKey, s.jwksSvc.RSAKeyID())
		_ = hdrs.Set(jws.TypeKey, typ)
		signed, signErr = jwt.Sign(token, jwt.WithKey(jwa.RS256(), s.jwksSvc.RSAPrivateKey(), jws.WithProtectedHeaders(hdrs)))
	} else {
		hdrs := jws.NewHeaders()
		_ = hdrs.Set(jws.KeyIDKey, s.jwksSvc.KeyID())
		_ = hdrs.Set(jws.TypeKey, typ)
		signed, signErr = jwt.Sign(token, jwt.WithKey(jwa.ES256(), s.jwksSvc.PrivateKey(), jws.WithProtectedHeaders(hdrs)))
	}
	if signErr != nil {
		return nil, nil, fmt.Errorf("failed to sign JWT: %w", signErr)
	}

	// Persist credential record. AuditRetentionUntil (evidence clock) is
	// stamped at issuance so the row outlives the token: the delegation
	// graph reads expired rows within the retention window (see the
	// cleanup worker's two-clock prune).
	auditRetentionUntil := expiresAt.Add(s.auditRetention)
	cred := &domain.IssuedCredential{
		ID:                  uuid.New().String(),
		IdentityID:          stringPtrOrNil(req.Identity.ID),
		AccountID:           req.Identity.AccountID,
		ProjectID:           req.Identity.ProjectID,
		JTI:                 jti,
		Subject:             req.Identity.WIMSEURI,
		IssuedAt:            now,
		ExpiresAt:           expiresAt,
		TTLSeconds:          ttl,
		Scopes:              coalesceScopeSlice(req.Scopes),
		GrantType:           req.GrantType,
		DelegationDepth:     req.DelegationDepth,
		ParentJTI:           req.ParentJTI,
		DelegatedByWIMSEURI: req.DelegatedBy,
		MissionID:           missionID,
		DPoPKeyThumbprint:   req.DPoPKeyThumbprint,
		AuditRetentionUntil: &auditRetentionUntil,
		// Persisted for every tenant, whatever its token profile, so a chain
		// minted today is reachable by per-user revocation (phase 2).
		PrincipalType: principal.Type,
		PrincipalSub:  principal.Sub,
		PrincipalIss:  principal.Iss,
	}

	if err := s.repo.Create(ctx, cred); err != nil {
		return nil, nil, fmt.Errorf("failed to persist credential: %w", err)
	}

	log.Info().
		Str("jti", jti).
		Str("identity_id", req.Identity.ID).
		Str("mission_id", missionID).
		Int("ttl_seconds", ttl).
		Msg("Credential issued")

	s.recordUnboundedScope(ctx, req, principal, identityPolicy)

	tokenType := "Bearer"
	if req.DPoPKeyThumbprint != "" {
		tokenType = "DPoP"
	}
	accessToken := &domain.AccessToken{
		AccessToken: string(signed),
		TokenType:   tokenType,
		ExpiresIn:   ttl,
		Scope:       strings.Join(req.Scopes, " "),
		JTI:         jti,
		IssuedAt:    now.Unix(),
	}

	return accessToken, cred, nil
}

// GetCredential retrieves a credential by ID.
func (s *CredentialService) GetCredential(ctx context.Context, id, accountID, projectID string) (*domain.IssuedCredential, error) {
	return s.repo.GetByID(ctx, id, accountID, projectID)
}

// ListCredentials returns credentials for a given identity.
func (s *CredentialService) ListCredentials(ctx context.Context, identityID, accountID, projectID string) ([]*domain.IssuedCredential, error) {
	return s.repo.ListByIdentity(ctx, identityID, accountID, projectID)
}

// ListCredentialsByMission returns every credential in the delegation tree
// keyed by missionID, ordered by delegation_depth ASC then created_at ASC
// so the chain reads from root to leaves. Issue #81: O(1) replacement for
// the recursive parent_jti walk.
func (s *CredentialService) ListCredentialsByMission(ctx context.Context, missionID, accountID, projectID string) ([]*domain.IssuedCredential, error) {
	return s.repo.ListByMissionID(ctx, missionID, accountID, projectID)
}

// SetRevocationDispatcher attaches the shared revocation-event dispatcher.
// Wired once at server construction; the same dispatcher is shared with
// RefreshTokenService so a single Server.SetRevocationNotifier configures every
// revocation path. Nil-safe — when unset, revocation emits no events.
func (s *CredentialService) SetRevocationDispatcher(d *RevocationDispatcher) {
	s.revocationDispatcher = d
}

// RevokeCredential revokes a credential by ID and cascades to any delegated
// descendants. Fires one RevocationNotifier event per affected JTI after the
// revocation commits (on a detached goroutine — never on the request's
// critical path).
//
// Returns ErrCredentialNotFound when the underlying cascade matches zero
// rows. The SQL function filters on id + account_id + project_id, and skips
// rows that are already revoked or past expires_at — so a zero-row outcome
// means one of: wrong id, tenant-scope mismatch, already revoked, or
// already expired. Mapping all four to a typed error turns what used to be
// a silent 200-OK no-op (the handler always set revoked:true) into an
// explicit failure the caller can react to. Real DB errors still surface
// as the underlying error.
func (s *CredentialService) RevokeCredential(ctx context.Context, id, accountID, projectID, reason string) error {
	if reason == "" {
		reason = "manual_revocation"
	}
	revoked, err := s.repo.Revoke(ctx, id, accountID, projectID, reason)
	if err != nil {
		return err
	}
	if len(revoked) == 0 {
		return ErrCredentialNotFound
	}
	s.dispatchRevocations(ctx, revoked, reason)
	return nil
}

// RevokeAllActiveForIdentity revokes every active credential issued to the given
// identity and cascades to any delegated descendants via the parent_jti chain.
// Returns the total number of credentials revoked. Used during agent deactivation
// (and CAE high/critical signal ingest) so existing tokens stop working
// immediately rather than surviving until TTL.
//
// Fires one RevocationNotifier event per affected JTI after the revocation
// commits — if the cascade revokes N tokens, N events are emitted, each on the
// shared dispatcher's detached goroutine so the caller's path is never blocked.
func (s *CredentialService) RevokeAllActiveForIdentity(ctx context.Context, identityID, reason string) (int64, error) {
	if reason == "" {
		reason = "identity_deactivated"
	}
	revoked, err := s.repo.RevokeAllActiveForIdentity(ctx, identityID, reason)
	if err != nil {
		return 0, err
	}
	s.dispatchRevocations(ctx, revoked, reason)
	return int64(len(revoked)), nil
}

// RevokeLongLivedUserAccessTokens revokes a tenant's active user-subject
// access tokens whose lifetime exceeds maxTTLSeconds, cascading to their
// delegated descendants, and returns how many credentials it revoked. Called
// when a tenant switches to the rfc8693 profile, so 90-day roots minted under
// the old no-refresh default do not outlive the switch (D14). Revoking an
// access token leaves its refresh family alone, so a client with the refresh
// grant simply refreshes; one without it re-authorizes.
func (s *CredentialService) RevokeLongLivedUserAccessTokens(ctx context.Context, accountID, projectID string, maxTTLSeconds int, reason string) (int, error) {
	ids, err := s.repo.ListActiveLongLivedUserAccessTokenIDs(ctx, accountID, projectID, maxTTLSeconds)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, id := range ids {
		revoked, err := s.repo.Revoke(ctx, id, accountID, projectID, reason)
		if err != nil {
			return total, err
		}
		s.dispatchRevocations(ctx, revoked, reason)
		total += len(revoked)
	}
	return total, nil
}

// RevokeAllActiveForOwner revokes every active credential belonging to an
// identity owned by ownerUserID within accountID, cascading to any delegated
// descendants via the parent_jti chain. Returns the total number revoked. This
// is the offboarding primitive: when a human is deactivated in the IdP, an
// offboarding handler calls this so every agent that person owns — and every
// sub-agent those agents delegated to — stops working immediately rather than
// surviving until TTL.
//
// Fires one RevocationNotifier event per affected JTI after the revocation
// commits, exactly like RevokeAllActiveForIdentity, so Shield's deny-set picks
// them up within seconds.
//
// Both ownerUserID and accountID are REQUIRED and rejected when empty. This is
// a hard guard, not defensive tidiness: identities.owner_user_id is NOT NULL
// (001_init_schema), so an ownerless identity — the documented posture for
// `discovered` ones (identity-lifecycle.md "Ownership: relaxed for discovered
// only") — stores the empty string. An empty ownerUserID would therefore match
// EVERY ownerless identity in the account and cascade-revoke each one's whole
// delegation subtree. The realistic trigger is the intended caller: an IdP
// offboarding webhook whose user-id field arrives blank, turning "revoke one
// departing human's agents" into a tenant-wide outage of exactly the workloads
// nobody watches. Revocation is not reversible, so this fails closed.
//
// The identity-scoped sibling is protected only incidentally — its uuid cast
// rejects "" with a 22P02 — so the guard lives here explicitly rather than
// relying on that accident holding for a TEXT column. Mirrored in SQL by
// migration 042 so it survives a caller that bypasses this service.
func (s *CredentialService) RevokeAllActiveForOwner(ctx context.Context, ownerUserID, accountID, reason string) (int64, error) {
	// Trim-aware (not just non-empty): a whitespace-only or padded owner
	// passes == "" but matches NO stored row (ownerless identities store "";
	// VARCHAR equality is exact), so the cascade would "succeed" with zero
	// revocations and a broken offboarding integration would look healthy
	// indefinitely. Malformed input fails loudly instead.
	if strings.TrimSpace(ownerUserID) == "" || strings.TrimSpace(ownerUserID) != ownerUserID ||
		strings.TrimSpace(accountID) == "" || strings.TrimSpace(accountID) != accountID {
		return 0, fmt.Errorf(
			"%w: RevokeAllActiveForOwner requires trimmed, non-empty owner_user_id and account_id (got owner=%q account=%q): "+
				"an empty owner matches every ownerless identity in the account, and a padded one silently matches nothing",
			ErrInvalidOwnerArgument, ownerUserID, accountID)
	}

	if reason == "" {
		reason = "owner_deactivated"
	}
	revoked, err := s.repo.RevokeAllActiveForOwner(ctx, ownerUserID, accountID, reason)
	if err != nil {
		return 0, err
	}
	s.dispatchRevocations(ctx, revoked, reason)
	return int64(len(revoked)), nil
}

// dispatchRevocations maps the repository's affected-row projection into
// RevocationEvents and hands them to the shared dispatcher. The dispatcher
// itself owns the async/sync decision, the notifier-installed check, and the
// detached-goroutine lifecycle (mirroring the backchannel notifier). No-op when
// no dispatcher is attached or no notifier is installed — the no-listener path
// stays exactly as cheap as before this hook existed.
func (s *CredentialService) dispatchRevocations(ctx context.Context, revoked []postgres.RevokedCredential, reason string) {
	// hasNotifier short-circuit keeps the default no-listener path allocation-free:
	// skip building the events slice + mapping loop when nobody is subscribed.
	if s.revocationDispatcher == nil || !s.revocationDispatcher.hasNotifier() || len(revoked) == 0 {
		return
	}
	events := make([]RevocationEvent, 0, len(revoked))
	for _, rc := range revoked {
		identityID := ""
		if rc.IdentityID != nil {
			identityID = *rc.IdentityID
		}
		events = append(events, RevocationEvent{
			JTI:        rc.JTI,
			IdentityID: identityID,
			AccountID:  rc.AccountID,
			ProjectID:  rc.ProjectID,
			ExpiresAt:  rc.ExpiresAt,
			Reason:     reason,
			RevokedAt:  rc.RevokedAt,
		})
	}
	s.revocationDispatcher.Dispatch(ctx, events)
}

// resolveIdentityPolicyID returns the ID of the credential policy that
// governs this identity, to be used as the authority ceiling at the issuance
// chokepoint when the caller didn't supply one explicitly.
//
// It mirrors IdentityService.ResolveCredentialPolicy: prefer the identity's
// own CredentialPolicyID, otherwise fall back to the tenant default
// (EnsureDefaultPolicy, which creates one on first use). The chokepoint owns
// this resolution so every issuance path is governed even when its caller
// forgot to resolve and pass IdentityPolicyID. CredentialService already holds
// policySvc, so this introduces no new dependency and no import cycle (the
// OAuth-side resolver lives on IdentityService, which depends on
// CredentialService — reaching the other way would cycle).
//
// EnsureDefaultPolicy always returns a policy, so this never produces an
// "unrestricted, no policy" outcome for a tenant that simply never configured
// one — that tenant is governed by the permissive default policy, matching the
// OAuth grant paths exactly.
func (s *CredentialService) resolveIdentityPolicyID(ctx context.Context, identity *domain.Identity) (string, error) {
	if s.policySvc == nil || identity == nil {
		return "", nil
	}
	if identity.CredentialPolicyID != "" {
		return identity.CredentialPolicyID, nil
	}
	policy, err := s.policySvc.EnsureDefaultPolicy(ctx, identity.AccountID, identity.ProjectID)
	if err != nil {
		return "", err
	}
	return policy.ID, nil
}

// RotateCredential revokes an existing credential and immediately issues a new one for the same identity.
// The new credential inherits the scopes and TTL of the old one unless overridden.
func (s *CredentialService) RotateCredential(ctx context.Context, credID, accountID, projectID string, identity *domain.Identity) (*domain.AccessToken, *domain.IssuedCredential, error) {
	old, err := s.repo.GetByID(ctx, credID, accountID, projectID)
	if err != nil {
		return nil, nil, fmt.Errorf("credential not found: %w", err)
	}
	// Both terminal-state rejections wrap a sentinel so the handler maps
	// them to 409, not 500: with rows now outliving their tokens by the
	// audit-retention window, rotating a long-dead credential is a routine
	// client mistake, not a server fault, and must not fire 5xx alerting.
	if old.IsRevoked {
		return nil, nil, fmt.Errorf("%w: issue a new credential instead of rotating", domain.ErrCredentialAlreadyRevoked)
	}
	// An expired credential cannot be rotated: the revoke half would be a
	// silent no-op (the cascade anchor requires expires_at > revoked_at) and
	// "rotate" would degrade to minting a fresh token off a dead row.
	if time.Now().After(old.ExpiresAt) {
		return nil, nil, fmt.Errorf("%w: issue a new credential instead of rotating", domain.ErrCredentialExpired)
	}

	// Revoke the old credential (cascades to descendants and fires the
	// RevocationNotifier per affected JTI, same as any other revoke path).
	revoked, err := s.repo.Revoke(ctx, credID, accountID, projectID, "rotated")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to revoke old credential during rotation: %w", err)
	}
	s.dispatchRevocations(ctx, revoked, "rotated")

	// Issue a new one with the same parameters.
	return s.IssueCredential(ctx, IssueRequest{
		Identity:              identity,
		Scopes:                old.Scopes,
		TTL:                   old.TTLSeconds,
		GrantType:             old.GrantType,
		ResolveIdentityPolicy: true,
	})
}

// coalesceScopeSlice returns an empty slice if scopes is nil (avoids DB NOT NULL violations).
func coalesceScopeSlice(scopes []string) []string {
	if scopes == nil {
		return []string{}
	}
	return scopes
}

// stringPtrOrNil returns a pointer to s if non-empty, or nil (for nullable UUID columns).
func stringPtrOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// IntrospectToken checks the validity of a JTI against the credential store.
func (s *CredentialService) IntrospectToken(ctx context.Context, jti string) (*domain.IssuedCredential, bool, error) {
	cred, err := s.repo.GetByJTI(ctx, jti)
	if err != nil {
		return nil, false, nil // not found = inactive
	}
	if cred.IsRevoked {
		return cred, false, nil
	}
	if time.Now().After(cred.ExpiresAt) {
		return cred, false, nil
	}
	return cred, true, nil
}
