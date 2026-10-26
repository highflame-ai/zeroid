package service

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/jwtalg"
	"github.com/highflame-ai/zeroid/internal/oautherror"
	"github.com/highflame-ai/zeroid/internal/telemetry"
)

// externalIDTokenClockSkew is the leeway allowed when validating the upstream
// ID token's exp/nbf/iat against ZeroID's clock. Per issue #88 (and standard
// OIDC practice) a small skew absorbs clock drift between the IdP and ZeroID
// so federation isn't brittle to sub-minute differences.
const externalIDTokenClockSkew = 60 * time.Second

// SubjectTokenTypeIDToken is the RFC 8693 subject_token_type for an OIDC ID
// token. ZeroID dispatches token-exchange requests carrying this type to the
// direct-federation path (issue #88) instead of the broker path.
const SubjectTokenTypeIDToken = "urn:ietf:params:oauth:token-type:id_token"

// SubjectTokenTypeJWT is the RFC 8693 §3 subject_token_type for a JWT of no
// more specific type.
const SubjectTokenTypeJWT = "urn:ietf:params:oauth:token-type:jwt"

// jwtSubjectIsIDTokenExchange reports whether a token exchange that names its
// subject only as a JWT is an ID-token exchange. RFC 8693 §3 lets a client use
// the generic JWT type for any JWT, and a credential broker that exchanges, on
// a workload's behalf, the token the workload was called with sends it for an
// OIDC ID token.
//
// It is one only when the request authenticates a client and the caller is not
// a trusted service. The broker path refuses every other caller, so no request
// it accepts today changes path. externalIDTokenExchange still authenticates the
// client, requires an ID token issued to that client, and refuses an issuer that
// is not a trusted person issuer, so a JWT of any other kind is refused there.
func (s *OAuthService) jwtSubjectIsIDTokenExchange(ctx context.Context, req TokenRequest) bool {
	if req.SubjectTokenType != SubjectTokenTypeJWT {
		return false
	}
	if req.ClientID == "" && !clientAssertionPresented(req.ClientAssertion, req.ClientAssertionType) {
		return false
	}
	if s.trustedServiceValidator != nil {
		if _, err := s.trustedServiceValidator(ctx); err == nil {
			return false
		}
	}
	return true
}

// idTokenIssuedTo checks that an OIDC ID token was issued to clientID (D13),
// per OpenID Connect Core §2 and §3.1.3.7: clientID must be one of the
// token's audiences, and when the token names an authorized party (azp) it
// must be clientID. A token with several audiences must name one, since
// otherwise any of them could claim it.
func idTokenIssuedTo(token jwt.Token, clientID string) error {
	aud, _ := token.Audience()
	if !slices.Contains(aud, clientID) {
		return oauthBadRequestCause(oautherror.InvalidGrant, "subject_token was not issued to the authenticated client (aud)", errAssertionAudience)
	}
	// An azp that is present must be a string equal to clientID: one of
	// another type is refused, never read as absent.
	hasAZP := token.Has("azp")
	if hasAZP {
		if azp, err := jwt.Get[string](token, "azp"); err != nil || azp != clientID {
			return oauthBadRequestCause(oautherror.InvalidGrant, "subject_token was issued to a different authorized party (azp)", errAssertionAudience)
		}
	}
	if !hasAZP && len(aud) > 1 {
		return oauthBadRequestCause(oautherror.InvalidGrant, "subject_token has several audiences and no azp naming the authenticated client", errAssertionAudience)
	}
	return nil
}

// Causes wrapped onto the *OAuthError of a refused external assertion, for
// callers that report the reason as a code (VerifyIDToken). The wire answer
// on the grants is unchanged: invalid_grant.
var (
	errAssertionAudience    = errors.New("the assertion was not issued to the expected audience")
	errAssertionConstraints = errors.New("the assertion does not satisfy the issuer's claim constraints")
)

// personIDToken is a person's ID token verified by verifyPersonIDToken, with
// what the issuer's claim mapping reads from it.
type personIDToken struct {
	claims        map[string]any
	userID        string
	email         string
	emailVerified bool
	name          string
}

// verifyPersonIDToken verifies an OpenID Connect ID token naming a person,
// issued by entry's IdP to clientID: the P1c checks that need no binding
// (ADR 0042 D3a rules 1 to 3). Signature against the issuer's JWKS, iss,
// exp/nbf/iat with the shared skew and max_token_age, the row's claim
// constraints (and shared-issuer pin), the token being an ID token and not
// an access token, aud naming clientID with azp equal to it when present,
// the mapped user_id, and a person rather than a workload subject. The
// email and email_verified come from the row's claim mapping (Entra's
// xms_edov).
//
// It is the single routine both the ID-token exchange and the issuer
// ownership proof (ExternalIssuerService.VerifyIDToken) run, so the proof
// can never accept a token the grant would refuse on these checks. On an
// issuer row clientID is an accepted audience beside the row's own: on the
// exchange an enabled binding for it is required afterwards.
func verifyPersonIDToken(ctx context.Context, raw string, entry *ExternalIssuerEntry, clientID string) (*personIDToken, error) {
	var extraAudiences []string
	if entry.Row != nil {
		extraAudiences = []string{clientID}
	}
	verified, err := validateExternalAssertion(ctx, raw, entry, "subject_token", requirePlainSub, extraAudiences...)
	if err != nil {
		return nil, err
	}
	if err := requireIDToken(raw, verified); err != nil {
		return nil, err
	}
	if err := idTokenIssuedTo(verified, clientID); err != nil {
		return nil, err
	}
	// Single-level claim names only. v4 dropped AsMap, so the claims are
	// materialized from Keys()/Get().
	mapping := entry.Config.ClaimMapping
	claims := tokenClaimsAsMap(verified)
	userID, ok := extractMappedClaimString(claims, mapping["user_id"])
	if !ok || userID == "" {
		return nil, oauthBadRequest("invalid_grant", fmt.Sprintf("subject_token missing claim %q (mapped to user_id)", mapping["user_id"]))
	}
	if err := refuseWorkloadSubject(claims, userID); err != nil {
		return nil, err
	}
	out := &personIDToken{claims: claims, userID: userID}
	out.email, _ = extractMappedClaimString(claims, mapping["email"])
	out.emailVerified = issuerEmailVerified(claims, entry.Config, out.email)
	out.name, _ = extractMappedClaimString(claims, mapping["name"])
	return out, nil
}

// requireIDToken is ADR 0042 D3a rule 2: the subject token is positively an
// ID token, not merely a JWT from a trusted issuer. IdPs do not type ID
// tokens, so this means the OpenID Connect Core §2 claims are present and no
// access-token marker is (RFC 9068 §2.1 typ, scp or scope). The aud check
// that separates the two is idTokenIssuedTo. Signature, iss, exp and iat
// were verified before this runs.
func requireIDToken(raw string, verified jwt.Token) error {
	if hdr, ok := decodeJWTHeader(raw); ok {
		switch strings.ToLower(hdr.Typ) {
		case "at+jwt", "application/at+jwt":
			return oauthBadRequest(oautherror.InvalidGrant, "subject_token is an access token (typ at+jwt), not an ID token")
		case idJAGTyp:
			return oauthBadRequest(oautherror.InvalidGrant, "subject_token is an ID-JAG; redeem it with the jwt-bearer grant")
		}
	}
	for _, claim := range []string{"iss", "sub", "aud", "exp", "iat"} {
		if !verified.Has(claim) {
			return oauthBadRequest(oautherror.InvalidGrant, fmt.Sprintf("subject_token is not an ID token: it has no %s claim", claim))
		}
	}
	// Entra stamps azpacr (v2) or appidacr (v1) on every access token, the
	// app-only ones included, and never on an ID token. roles alone is not
	// a marker: Entra ID tokens carry a user's app roles in it.
	for _, claim := range []string{"scp", "scope", "azpacr", "appidacr"} {
		if verified.Has(claim) {
			return oauthBadRequest(oautherror.InvalidGrant, fmt.Sprintf("subject_token carries %s, which marks an access token, not an ID token", claim))
		}
	}
	return nil
}

// TokenTypeAccessToken is the RFC 8693 §3 identifier for an OAuth 2.0 access
// token, returned as issued_token_type on every token-exchange response.
const TokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"

// ErrUnknownExternalIssuer is the cause when a person grant's token names an
// issuer nobody trusts. It is wrapped onto the *OAuthError so callers can
// branch with errors.Is; on the wire it is the same generic invalid_grant as
// every other issuer refusal (resolvePersonIssuer), so a probe cannot tell an
// unknown issuer from a disabled or workload one.
var ErrUnknownExternalIssuer = errors.New("issuer is not a configured external issuer")

// SetExternalIssuerRegistry installs a registry of trusted external IdPs.
// Must be set before /oauth2/token requests with subject_token_type=id_token
// can be served — without a registry, those requests are rejected with
// invalid_request.
func (s *OAuthService) SetExternalIssuerRegistry(r *ExternalIssuerRegistry) {
	s.externalIssuerRegistry = r
}

// externalIDTokenExchange handles RFC 8693 token exchange where the
// subject_token is an OIDC ID token and ZeroID itself verifies it (issue
// #88).
//
// This is the spec-aligned preferred path for ingesting upstream user
// identity. Compared to ExternalPrincipalExchange (the broker pattern):
//
//   - ZeroID verifies the upstream signature against a configured JWKS,
//     so trust flows from the IdP directly rather than from a relay
//     service.
//   - The issued token carries user_id_iss = upstream iss, giving every
//     downstream consumer per-IdP provenance (NIST SP 800-63C §4.1).
//   - RFC 9068 authentication-context claims (auth_time, acr, amr) can
//     be propagated through truthfully because we read them from the
//     token we just verified.
//
// TrustedServiceValidator is bypassed on this path: the JWKS signature
// check + issuer allowlist + audience binding are the proof of trust.
// That bypass is intentional and the entire point of the new path.
func (s *OAuthService) externalIDTokenExchange(ctx context.Context, req TokenRequest) (*domain.AccessToken, error) {
	if req.SubjectToken == "" {
		return nil, oauthBadRequest("invalid_request", "subject_token is required")
	}

	// D13: only the relying party an ID token was issued to may redeem it, and
	// it must authenticate as that client. Authenticated first, so nothing
	// about the token's issuer is looked up or revealed to an anonymous
	// caller. cimdFallback=false: this path does not gate on the client's
	// declared grant_types, so a self-asserted document must not resolve here.
	if req.ClientID == "" {
		return nil, oauthUnauthorized("ID-token exchange requires client authentication", nil)
	}
	authedClient, err := s.authenticateRegisteredClient(ctx, req, false)
	if err != nil {
		return nil, err
	}

	if s.externalIssuerRegistry == nil || !s.externalIssuerRegistry.HasAny() {
		return nil, oauthBadRequest("invalid_request", "no external issuers are configured for direct OIDC federation")
	}
	entry, upstreamIss, err := s.resolvePersonIssuer(ctx, req.SubjectToken, "subject_token")
	if err != nil {
		return nil, err
	}
	cfg := entry.Config

	var identity *domain.Identity
	if entry.Row != nil {
		// ADR 0042 D3a rule 1 (issuer rows): the relying party proves itself
		// with a key, never a shared secret, so an agent needs no Highflame
		// secret (D8). Static issuers keep the client's registered method.
		if authedClient.TokenEndpointAuthMethod != clientAuthMethodPrivateKeyJWT {
			return nil, oauthUnauthorized("the ID-token exchange requires private_key_jwt client authentication; "+
				"a client secret is not accepted", nil)
		}
		// The binding is the audience rule (D3a): verifyPersonIDToken accepts
		// the presenting client_id beside the row's optional audiences, and
		// bindFederatedAgent below refuses a client with no enabled binding.
		// The binding is read only after the token is verified, so a forged
		// token cannot raise events under the account or learn its binding
		// state.
	} else {
		// A static issuer, in standalone ZeroID, takes the tenant from the
		// caller, inside its allowed_accounts (D5 is for issuer rows).
		if req.AccountID == "" || req.ProjectID == "" {
			return nil, oauthBadRequest("invalid_request", "account_id and project_id are required for external id_token exchange")
		}
		if !cfg.AccountAllowed(req.AccountID) {
			return nil, oauthBadRequest("invalid_request", fmt.Sprintf("account %s is not allowed to use issuer %s", req.AccountID, upstreamIss))
		}
	}

	// Verify the upstream ID token against its IdP (signature, iss, aud/azp,
	// exp/nbf/iat, alg allow-list, MaxTokenAge, constraints, ID-token shape,
	// person subject) and read the mapped claims. The issuer ownership proof
	// runs the same routine.
	idTok, err := verifyPersonIDToken(ctx, req.SubjectToken, entry, authedClient.ClientID)
	if err != nil {
		return nil, err
	}
	rawClaims, userID, userEmail, userName := idTok.claims, idTok.userID, idTok.email, idTok.name

	// For an issuer row the agent is the identity the presenting client is
	// bound to under the row (D6: on P1c the subject key is the client_id),
	// and the tenant is that identity's (D5). Static issuers keep the
	// caller-named application, or a synthetic carrier.
	var actors []domain.Actor
	if entry.Row != nil {
		identity, err = s.bindFederatedAgent(ctx, entry.Row, authedClient.ClientID, authedClient, federatedGrantIDToken)
		if err != nil {
			return nil, err
		}
		if err := federatedTenant(identity, req.AccountID, req.ProjectID); err != nil {
			return nil, err
		}
		if req.ApplicationID != "" && req.ApplicationID != identity.ID {
			return nil, oauthBadRequest(oautherror.InvalidGrant, "application_id is not the agent the presenting client is bound to")
		}
		req.AccountID, req.ProjectID = identity.AccountID, identity.ProjectID
		// The bound agent is the current actor (ADR 0043 D2), as on ID-JAG.
		actors = idJAGActors(identity)
	} else {
		identity, err = s.resolveExternalPrincipalIdentity(ctx, req)
		if err != nil {
			return nil, err
		}
	}

	// The person must be a member of the tenant (ADR 0042 D5a); the token's
	// sub becomes the deployer's user id and the IdP pair moves to user_idp_iss/user_idp_sub.
	person, err := s.resolveFederatedPerson(ctx, entry.Row != nil, FederatedPersonRequest{
		GrantType:       PersonGrantExternalIDToken,
		AccountID:       req.AccountID,
		ProjectID:       req.ProjectID,
		Issuer:          upstreamIss,
		IssuerID:        issuerRowID(entry),
		Subject:         userID,
		Email:           userEmail,
		EmailVerified:   idTok.emailVerified,
		ClientID:        authedClient.ClientID,
		AgentIdentityID: identity.ID,
	})
	if err != nil {
		return nil, err
	}

	// Build provenance claims. user_id_iss is the headline addition: it
	// pins the upstream IdP onto every issued token, so consumers can
	// answer "which IdP authenticated this user" from the token alone.
	customClaims := map[string]any{
		"token_exchange": "external_id_token",
		"user_id_iss":    upstreamIss,
	}

	// Honest propagation: only forward auth_time/acr/amr when (a) the
	// deployer asked for them and (b) the upstream actually set them.
	// We never default-fill — RFC 9068 authentication-context claims are
	// only meaningful when they reflect the IdP's authentication event.
	//
	// reservedClaims is enforced here too, not just on the AdditionalClaims loop
	// below. Config restricts propagate_claims to auth_time/acr/amr today
	// (domain.ExternalIssuerConfig.Validate), so nothing reserved can reach this
	// loop — but that is a guarantee held one file away, and `resource` in
	// particular is only a trustworthy signal while bindResourceOnIssue is its
	// sole writer. A deployer-controlled list that can name claims must not be
	// the one place that could quietly become an exception.
	for _, claim := range cfg.PropagateClaims {
		if reservedClaims[claim] {
			continue
		}
		if v, present := rawClaims[claim]; present {
			customClaims[claim] = v
		}
	}

	// Caller-provided AdditionalClaims pass through the same blocklist as
	// the broker path. user_id_iss is in reservedClaims so callers cannot
	// spoof IdP provenance.
	for k, v := range req.AdditionalClaims {
		if reservedClaims[k] {
			continue
		}
		customClaims[k] = v
	}

	// Resolve the identity's credential policy when we have a real identity
	// row, so issuance enforces the same policy ceiling (allowed scopes, max
	// TTL, trust level, policy expiry) as every other grant.
	var identityPolicyID string
	if identity.ID != "" {
		policy, err := s.identitySvc.ResolveCredentialPolicy(ctx, identity)
		if err != nil {
			return nil, oauthServerError("failed to resolve identity credential policy", err)
		}
		identityPolicyID = policy.ID
	}

	scopes := parseScopeString(req.Scope)
	issue := IssueRequest{
		// The IdP's scopes are not read on this path, so the token is bounded
		// only by the caller's request and the governing policy (ceiling rule, P1).
		RequestBoundedRoot: true,
		Identity:           identity,
		IdentityPolicyID:   identityPolicyID,
		// Govern the synthetic-carrier path (no application_id, so no identity
		// row and no IdentityPolicyID above) by the tenant default policy.
		// resolveIdentityPolicyID falls back to EnsureDefaultPolicy on the
		// request's account_id/project_id, so requested scopes are gated by the
		// tenant policy ceiling instead of passing through ungated. Without
		// this, any holder of a valid upstream token could request arbitrary
		// scopes on the no-application_id path — a weaker gate than the broker
		// path, which is at least fronted by TrustedServiceValidator.
		ResolveIdentityPolicy: true,
		GrantType:             domain.GrantTypeTokenExchange,
		Scopes:                scopes,
		UseRS256:              true,
		UserEmail:             userEmail,
		UserName:              userName,
		ApplicationID:         req.ApplicationID,
		// RFC 9068 §2.2 client_id: the relying party just authenticated and
		// bound to the ID token's aud/azp (D13), so it is the client the
		// token is issued to.
		ClientID:          authedClient.ClientID,
		Actors:            actors,
		TTL:               900, // 15 minutes — same short-lived posture as the broker path
		CustomClaims:      customClaims,
		DPoPKeyThumbprint: req.DPoPKeyThumbprint,
		PersonGrantType:   PersonGrantExternalIDToken,
	}
	// RFC 8707 resource binding (CAP-IDN-026). token-exchange forks THREE ways —
	// this id_token federation path, the trusted external-principal exchange, and
	// NHI delegation — and the grant type as a whole is in
	// resourceSupportedGrants, so the Token() gate admits `resource` for all
	// three. A fork that does not bind here does not ignore the parameter
	// harmlessly: it returns 200 with an UNBOUND token, and Shield's
	// checkResourceBinding then allows the request at every MCP server because
	// the discriminator claim is absent. The caller believes it holds a token
	// narrowed to one server and holds one honoured everywhere.
	//
	// Binding rather than rejecting: this is an ordinary federation grant with no
	// upstream authorized set to narrow against, so the requested resource simply
	// restricts the token it would have minted anyway — the same treatment
	// client_credentials and api_key get.
	person.apply(&issue)
	bindResourceOnIssue(&issue, req.Resource)

	accessToken, _, err := s.credentialSvc.IssueCredential(ctx, issue)
	if err != nil {
		if mapped := personGrantOAuthError(err, oautherror.InvalidScope); mapped != err {
			return nil, mapped
		}
		if issuanceRefusal(err) {
			return nil, err
		}
		return nil, oauthServerError("failed to issue external id_token exchange token", err)
	}

	accessToken.AccountID = req.AccountID
	accessToken.ProjectID = req.ProjectID
	accessToken.UserID = person.sub

	log.Info().
		Str("upstream_iss", upstreamIss).
		Str("account_id", req.AccountID).
		Str("project_id", req.ProjectID).
		Str("user_id", person.sub).
		Msg("external id_token exchange succeeded")

	return accessToken, nil
}

// resolvePersonIssuer reads the token's issuer and resolves the trusted
// person issuer it must verify against (ADR 0042 D4: person grants accept
// only enabled person rows). Every refusal is one generic invalid_grant on
// the wire, since the token is not verified yet: telling an unknown issuer
// from a disabled, workload or unmatched one would let a probe learn which
// IdPs a deployment trusts. The reason is logged and counted. Callers
// authenticate the client first.
func (s *OAuthService) resolvePersonIssuer(ctx context.Context, token, fieldName string) (*ExternalIssuerEntry, string, error) {
	peeked, err := jwt.ParseInsecure([]byte(token))
	if err != nil {
		return nil, "", oauthBadRequestCause(oautherror.InvalidGrant, fieldName+" is malformed", err)
	}
	iss, ok := peeked.Issuer()
	if !ok || iss == "" {
		return nil, "", oauthBadRequest(oautherror.InvalidGrant, fieldName+" missing iss claim")
	}
	entry, err := s.externalIssuerRegistry.ResolvePerson(ctx, iss, tokenClaimsAsMap(peeked))
	if err == nil {
		return entry, iss, nil
	}
	if errors.Is(err, errIssuerLookupFailed) {
		return nil, "", oauthServerError("failed to resolve the external issuer", err)
	}
	reason := "unknown"
	switch {
	case errors.Is(err, errIssuerNotPerson):
		reason = "workload_issuer"
	case errors.Is(err, errIssuerDisabled):
		reason = "disabled"
	case errors.Is(err, errIssuerConstraints):
		reason = "constraints"
	case errors.Is(err, errIssuerAmbiguous):
		reason = "ambiguous"
	}
	telemetry.FederationIssuerRefused.Add(ctx, 1, metric.WithAttributes(attribute.String("reason", reason)))
	log.Info().Err(err).Str("issuer", iss).Str("reason", reason).Msg("federation_issuer_refused")
	return nil, "", oauthBadRequestCause(oautherror.InvalidGrant, fieldName+"'s issuer is not trusted for this grant", err)
}

// validateExternalAssertion runs the #88 external-IdP validation substrate
// against a single externally-signed assertion: the JWS algorithm allow-list
// gate, a synchronous best-effort JWKS load, full signature + iss + aud +
// exp/nbf verification (with a one-shot JWKS refresh + retry on an unknown
// kid to absorb upstream key rotation), and the RFC 7523 §3 presence checks
// for sub/exp plus the iat-based MaxTokenAge stale-token cap.
//
// It is the single security-critical verification routine shared by BOTH
// external-IdP ingestion paths:
//   - externalIDTokenExchange (RFC 8693 subject_token_type=id_token, #88)
//   - idJAGBearer (RFC 7523 jwt-bearer carrying an MCP ID-JAG, ADR 0010)
//
// so neither path can drift from the other. The issuer lookup and the
// AllowedAccounts tenant binding stay in each caller, because their OAuth
// error-code semantics differ (id_token: invalid_request for an unconfigured
// issuer; ID-JAG: invalid_grant, fail-closed). fieldName names the assertion
// in error strings ("subject_token" vs "assertion") so callers surface the
// right wire field. On success the verified token is returned for claim
// mapping; on any failure an *OAuthError shaped for direct return.
// subjectRequirement says what satisfies RFC 7523 §3's requirement that an
// assertion "identify the principal that is the subject of the JWT".
//
// It is a parameter rather than a constant because the two callers are on
// different profiles and the answer genuinely differs — and because relaxing it
// for both would be a security change to the external-IdP token exchange that
// nobody asked for.
type subjectRequirement int

const (
	// requirePlainSub is RFC 7523 §3 as written: a `sub` claim, or nothing. The
	// external-IdP subject_token exchange stays here.
	requirePlainSub subjectRequirement = iota

	// allowSubjectIdentifier additionally accepts a resolvable RFC 9493 `sub_id`
	// (zeroid#265).
	//
	// A DELIBERATE DEVIATION FROM RFC 7523 §3, confined to the ID-JAG profile,
	// and worth stating plainly because the specs disagree: §3 says the JWT MUST
	// carry `sub`, while the MCP interop matrix lists `sub_id` as a supported
	// way for an ID-JAG to name its subject — and its acceptance case drops
	// `sub` entirely. An assertion in that shape is non-conformant to RFC 7523
	// read literally.
	//
	// Accepted here because `sub_id` identifies the principal at least as
	// precisely as `sub` does (more so for iss_sub, which cannot collide across
	// issuers), so the SPIRIT of §3 is met even where the letter is not. Scoped
	// to this one profile so the deviation is a decision recorded in one place
	// rather than a general loosening — subject_token is unaffected.
	allowSubjectIdentifier
)

// extraAudiences are accepted beside the issuer's configured audiences.
func validateExternalAssertion(ctx context.Context, assertion string, entry *ExternalIssuerEntry, fieldName string, subjectReq subjectRequirement, extraAudiences ...string) (jwt.Token, error) {
	cfg := entry.Config

	// Algorithm allowlist gate. Read the JWS header before signature
	// verification — defense-in-depth against alg confusion. Any alg outside
	// the configured set (or outside the small whitelist of secure asymmetric
	// algs we actually support) is rejected.
	if err := checkExternalIDTokenAlg(assertion, cfg.Algorithms); err != nil {
		return nil, oauthBadRequestCause("invalid_grant", fmt.Sprintf("%s uses a disallowed algorithm", fieldName), err)
	}

	// Ensure the issuer's JWKS is loaded. authjwt warms up best-effort at
	// startup and refreshes in the background (it deliberately does not fail
	// construction on an unreachable JWKS, to survive transient IdP blips).
	// This synchronous load covers the case where the startup warm-up failed,
	// so the first request self-heals rather than failing. A genuinely
	// unreachable IdP returns an error here and we fail closed.
	if err := entry.JWKS.EnsureLoaded(ctx); err != nil {
		return nil, oauthServerError(fmt.Sprintf("failed to load JWKS for issuer %s", cfg.Issuer), err)
	}

	// Verify signature, exp, nbf, iss, and aud against the configured IdP
	// in one Parse call. WithKeySet picks the right key by kid from the JWKS
	// we cache for this issuer.
	//
	// WithInferAlgorithmFromKey is REQUIRED, not optional: jwx selects the
	// verification alg from the JWK's `alg` member, but many production IdPs
	// (Microsoft Entra ID is the canonical example) publish JWKS keys with no
	// `alg` member at all. Without inference, jwx supplies no key for those and
	// every verification fails — i.e. federation would silently never work
	// against Entra. Inference is safe here because checkExternalIDTokenAlg has
	// already pinned the token header alg to the asymmetric allow-list above,
	// and jwx's infer path additionally rejects any header alg the key type
	// cannot produce — so HS*/none still cannot slip through.
	keySet := entry.JWKS.KeySet()
	if keySet == nil || keySet.Len() == 0 {
		return nil, oauthServerError(fmt.Sprintf("JWKS for issuer %s is empty", cfg.Issuer), nil)
	}
	verified, err := jwt.Parse([]byte(assertion),
		jwt.WithKeySet(keySet, jws.WithInferAlgorithmFromKey(true)),
		jwt.WithValidate(true),
		jwt.WithIssuer(cfg.Issuer),
		jwt.WithAcceptableSkew(externalIDTokenClockSkew),
	)
	if err != nil {
		// On unknown kid, refresh the JWKS once and retry — handles upstream
		// key rotation without requiring a server restart.
		if kid := extractJWSKeyID(assertion); kid != "" && entry.JWKS.RefreshIfMissing(ctx, kid) {
			keySet = entry.JWKS.KeySet()
			verified, err = jwt.Parse([]byte(assertion),
				jwt.WithKeySet(keySet, jws.WithInferAlgorithmFromKey(true)),
				jwt.WithValidate(true),
				jwt.WithIssuer(cfg.Issuer),
				jwt.WithAcceptableSkew(externalIDTokenClockSkew),
			)
		}
		if err != nil {
			return nil, oauthBadRequestCause("invalid_grant", fmt.Sprintf("%s verification failed", fieldName), err)
		}
	}

	// aud must name one of the issuer's audiences. Checked here rather than
	// with jwt.WithAudience, which accepts only one value.
	aud, _ := verified.Audience()
	accepted := append(cfg.AudienceList(), extraAudiences...)
	if !slices.ContainsFunc(accepted, func(a string) bool { return slices.Contains(aud, a) }) {
		return nil, oauthBadRequestCause(oautherror.InvalidGrant, fmt.Sprintf("%s verification failed: aud is not one this issuer is trusted for", fieldName), errAssertionAudience)
	}
	// A shared issuer's row was chosen on unverified claims; its constraints
	// must also hold on the verified ones.
	if entry.Row != nil && !entry.Row.ConstraintsMatch(tokenClaimsAsMap(verified), entry.PinClaim) {
		return nil, oauthBadRequestCause(oautherror.InvalidGrant, fmt.Sprintf("%s does not satisfy the issuer's claim constraints", fieldName), errAssertionConstraints)
	}

	// jwx's validation only checks exp/nbf when present; RFC 7523 §3 requires
	// both sub and exp on an assertion. Enforce their presence explicitly so a
	// token without an expiry (replayable forever) or without a subject is
	// rejected rather than silently accepted.
	if _, ok := verified.Subject(); !ok {
		if subjectReq != allowSubjectIdentifier {
			return nil, oauthBadRequest("invalid_grant", fmt.Sprintf("%s missing required sub claim", fieldName))
		}
		// An RFC 9493 `sub_id` may stand in for `sub` on this profile. It must
		// actually RESOLVE — a present-but-unreadable one is reported as such
		// rather than as a missing subject, because those are different faults
		// and the publisher can only fix the one they are told about.
		verifiedIss, _ := verified.Issuer()
		subID, subIDErr := parseSubjectIdentifier(tokenClaimsAsMap(verified), verifiedIss)
		if subIDErr != nil {
			return nil, oauthBadRequest("invalid_grant", fmt.Sprintf("%s has an unusable sub_id: %v", fieldName, subIDErr))
		}
		if subID == nil {
			return nil, oauthBadRequest("invalid_grant",
				fmt.Sprintf("%s has neither a sub claim nor a sub_id — nothing identifies the principal", fieldName))
		}
	}
	if _, ok := verified.Expiration(); !ok {
		return nil, oauthBadRequest("invalid_grant", fmt.Sprintf("%s missing required exp claim", fieldName))
	}

	// Stale-token cap. exp guards future-side; iat guards past-side. We
	// require iat present and not older than max_token_age — the upstream
	// signed it for a fresh authentication, not a replay from days ago.
	iat, iatPresent := verified.IssuedAt()
	if !iatPresent || iat.IsZero() {
		return nil, oauthBadRequest("invalid_grant", fmt.Sprintf("%s missing iat claim", fieldName))
	}
	if age := time.Since(iat); age > cfg.MaxTokenAge {
		return nil, oauthBadRequest("invalid_grant", fmt.Sprintf("%s age %s exceeds max_token_age %s", fieldName, age.Round(time.Second), cfg.MaxTokenAge))
	}

	return verified, nil
}

// resolveExternalPrincipalIdentity factors out the identity-resolution step
// shared between the broker and direct-federation paths. ApplicationID, when
// provided, must resolve to an active identity in the caller's tenant; this
// is the IDOR guard that prevents a token-exchange request from minting a
// token for someone else's application. With no ApplicationID we synthesize
// a service identity (same shape the broker path used).
func (s *OAuthService) resolveExternalPrincipalIdentity(ctx context.Context, req TokenRequest) (*domain.Identity, error) {
	if req.ApplicationID == "" {
		return &domain.Identity{
			AccountID:    req.AccountID,
			ProjectID:    req.ProjectID,
			IdentityType: domain.IdentityTypeService,
			Status:       domain.IdentityStatusActive,
		}, nil
	}
	resolved, err := s.identitySvc.GetIdentity(ctx, req.ApplicationID, req.AccountID, req.ProjectID)
	if err != nil {
		// Distinguish "row not found / wrong tenant" (client error, 400) from
		// a transient infrastructure failure (server error, 500 — retriable).
		// The repository wraps sql.ErrNoRows for both genuine-missing and
		// IDOR-protected cross-tenant lookups; anything else is an infra
		// problem the client can't act on. Mirrors ExternalPrincipalExchange.
		if errors.Is(err, sql.ErrNoRows) {
			return nil, oauthBadRequestCause("invalid_request", fmt.Sprintf("application_id %s not found or access denied", req.ApplicationID), err)
		}
		return nil, oauthServerError(fmt.Sprintf("failed to look up application_id %s", req.ApplicationID), err)
	}
	if !resolved.Status.IsUsable() {
		return nil, oauthBadRequest("invalid_grant", "identity is suspended or deactivated")
	}
	if resolved.IsExpired() {
		return nil, oauthBadRequest("invalid_grant", "identity_expired")
	}
	return resolved, nil
}

// extractMappedClaimString reads a single-level claim by name and coerces it
// to string. Returns ok=false when the path is empty (no mapping configured)
// or the upstream value is not stringifiable. Numeric claims are accepted
// because some IdPs (Entra) emit numeric subject identifiers.
func extractMappedClaimString(claims map[string]any, path string) (string, bool) {
	if path == "" {
		return "", false
	}
	v, ok := claims[path]
	if !ok {
		return "", false
	}
	switch tv := v.(type) {
	case string:
		return tv, true
	case float64:
		// %v / %g switch to scientific notation for large floats
		// (1.23e+18), which would silently corrupt large numeric subject
		// identifiers. FormatFloat with 'f' keeps a plain decimal. Note
		// that float64 still loses integer precision past 2^53; an IdP
		// that mints subjects above that range is the one violating the
		// JWT/JSON contract — we just don't add a second bug on top.
		return strconv.FormatFloat(tv, 'f', -1, 64), true
	case int64:
		return strconv.FormatInt(tv, 10), true
	case int:
		return strconv.Itoa(tv), true
	case json.Number:
		// Present when the upstream claims were decoded with UseNumber();
		// preserves the exact textual form without float rounding.
		return tv.String(), true
	}
	return "", false
}

// refuseWorkloadSubject rejects a subject_token that names a workload rather
// than a person. This grant mints with the mapped user_id as the subject, so the
// token carries principal_type=user, which resource servers read as "a person
// authorized this chain". A configured issuer can also sign tokens for machines,
// and exchanged here one would pass any check that requires a human behind the
// chain. Workloads authenticate as clients instead (RFC 7523 §2.2), which mints
// a workload principal.
//
// The issuer's kind (person) is checked first; this also refuses the
// well-known workload shapes a person issuer can still sign (ADR 0042 D3a
// rule 3): an Entra app-only token (idtyp=app), a Kubernetes service-account
// subject, and a SPIFFE ID. Both `sub` and the mapped user_id are checked,
// since the mapping may point at a claim other than `sub`.
func refuseWorkloadSubject(claims map[string]any, userID string) error {
	if idtyp, _ := claims["idtyp"].(string); strings.EqualFold(idtyp, "app") {
		return oauthBadRequest(oautherror.InvalidGrant, "the subject is an app-only token (idtyp=app); this grant accepts person tokens only")
	}
	sub, _ := claims["sub"].(string)
	for _, id := range []string{sub, userID} {
		if strings.HasPrefix(id, "repo:") {
			return oauthBadRequest(oautherror.InvalidGrant, "the subject is a GitHub Actions workflow; this grant accepts person tokens only")
		}
		if strings.HasPrefix(id, "system:serviceaccount:") {
			return oauthBadRequest(oautherror.InvalidGrant, "the subject is a Kubernetes service account; this grant accepts person tokens only")
		}
		if len(id) >= len("spiffe://") && strings.EqualFold(id[:len("spiffe://")], "spiffe://") {
			return oauthBadRequest(oautherror.InvalidGrant, "the subject is a SPIFFE ID; this grant accepts person tokens only")
		}
	}
	return nil
}

// extractMappedClaimStrings reads a claim that may be either a space-delimited
// string (the standard `scope` shape, RFC 8693) or a JSON array (the shape some
// IdPs emit for multi-valued claims like groups / privilege_scope). Returns
// ok=false when the path is empty (no mapping configured) or the claim is
// absent; an empty/whitespace-only value yields (nil-or-empty, true). Each
// element is coerced via extractMappedClaimString's single-value rules so
// numeric entries are stringified consistently with the rest of the mapping
// surface.
func extractMappedClaimStrings(claims map[string]any, path string) ([]string, bool) {
	if path == "" {
		return nil, false
	}
	v, ok := claims[path]
	if !ok {
		return nil, false
	}
	switch tv := v.(type) {
	case string:
		// Space-delimited (scope-style). strings.Fields drops empties.
		return parseScopeString(tv), true
	case []string:
		return tv, true
	case []any:
		out := make([]string, 0, len(tv))
		for _, e := range tv {
			if s, ok := extractMappedClaimString(map[string]any{"_": e}, "_"); ok {
				out = append(out, s)
			}
		}
		return out, true
	}
	return nil, false
}

// extractResourceClaim reads the ID-JAG `resource` claim, which per RFC 8707 is
// EITHER a single resource URI (string) OR an array of them. Unlike a scope
// claim, a string value is a SINGLE resource — it is NOT space-delimited — so it
// is taken atomically rather than split on whitespace (a resource URI may
// legitimately contain encoded content; splitting it would forge bogus
// audiences). Returns ok=false when the claim is absent; blank entries dropped.
func extractResourceClaim(claims map[string]any) ([]string, bool) {
	v, ok := claims["resource"]
	if !ok {
		return nil, false
	}
	switch tv := v.(type) {
	case string:
		if s := strings.TrimSpace(tv); s != "" {
			return []string{s}, true
		}
		return nil, true
	case []string:
		return tv, true
	case []any:
		out := make([]string, 0, len(tv))
		for _, e := range tv {
			if s, ok := extractMappedClaimString(map[string]any{"_": e}, "_"); ok && s != "" {
				out = append(out, s)
			}
		}
		return out, true
	}
	return nil, false
}

// checkExternalIDTokenAlg enforces the JWT-SVID §3 asymmetric allow-list
// (via jwtalg.Validate — also rejects alg=none and HS*) and then narrows
// further if the deployer configured a per-issuer allow-list. Runs before
// any signature work so a bad alg dies up front.
func checkExternalIDTokenAlg(tokenStr string, allowed []string) error {
	if err := jwtalg.Validate(tokenStr); err != nil {
		return err
	}
	if len(allowed) == 0 {
		return nil
	}
	alg := readJWSAlg(tokenStr)
	for _, a := range allowed {
		if a == alg {
			return nil
		}
	}
	return fmt.Errorf("alg %q not in issuer allow-list %v", alg, allowed)
}

// extractJWSKeyID reads kid from a JWT protected header without verifying.
// Returns "" if the header is unreadable. Used to drive a one-shot JWKS
// refresh after a verification failure that might be caused by upstream key
// rotation.
func extractJWSKeyID(tokenStr string) string {
	hdr, ok := decodeJWTHeader(tokenStr)
	if !ok {
		return ""
	}
	return hdr.Kid
}

// readJWSAlg returns the alg header value or "" when the header is
// unreadable. Used by the per-issuer allow-list comparison; jwtalg.Validate
// already guarantees alg is present and asymmetric by the time we get here.
func readJWSAlg(tokenStr string) string {
	hdr, ok := decodeJWTHeader(tokenStr)
	if !ok {
		return ""
	}
	return hdr.Alg
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// tokenClaimsAsMap materializes every claim on a v4 jwt.Token into a plain
// map[string]any. v4 dropped AsMap, so we iterate Claims() (an iter.Seq2).
// Used for claim-mapping lookups and propagation passes.
func tokenClaimsAsMap(t jwt.Token) map[string]any {
	out := make(map[string]any, len(t.Keys()))
	for k, v := range t.Claims() {
		out[k] = v
	}
	return out
}

// decodeJWTHeader base64url-decodes the protected header of a compact JWS
// without doing any signature work. Mirrors the technique used in
// internal/jwtalg so we stay independent of the jwx major version.
func decodeJWTHeader(tokenStr string) (jwtHeader, bool) {
	header, _, found := strings.Cut(tokenStr, ".")
	if !found || header == "" {
		return jwtHeader{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		return jwtHeader{}, false
	}
	var hdr jwtHeader
	if err := json.Unmarshal(raw, &hdr); err != nil {
		return jwtHeader{}, false
	}
	return hdr, true
}
