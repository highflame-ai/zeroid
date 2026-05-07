package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/jwtalg"
)

// SubjectTokenTypeIDToken is the RFC 8693 subject_token_type for an OIDC ID
// token. ZeroID dispatches token-exchange requests carrying this type to the
// direct-federation path (issue #88) instead of the broker path.
const SubjectTokenTypeIDToken = "urn:ietf:params:oauth:token-type:id_token"

// ErrUnknownExternalIssuer is returned when a token-exchange request carries
// an upstream `iss` that is not in the deployer-configured external_issuers
// allowlist. Wrapped onto the *OAuthError so callers can branch with
// errors.Is while the handler still maps the OAuth error code via errors.As.
//
// We classify this as `invalid_request` (RFC 6749 §5.2) rather than
// `invalid_grant`: the token may be perfectly valid against its real issuer;
// the failure is that the deployer has not configured this IdP. Per the RFC,
// `invalid_grant` covers credentials that "are invalid, expired, revoked"
// against a trust config the server does have — not credentials whose issuer
// the server has never been told to trust.
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
	if s.externalIssuerRegistry == nil || !s.externalIssuerRegistry.HasAny() {
		return nil, oauthBadRequest("invalid_request", "no external issuers are configured for direct OIDC federation")
	}
	if req.SubjectToken == "" {
		return nil, oauthBadRequest("invalid_request", "subject_token is required")
	}
	if req.AccountID == "" || req.ProjectID == "" {
		return nil, oauthBadRequest("invalid_request", "account_id and project_id are required for external id_token exchange")
	}

	// Peek at the token to extract iss without validating signatures yet —
	// we need iss to look up which IdP's JWKS to verify against.
	peeked, err := jwt.ParseInsecure([]byte(req.SubjectToken))
	if err != nil {
		return nil, oauthBadRequestCause("invalid_grant", "subject_token is malformed", err)
	}
	upstreamIss, ok := peeked.Issuer()
	if !ok || upstreamIss == "" {
		return nil, oauthBadRequest("invalid_grant", "subject_token missing iss claim")
	}

	entry := s.externalIssuerRegistry.Lookup(upstreamIss)
	if entry == nil {
		// Unknown issuer — invalid_request, not invalid_grant: the deployer
		// has not configured this IdP, which is a configuration mismatch
		// rather than a credential failure. Wrap ErrUnknownExternalIssuer as
		// the cause so callers can errors.Is while the handler still picks up
		// the OAuth error code via errors.As on *OAuthError.
		return nil, oauthBadRequestCause(
			"invalid_request",
			fmt.Sprintf("issuer %s is not a configured external issuer", upstreamIss),
			fmt.Errorf("%w: %s", ErrUnknownExternalIssuer, upstreamIss),
		)
	}
	cfg := entry.Config

	if !cfg.AccountAllowed(req.AccountID) {
		return nil, oauthBadRequest("invalid_request", fmt.Sprintf("account %s is not allowed to use issuer %s", req.AccountID, upstreamIss))
	}

	// Algorithm allowlist gate. Read the JWS header before signature
	// verification — defense-in-depth against alg confusion. Any alg outside
	// the configured set (or outside the small whitelist of secure asymmetric
	// algs we actually support) is rejected.
	if err := checkExternalIDTokenAlg(req.SubjectToken, cfg.Algorithms); err != nil {
		return nil, oauthBadRequestCause("invalid_grant", "subject_token uses a disallowed algorithm", err)
	}

	// Verify signature, exp, nbf, iss, and aud against the configured IdP
	// in one Parse call. WithKeySet picks the right key by kid+alg from
	// the JWKS we cache for this issuer.
	keySet := entry.JWKS.KeySet()
	if keySet == nil || keySet.Len() == 0 {
		return nil, oauthServerError(fmt.Sprintf("JWKS for issuer %s is empty", upstreamIss), nil)
	}
	verified, err := jwt.Parse([]byte(req.SubjectToken),
		jwt.WithKeySet(keySet),
		jwt.WithValidate(true),
		jwt.WithIssuer(upstreamIss),
		jwt.WithAudience(cfg.Audience),
	)
	if err != nil {
		// On unknown kid, refresh the JWKS once and retry — handles upstream
		// key rotation without requiring a server restart.
		if kid := extractJWSKeyID(req.SubjectToken); kid != "" && entry.JWKS.RefreshIfMissing(ctx, kid) {
			keySet = entry.JWKS.KeySet()
			verified, err = jwt.Parse([]byte(req.SubjectToken),
				jwt.WithKeySet(keySet),
				jwt.WithValidate(true),
				jwt.WithIssuer(upstreamIss),
				jwt.WithAudience(cfg.Audience),
			)
		}
		if err != nil {
			return nil, oauthBadRequestCause("invalid_grant", "subject_token verification failed", err)
		}
	}

	// Stale-token cap. exp guards future-side; iat guards past-side. We
	// require iat present and not older than max_token_age — the upstream
	// signed it for a fresh authentication, not a replay from days ago.
	iat, iatPresent := verified.IssuedAt()
	if !iatPresent || iat.IsZero() {
		return nil, oauthBadRequest("invalid_grant", "subject_token missing iat claim")
	}
	if age := time.Since(iat); age > cfg.MaxTokenAge {
		return nil, oauthBadRequest("invalid_grant", fmt.Sprintf("subject_token age %s exceeds max_token_age %s", age.Round(time.Second), cfg.MaxTokenAge))
	}

	// Claim mapping. user_id is required (validated at config load); other
	// mappings are optional. Single-level keys only in v1. v4 dropped AsMap,
	// so iterate Keys()/Get() to materialize a plain map.
	rawClaims := tokenClaimsAsMap(verified)
	userID, ok := extractMappedClaimString(rawClaims, cfg.ClaimMapping["user_id"])
	if !ok || userID == "" {
		return nil, oauthBadRequest("invalid_grant", fmt.Sprintf("subject_token missing claim %q (mapped to user_id)", cfg.ClaimMapping["user_id"]))
	}
	userEmail, _ := extractMappedClaimString(rawClaims, cfg.ClaimMapping["email"])
	userName, _ := extractMappedClaimString(rawClaims, cfg.ClaimMapping["name"])

	// Resolve the application identity if requested. Same IDOR-guarded
	// lookup the broker path uses — falling back to a synthetic service
	// identity when no application_id is provided.
	identity, err := s.resolveExternalPrincipalIdentity(ctx, req)
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
	for _, claim := range cfg.PropagateClaims {
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

	scopes := parseScopeString(req.Scope)
	accessToken, _, err := s.credentialSvc.IssueCredential(ctx, IssueRequest{
		Identity:        identity,
		GrantType:       domain.GrantTypeTokenExchange,
		Scopes:          scopes,
		UseRS256:        true,
		SubjectOverride: userID,
		UserEmail:       userEmail,
		UserName:        userName,
		ApplicationID:   req.ApplicationID,
		TTL:             900, // 15 minutes — same short-lived posture as the broker path
		CustomClaims:    customClaims,
	})
	if err != nil {
		return nil, oauthServerError("failed to issue external id_token exchange token", err)
	}

	accessToken.AccountID = req.AccountID
	accessToken.ProjectID = req.ProjectID
	accessToken.UserID = userID

	log.Info().
		Str("upstream_iss", upstreamIss).
		Str("account_id", req.AccountID).
		Str("project_id", req.ProjectID).
		Str("user_id", userID).
		Msg("external id_token exchange succeeded")

	return accessToken, nil
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
		return nil, oauthBadRequest("invalid_request", fmt.Sprintf("application_id %s not found or access denied", req.ApplicationID))
	}
	if !resolved.Status.IsUsable() {
		return nil, oauthBadRequest("invalid_grant", "identity is suspended or deactivated")
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
	}
	return "", false
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
