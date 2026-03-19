package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/signing"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
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
}

// NewCredentialService creates a new CredentialService.
func NewCredentialService(
	repo *postgres.CredentialRepository,
	jwksSvc *signing.JWKSService,
	policySvc *CredentialPolicyService,
	attestationRepo *postgres.AttestationRepository,
	issuer string,
	defaultTTL, maxTTL int,
) *CredentialService {
	return &CredentialService{
		repo:            repo,
		jwksSvc:         jwksSvc,
		policySvc:       policySvc,
		attestationRepo: attestationRepo,
		issuer:          issuer,
		defaultTTL:      defaultTTL,
		maxTTL:          maxTTL,
	}
}

// IssueRequest holds parameters for credential issuance.
// If Scopes is non-empty, they are validated against the identity's AllowedScopes.
// TTL defaults to the service default and is capped at MaxTTL.
type IssueRequest struct {
	Identity           *domain.Identity
	CredentialPolicyID string // From the API key, not the identity.
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
	// SubjectOverride, when non-empty, replaces the default WIMSE URI as the JWT "sub" claim.
	// Used for external principal exchange (sub = external user ID) and authorization_code
	// (sub = authenticated user ID). For NHI grants, leave empty to use the WIMSE URI.
	SubjectOverride string
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
}

// ErrScopesNotAllowed is returned when one or more requested scopes are not in the identity's AllowedScopes list.
var ErrScopesNotAllowed = fmt.Errorf("one or more requested scopes are not permitted for this identity")

// IssueCredential issues a short-lived JWT for an identity.
func (s *CredentialService) IssueCredential(ctx context.Context, req IssueRequest) (*domain.AccessToken, *domain.IssuedCredential, error) {
	ttl := req.TTL
	if ttl <= 0 {
		ttl = s.defaultTTL
	}
	if ttl > s.maxTTL {
		ttl = s.maxTTL
	}
	if req.GrantType == "" {
		req.GrantType = domain.GrantTypeClientCredentials
	}

	// Enforce allowed_scopes: if the identity has a non-empty allowed list, requested scopes must be a subset.
	if len(req.Identity.AllowedScopes) > 0 && len(req.Scopes) > 0 {
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

	// Enforce credential policy (all six constraints) if one is assigned to the key.
	if req.CredentialPolicyID != "" && s.policySvc != nil {
		policy, err := s.policySvc.GetPolicy(ctx, req.CredentialPolicyID, req.Identity.AccountID, req.Identity.ProjectID)
		if err != nil {
			return nil, nil, fmt.Errorf("credential policy %s not found: %w", req.CredentialPolicyID, err)
		}

		// Look up the identity's highest verified attestation level for check #5.
		var attestationLevel string
		if s.attestationRepo != nil {
			attestationLevel, _ = s.attestationRepo.GetHighestVerifiedLevel(ctx, req.Identity.ID)
		}

		if err := s.policySvc.EnforcePolicy(ctx, policy, EnforcePolicyRequest{
			TTL:              ttl,
			GrantType:        req.GrantType,
			Scopes:           req.Scopes,
			TrustLevel:       req.Identity.TrustLevel,
			AttestationLevel: attestationLevel,
			DelegationDepth:  req.DelegationDepth,
		}); err != nil {
			log.Warn().
				Err(err).
				Str("identity_id", req.Identity.ID).
				Str("policy_id", req.CredentialPolicyID).
				Msg("Credential policy enforcement denied issuance")
			return nil, nil, err
		}
	}

	now := time.Now()
	expiresAt := now.Add(time.Duration(ttl) * time.Second)
	jti := uuid.New().String()

	// Build JWT
	token := jwt.New()
	_ = token.Set(jwt.IssuerKey, s.issuer)
	sub := req.Identity.WIMSEURI
	if req.SubjectOverride != "" {
		sub = req.SubjectOverride
	}
	_ = token.Set(jwt.SubjectKey, sub)
	_ = token.Set(jwt.IssuedAtKey, now)
	_ = token.Set(jwt.ExpirationKey, expiresAt)
	_ = token.Set(jwt.JwtIDKey, jti)
	_ = token.Set("account_id", req.Identity.AccountID)
	_ = token.Set("project_id", req.Identity.ProjectID)
	_ = token.Set("grant_type", string(req.GrantType))

	// Identity claims.
	_ = token.Set("external_id", req.Identity.ExternalID)
	_ = token.Set("identity_type", string(req.Identity.IdentityType))
	_ = token.Set("sub_type", string(req.Identity.SubType))
	_ = token.Set("trust_level", string(req.Identity.TrustLevel))
	_ = token.Set("status", string(req.Identity.Status))

	// Owner — the user who registered/owns this identity. Distinct from:
	//   - sub (the principal itself)
	//   - act.sub (the end user the principal is acting on behalf of)
	if req.Identity.OwnerUserID != "" {
		_ = token.Set("owner_user_id", req.Identity.OwnerUserID)
	}

	if req.DelegationDepth > 0 {
		_ = token.Set("delegation_depth", req.DelegationDepth)
	}

	// Identity metadata — embedded so downstream services can
	// make identity-aware decisions without calling back to ZeroID.
	if req.Identity.Name != "" {
		_ = token.Set("name", req.Identity.Name)
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

	if len(req.Audience) > 0 {
		_ = token.Set(jwt.AudienceKey, req.Audience)
	}
	if len(req.Scopes) > 0 {
		_ = token.Set("scopes", req.Scopes)
	}
	// Generic claims for RS256 tokens (api_key grant).
	if req.ApplicationID != "" {
		_ = token.Set("application_id", req.ApplicationID)
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

	// RFC 8693 "act" claim — two use cases:
	//   1. NHI delegation: orchestrator delegates to sub-agent. act.sub = orchestrator WIMSE URI.
	//   2. User context: NHI acts on behalf of an end user. act.sub = user ID.
	// These are mutually exclusive per token — a delegated token already has act from the orchestrator.
	if req.DelegatedBy != "" {
		_ = token.Set("act", map[string]string{"sub": req.DelegatedBy})
	} else if req.ActingUserID != "" {
		_ = token.Set("act", map[string]string{"sub": req.ActingUserID})
	}

	// Sign: RS256 for api_key grant (compatible), ES256 for all agent/NHI flows.
	// kid is included in the JWS header so verifiers can select the correct key from JWKS.
	var signed []byte
	var signErr error
	if req.UseRS256 && s.jwksSvc.HasRSAKeys() {
		hdrs := jws.NewHeaders()
		_ = hdrs.Set(jws.KeyIDKey, s.jwksSvc.RSAKeyID())
		signed, signErr = jwt.Sign(token, jwt.WithKey(jwa.RS256, s.jwksSvc.RSAPrivateKey(), jws.WithProtectedHeaders(hdrs)))
	} else {
		hdrs := jws.NewHeaders()
		_ = hdrs.Set(jws.KeyIDKey, s.jwksSvc.KeyID())
		signed, signErr = jwt.Sign(token, jwt.WithKey(jwa.ES256, s.jwksSvc.PrivateKey(), jws.WithProtectedHeaders(hdrs)))
	}
	if signErr != nil {
		return nil, nil, fmt.Errorf("failed to sign JWT: %w", signErr)
	}

	// Persist credential record
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
	}

	if err := s.repo.Create(ctx, cred); err != nil {
		return nil, nil, fmt.Errorf("failed to persist credential: %w", err)
	}

	log.Info().
		Str("jti", jti).
		Str("identity_id", req.Identity.ID).
		Int("ttl_seconds", ttl).
		Msg("Credential issued")

	accessToken := &domain.AccessToken{
		AccessToken: string(signed),
		TokenType:   "Bearer",
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

// RevokeCredential revokes a credential by ID.
func (s *CredentialService) RevokeCredential(ctx context.Context, id, accountID, projectID, reason string) error {
	if reason == "" {
		reason = "manual_revocation"
	}
	return s.repo.Revoke(ctx, id, accountID, projectID, reason)
}

// RotateCredential revokes an existing credential and immediately issues a new one for the same identity.
// The new credential inherits the scopes and TTL of the old one unless overridden.
func (s *CredentialService) RotateCredential(ctx context.Context, credID, accountID, projectID string, identity *domain.Identity) (*domain.AccessToken, *domain.IssuedCredential, error) {
	old, err := s.repo.GetByID(ctx, credID, accountID, projectID)
	if err != nil {
		return nil, nil, fmt.Errorf("credential not found: %w", err)
	}
	if old.IsRevoked {
		return nil, nil, fmt.Errorf("credential is already revoked")
	}

	// Revoke the old credential.
	if err := s.repo.Revoke(ctx, credID, accountID, projectID, "rotated"); err != nil {
		return nil, nil, fmt.Errorf("failed to revoke old credential during rotation: %w", err)
	}

	// Issue a new one with the same parameters.
	return s.IssueCredential(ctx, IssueRequest{
		Identity:  identity,
		Scopes:    old.Scopes,
		TTL:       old.TTLSeconds,
		GrantType: old.GrantType,
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
