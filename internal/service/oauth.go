package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/signing"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// OAuthService handles OAuth2 grant type implementations.
type OAuthService struct {
	credentialSvc   *CredentialService
	identitySvc     *IdentityService
	oauthClientSvc  *OAuthClientService
	apiKeyRepo      *postgres.APIKeyRepository
	jwksSvc         *signing.JWKSService
	refreshTokenSvc *RefreshTokenService
	issuer          string
	wimseDomain     string // configurable WIMSE URI domain (e.g. "zeroid.dev")
	hmacSecret      string // HS256 shared secret for auth code JWT verification
	authCodeIssuer  string // expected issuer in auth code JWTs
	// validClientIDs is the set of recognised static client IDs.
	validClientIDs map[string]bool
	// mcpClientPrefix is the prefix for dynamically registered MCP client IDs.
	mcpClientPrefix string
	// mcpStaticClients lists static client IDs that are MCP clients (short-lived tokens + refresh).
	mcpStaticClients map[string]bool
	// trustedServiceValidator checks if the caller is a trusted service for external principal exchange.
	trustedServiceValidator trustedServiceValidatorFunc
}

// trustedServiceValidatorFunc checks whether the current request comes from a trusted
// internal service that is allowed to perform external principal exchange.
// The public type is zeroid.TrustedServiceValidator (hooks.go).
type trustedServiceValidatorFunc func(ctx context.Context) (serviceName string, err error)

// OAuthServiceConfig holds configuration for the OAuthService.
type OAuthServiceConfig struct {
	Issuer           string
	WIMSEDomain      string
	HMACSecret       string
	AuthCodeIssuer   string
	ValidClientIDs   map[string]bool
	MCPClientPrefix  string
	MCPStaticClients map[string]bool
	// TrustedServiceValidator is called during external principal token exchange
	// to verify the caller is a trusted internal service. If nil, external
	// principal exchange is disabled.
	TrustedServiceValidator trustedServiceValidatorFunc
}

// NewOAuthService creates a new OAuthService.
func NewOAuthService(
	credentialSvc *CredentialService,
	identitySvc *IdentityService,
	oauthClientSvc *OAuthClientService,
	apiKeyRepo *postgres.APIKeyRepository,
	jwksSvc *signing.JWKSService,
	refreshTokenSvc *RefreshTokenService,
	cfg OAuthServiceConfig,
) *OAuthService {
	return &OAuthService{
		credentialSvc:    credentialSvc,
		identitySvc:      identitySvc,
		oauthClientSvc:   oauthClientSvc,
		apiKeyRepo:       apiKeyRepo,
		jwksSvc:          jwksSvc,
		refreshTokenSvc:  refreshTokenSvc,
		issuer:           cfg.Issuer,
		wimseDomain:      cfg.WIMSEDomain,
		hmacSecret:       cfg.HMACSecret,
		authCodeIssuer:   cfg.AuthCodeIssuer,
		validClientIDs:   cfg.ValidClientIDs,
		mcpClientPrefix:  cfg.MCPClientPrefix,
		mcpStaticClients:       cfg.MCPStaticClients,
		trustedServiceValidator: cfg.TrustedServiceValidator,
	}
}

// SetTrustedServiceValidator sets the validator for external principal token exchange.
// Can be called after construction to override the config-provided validator.
func (s *OAuthService) SetTrustedServiceValidator(v trustedServiceValidatorFunc) {
	s.trustedServiceValidator = v
}

// TokenRequest represents an OAuth2 token request.
// Tenant (account_id, project_id) is required for client_credentials grant
// (multi-tenant client_id lookup) and optional for other grants where tenant
// is derived from the credential material (WIMSE URI, auth code JWT, etc.).
type TokenRequest struct {
	GrantType    string
	ClientID     string
	ClientSecret string
	Scope        string
	AccountID    string // tenant — required for client_credentials and external principal exchange
	ProjectID    string // tenant — required for client_credentials and external principal exchange
	Subject      string // assertion JWT for jwt_bearer grant
	APIKey       string // zid_sk_* API key for api_key grant
	// token_exchange (RFC 8693) fields:
	SubjectToken     string // the subject token being exchanged
	SubjectTokenType string // urn:ietf:params:oauth:token-type:access_token or jwt
	ActorToken       string // the sub-agent's JWT assertion (NHI delegation only)
	// External principal exchange fields (RFC 8693 with subject_token_type=jwt):
	// Populated by the trusted service (e.g. admin) that already authenticated the user.
	UserID        string // external user ID (e.g. Clerk user ID)
	UserEmail     string // user email
	UserName      string // user display name
	ApplicationID string // optional application scope
	// authorization_code grant fields:
	Code         string // HS256 auth code JWT
	CodeVerifier string // PKCE S256 code verifier
	RedirectURI  string // OAuth redirect URI
	// refresh_token grant fields:
	RefreshTokenStr string // raw refresh token (zid_rt_*)
	// TrustedService is true when the caller has been authenticated as a trusted
	// internal service (via AdminAuth middleware). Required for external principal exchange.
	TrustedService bool
}

// Token handles the /oauth2/token endpoint dispatch.
func (s *OAuthService) Token(ctx context.Context, req TokenRequest) (*domain.AccessToken, error) {
	switch req.GrantType {
	case "client_credentials":
		return s.clientCredentials(ctx, req)
	case "urn:ietf:params:oauth:grant-type:jwt-bearer":
		return s.jwtBearer(ctx, req)
	case "urn:ietf:params:oauth:grant-type:token-exchange":
		return s.tokenExchange(ctx, req)
	case "api_key":
		return s.apiKeyGrant(ctx, req)
	case "authorization_code":
		return s.authorizationCode(ctx, req)
	case "refresh_token":
		return s.refreshToken(ctx, req)
	default:
		return nil, fmt.Errorf("unsupported grant type: %s", req.GrantType)
	}
}

func (s *OAuthService) clientCredentials(ctx context.Context, req TokenRequest) (*domain.AccessToken, error) {
	if req.AccountID == "" || req.ProjectID == "" {
		return nil, fmt.Errorf("account_id and project_id are required for client_credentials grant")
	}

	// Validate client credentials against the oauth_clients table, scoped to tenant.
	client, err := s.oauthClientSvc.VerifyClientSecret(ctx, req.ClientID, req.ClientSecret, req.AccountID, req.ProjectID)
	if err != nil {
		if errors.Is(err, ErrOAuthClientNotFound) || errors.Is(err, ErrInvalidClientSecret) {
			return nil, fmt.Errorf("invalid client credentials")
		}
		return nil, fmt.Errorf("failed to verify client: %w", err)
	}

	// Ensure client_credentials grant is permitted.
	allowed := false
	for _, gt := range client.GrantTypes {
		if gt == "client_credentials" {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, fmt.Errorf("client not authorized for client_credentials grant")
	}

	// Parse and intersect requested scopes with the client's allowed scopes.
	scopes := intersectScopes(parseScopeString(req.Scope), client.Scopes)

	// Resolve the identity for this client (external_id == client_id within the tenant).
	// Tenant is derived from the client record — not from caller-supplied headers.
	identity, err := s.identitySvc.repo.GetByExternalID(ctx, req.ClientID, client.AccountID, client.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("no identity found for client_id %s: %w", req.ClientID, err)
	}

	accessToken, _, err := s.credentialSvc.IssueCredential(ctx, IssueRequest{
		Identity:  identity,
		Scopes:    scopes,
		GrantType: domain.GrantTypeClientCredentials,
	})
	if err != nil {
		return nil, err
	}

	return accessToken, nil
}

// jwtBearer implements RFC 7523: the agent presents a self-signed JWT assertion.
// The assertion is validated against the identity's registered public_key_pem.
// iss must equal the agent's WIMSE URI; aud must equal the issuer URL.
func (s *OAuthService) jwtBearer(ctx context.Context, req TokenRequest) (*domain.AccessToken, error) {
	if req.Subject == "" {
		return nil, fmt.Errorf("subject (assertion JWT) is required for jwt_bearer grant")
	}

	// Peek at the assertion without signature verification to extract the iss claim (WIMSE URI).
	peeked, err := jwt.ParseInsecure([]byte(req.Subject))
	if err != nil {
		return nil, fmt.Errorf("invalid_grant: assertion JWT is malformed")
	}

	wimseURI := peeked.Issuer()
	if wimseURI == "" {
		return nil, fmt.Errorf("invalid_grant: assertion JWT missing iss claim")
	}

	// Parse tenant from the WIMSE URI itself — no caller-supplied tenant headers needed.
	accountID, projectID, err := s.parseWIMSEURI(wimseURI)
	if err != nil {
		return nil, fmt.Errorf("invalid_grant: %w", err)
	}

	// Resolve the identity by WIMSE URI, scoped to the tenant extracted above.
	identity, err := s.identitySvc.repo.GetByWIMSEURI(ctx, wimseURI, accountID, projectID)
	if err != nil {
		return nil, fmt.Errorf("invalid_grant: unknown issuer %s", wimseURI)
	}
	if !identity.Status.IsUsable() {
		return nil, fmt.Errorf("invalid_grant: identity is inactive")
	}
	if identity.PublicKeyPEM == "" {
		return nil, fmt.Errorf("invalid_grant: no public key registered for identity %s — register a key before using jwt_bearer", identity.ID)
	}

	agentPubKey, err := parseECPublicKeyPEM(identity.PublicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("invalid_grant: registered public key is invalid: %w", err)
	}

	// Fully validate the assertion JWT against the agent's registered public key.
	assertionToken, err := jwt.Parse([]byte(req.Subject),
		jwt.WithKey(jwa.ES256, agentPubKey),
		jwt.WithValidate(true),
		jwt.WithAudience(s.issuer),
	)
	if err != nil {
		return nil, fmt.Errorf("invalid_grant: assertion JWT validation failed: %w", err)
	}

	// iss must match the identity's WIMSE URI.
	if assertionToken.Issuer() != identity.WIMSEURI {
		return nil, fmt.Errorf("invalid_grant: iss claim does not match identity WIMSE URI")
	}

	scopes := intersectScopes(parseScopeString(req.Scope), identity.AllowedScopes)

	accessToken, _, err := s.credentialSvc.IssueCredential(ctx, IssueRequest{
		Identity:  identity,
		Scopes:    scopes,
		GrantType: domain.GrantTypeJWTBearer,
	})
	if err != nil {
		return nil, err
	}

	return accessToken, nil
}

// tokenExchange implements RFC 8693 for agent-to-agent delegation.
//
// An orchestrator agent delegates a downscoped credential to a sub-agent.
// The orchestrator proves its current authority via subject_token (its active JWT).
// The sub-agent proves its identity via actor_token (a self-signed JWT assertion,
// same mechanism as jwt_bearer). The issued credential carries:
//
//	sub  = sub-agent's WIMSE URI  (who holds/uses this token; authz checks sub-agent's policies)
//	act  = {"sub": orchestrator's WIMSE URI}  (RFC 8693 section 4.1 delegation chain for audit)
//	scopes = requested intersection of orchestrator's granted scopes intersection of sub-agent's allowed_scopes
//
// Both parties must belong to the same tenant. The sub-agent must have a registered
// public key (same requirement as jwt_bearer).
func (s *OAuthService) tokenExchange(ctx context.Context, req TokenRequest) (*domain.AccessToken, error) {
	if req.SubjectToken == "" {
		return nil, fmt.Errorf("invalid_request: subject_token is required for token_exchange grant")
	}

	// RFC 8693 defines two exchange modes:
	//   1. NHI delegation: subject_token (orchestrator) + actor_token (sub-agent) → delegated token
	//   2. External principal exchange: subject_token (external JWT) from a trusted service → zeroid token
	// Mode is determined by the presence of actor_token.
	if req.ActorToken == "" {
		return s.externalPrincipalExchange(ctx, req)
	}

	// Step 1: Verify the subject_token (orchestrator's active access token).
	// Accept both ES256 and RS256 tokens — the library matches kid + alg from the JWKS.
	subjectParsed, err := s.parseToken(req.SubjectToken, true)
	if err != nil {
		return nil, fmt.Errorf("invalid_grant: subject_token validation failed: %w", err)
	}

	subjectJTI := subjectParsed.JwtID()
	if subjectJTI == "" {
		return nil, fmt.Errorf("invalid_grant: subject_token missing jti claim")
	}

	// Check that the credential has not been revoked.
	subjectCred, active, err := s.credentialSvc.IntrospectToken(ctx, subjectJTI)
	if err != nil || subjectCred == nil || !active {
		return nil, fmt.Errorf("invalid_grant: subject_token is inactive or has been revoked")
	}

	// Step 2: Verify the actor_token (sub-agent's signed JWT assertion).
	actorPeeked, err := jwt.ParseInsecure([]byte(req.ActorToken))
	if err != nil {
		return nil, fmt.Errorf("invalid_grant: actor_token is malformed")
	}

	actorWIMSEURI := actorPeeked.Issuer()
	if actorWIMSEURI == "" {
		return nil, fmt.Errorf("invalid_grant: actor_token missing iss claim")
	}

	// Derive the tenant from the actor's WIMSE URI.
	accountID, projectID, err := s.parseWIMSEURI(actorWIMSEURI)
	if err != nil {
		return nil, fmt.Errorf("invalid_grant: actor_token iss is not a valid WIMSE URI: %w", err)
	}

	// Subject and actor must belong to the same tenant.
	if accountID != subjectCred.AccountID || projectID != subjectCred.ProjectID {
		return nil, fmt.Errorf("invalid_grant: subject_token and actor_token must belong to the same tenant")
	}

	// Look up the actor (sub-agent) identity.
	actorIdentity, err := s.identitySvc.repo.GetByWIMSEURI(ctx, actorWIMSEURI, accountID, projectID)
	if err != nil {
		return nil, fmt.Errorf("invalid_grant: unknown actor identity %s", actorWIMSEURI)
	}
	if !actorIdentity.Status.IsUsable() {
		return nil, fmt.Errorf("invalid_grant: actor identity is inactive")
	}
	if actorIdentity.PublicKeyPEM == "" {
		return nil, fmt.Errorf("invalid_grant: no public key registered for actor identity %s — register a key before using token_exchange", actorIdentity.ID)
	}

	// Fully validate the actor_token against the sub-agent's registered public key.
	actorPubKey, err := parseECPublicKeyPEM(actorIdentity.PublicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("invalid_grant: actor's registered public key is invalid: %w", err)
	}

	validatedActorToken, err := jwt.Parse([]byte(req.ActorToken),
		jwt.WithKey(jwa.ES256, actorPubKey),
		jwt.WithValidate(true),
		jwt.WithAudience(s.issuer),
	)
	if err != nil {
		return nil, fmt.Errorf("invalid_grant: actor_token validation failed: %w", err)
	}
	if validatedActorToken.Issuer() != actorIdentity.WIMSEURI {
		return nil, fmt.Errorf("invalid_grant: actor_token iss does not match actor identity WIMSE URI")
	}

	// Step 3: Compute the granted scopes.
	requestedScopes := parseScopeString(req.Scope)
	orchSet := make(map[string]bool, len(subjectCred.Scopes))
	for _, s := range subjectCred.Scopes {
		orchSet[s] = true
	}
	actorSet := make(map[string]bool, len(actorIdentity.AllowedScopes))
	for _, s := range actorIdentity.AllowedScopes {
		actorSet[s] = true
	}
	var scopes []string
	for _, s := range requestedScopes {
		if orchSet[s] && actorSet[s] {
			scopes = append(scopes, s)
		}
	}
	if len(scopes) == 0 {
		return nil, fmt.Errorf("invalid_scope: requested scopes are not available for delegation")
	}

	// Step 4: Compute delegation depth (increment from orchestrator's depth).
	var parentDepth int
	if v, ok := subjectParsed.Get("delegation_depth"); ok {
		if d, ok := v.(float64); ok {
			parentDepth = int(d)
		}
	}

	// Step 5: Issue a delegated credential for the sub-agent.
	accessToken, _, err := s.credentialSvc.IssueCredential(ctx, IssueRequest{
		Identity:        actorIdentity,
		Scopes:          scopes,
		GrantType:       domain.GrantTypeTokenExchange,
		DelegatedBy:     subjectParsed.Subject(),
		ParentJTI:       subjectJTI,
		DelegationDepth: parentDepth + 1,
	})
	if err != nil {
		return nil, err
	}

	return accessToken, nil
}

// externalPrincipalExchange handles RFC 8693 token exchange for externally-authenticated
// principals (e.g. human users authenticated by Clerk, Google, Okta).
//
// A trusted internal service (e.g. an admin gateway) authenticates the external principal,
// resolves tenant context, and calls the token endpoint with:
//
//	grant_type=urn:ietf:params:oauth:grant-type:token-exchange
//	subject_token=<external_jwt>
//	subject_token_type=urn:ietf:params:oauth:token-type:jwt
//	account_id=<resolved_tenant>
//	project_id=<resolved_tenant>
//	user_id=<external_user_id>
//
// ZeroID trusts the caller (verified by TrustedServiceValidator), does not re-verify the
// external JWT (the trusted service already did), and issues a ZeroID-signed RS256 token
// with the external principal's claims embedded.
func (s *OAuthService) externalPrincipalExchange(ctx context.Context, req TokenRequest) (*domain.AccessToken, error) {
	// Step 1: Verify the caller is a trusted internal service.
	if s.trustedServiceValidator == nil {
		return nil, fmt.Errorf("invalid_grant: external principal exchange is not configured")
	}
	serviceName, err := s.trustedServiceValidator(ctx)
	if err != nil {
		return nil, fmt.Errorf("invalid_grant: caller is not a trusted service: %w", err)
	}

	// Step 2: Validate required fields. The trusted service is responsible for
	// authenticating the external principal and resolving tenant context.
	if req.AccountID == "" || req.ProjectID == "" {
		return nil, fmt.Errorf("invalid_request: account_id and project_id are required for external principal exchange")
	}
	if req.UserID == "" {
		return nil, fmt.Errorf("invalid_request: user_id is required for external principal exchange")
	}

	// Step 3: Build a minimal identity for the external principal.
	// External principals are not registered in ZeroID's identity table — they are
	// authenticated by the external IdP and their token is scoped by the trusted service's
	// resolved tenant context.
	identity := &domain.Identity{
		AccountID:    req.AccountID,
		ProjectID:    req.ProjectID,
		IdentityType: domain.IdentityTypeService, // external principal, not a ZeroID NHI
		Status:       domain.IdentityStatusActive,
	}

	// Step 4: Build custom claims for the external principal.
	customClaims := map[string]any{
		"token_exchange": "external_principal",
		"trusted_by":     serviceName,
	}

	// Step 5: Issue an RS256 token. RS256 is used for human/SDK tokens to distinguish
	// them from ES256 NHI tokens in downstream verification.
	scopes := parseScopeString(req.Scope)
	accessToken, _, err := s.credentialSvc.IssueCredential(ctx, IssueRequest{
		Identity:        identity,
		GrantType:       domain.GrantTypeTokenExchange,
		Scopes:          scopes,
		UseRS256:        true,
		SubjectOverride: req.UserID,
		UserEmail:       req.UserEmail,
		UserName:        req.UserName,
		ApplicationID:   req.ApplicationID,
		TTL:             900, // 15 minutes — short-lived for external principals
		CustomClaims:    customClaims,
	})
	if err != nil {
		return nil, fmt.Errorf("issuing external principal token: %w", err)
	}

	accessToken.AccountID = req.AccountID
	accessToken.ProjectID = req.ProjectID
	accessToken.UserID = req.UserID

	return accessToken, nil
}

// apiKeyGrant validates a zid_sk_* API key and issues an RS256 JWT.
// Tenant is derived from the API key record — no caller-supplied headers needed.
func (s *OAuthService) apiKeyGrant(ctx context.Context, req TokenRequest) (*domain.AccessToken, error) {
	if req.APIKey == "" {
		return nil, fmt.Errorf("api_key is required for api_key grant")
	}

	if !s.jwksSvc.HasRSAKeys() {
		return nil, fmt.Errorf("api_key grant requires RSA keys to be configured")
	}

	// Hash the API key with SHA-256 to look up in the database.
	hash := sha256.Sum256([]byte(req.APIKey))
	keyHash := hex.EncodeToString(hash[:])

	sk, err := s.apiKeyRepo.GetByKeyHash(ctx, keyHash)
	if err != nil {
		return nil, fmt.Errorf("invalid api key")
	}

	// Build a synthetic identity for the API key holder.
	// API keys may or may not be linked to an identity.
	var identity *domain.Identity
	if sk.IdentityID != "" {
		// Key is linked to an identity — look up the full record.
		identity, err = s.identitySvc.repo.GetByID(ctx, sk.IdentityID, sk.AccountID, sk.ProjectID)
		if err != nil {
			log.Warn().Str("identity_id", sk.IdentityID).Str("key_id", sk.ID).Msg("API key linked to unknown identity_id, issuing without identity")
			identity = nil
		}
	}

	if identity == nil {
		// No identity — build a minimal one from the API key metadata.
		// ID is left empty so identity_id is stored as NULL in issued_credentials.
		identity = &domain.Identity{
			AccountID: sk.AccountID,
			ProjectID: sk.ProjectID,
			Status:    domain.IdentityStatusActive,
		}
	}

	// Resolve scopes: intersect requested with key's allowed scopes.
	// If the key has no scopes set, fall through to the identity's allowed_scopes
	// per RFC 6749 section 3.3 (server-defined default).
	allowedScopes := sk.Scopes
	if len(allowedScopes) == 0 && identity != nil {
		allowedScopes = identity.AllowedScopes
	}
	scopes := intersectScopes(parseScopeString(req.Scope), allowedScopes)

	accessToken, _, err := s.credentialSvc.IssueCredential(ctx, IssueRequest{
		Identity:           identity,
		CredentialPolicyID: sk.CredentialPolicyID,
		Scopes:             scopes,
		GrantType:          domain.GrantTypeAPIKey,
		UseRS256:           true,
		// sub = WIMSE URI (the identity), not the creator.
		// owner_user_id is set from Identity.OwnerUserID automatically.
		// The creator is the acting user (the developer using the SDK right now).
		ActingUserID: sk.CreatedBy,
	})
	if err != nil {
		return nil, err
	}

	// Populate convenience fields on response so callers don't need to decode the JWT.
	accessToken.AccountID = sk.AccountID
	accessToken.ProjectID = sk.ProjectID
	accessToken.UserID = sk.CreatedBy
	if identity != nil {
		accessToken.ExternalID = identity.ExternalID
	}

	// Update last_used metadata asynchronously (best-effort).
	go func() {
		_ = s.apiKeyRepo.UpdateLastUsed(context.Background(), sk.ID, "")
	}()

	return accessToken, nil
}

// authorizationCode handles the PKCE authorization code grant (RFC 6749 section 4.1).
// Auth codes are HS256 JWTs containing all tenant context.
// MCP clients receive short-lived access tokens + refresh tokens.
// CLI clients receive long-lived access tokens (90 days).
func (s *OAuthService) authorizationCode(ctx context.Context, req TokenRequest) (*domain.AccessToken, error) {
	if req.Code == "" || req.CodeVerifier == "" || req.ClientID == "" || req.RedirectURI == "" {
		return nil, fmt.Errorf("code, code_verifier, client_id, and redirect_uri are required")
	}

	if !s.isValidClientID(req.ClientID) {
		return nil, fmt.Errorf("invalid_client: unknown client_id")
	}

	if s.hmacSecret == "" {
		return nil, fmt.Errorf("authorization_code grant requires HMAC secret to be configured")
	}

	authCode, err := decodeAuthCodeJWT(req.Code, s.hmacSecret, s.authCodeIssuer)
	if err != nil {
		return nil, fmt.Errorf("invalid_grant: %w", err)
	}

	if authCode.ClientID != req.ClientID {
		return nil, fmt.Errorf("invalid_grant: client_id mismatch")
	}

	if normalizeLoopback(authCode.RedirectURI) != normalizeLoopback(req.RedirectURI) {
		return nil, fmt.Errorf("invalid_grant: redirect_uri mismatch")
	}

	if !verifyCodeChallenge(req.CodeVerifier, authCode.CodeChallenge) {
		return nil, fmt.Errorf("invalid_grant: PKCE verification failed")
	}

	isMCP := s.isMCPClient(req.ClientID)
	ttl := 90 * 24 * 3600 // 90 days for CLI clients
	if isMCP {
		ttl = 3600 // 1 hour for MCP clients
	}

	// Auth code JWT is self-contained — tenant context comes from the auth code.
	identity := &domain.Identity{
		AccountID: authCode.AccountID,
		ProjectID: authCode.ProjectID,
		Status:    domain.IdentityStatusActive,
	}

	accessToken, _, err := s.credentialSvc.IssueCredential(ctx, IssueRequest{
		Identity:        identity,
		GrantType:       domain.GrantTypeAuthorizationCode,
		UseRS256:        true,
		SubjectOverride: authCode.UserID,
		ApplicationID:   authCode.ClientID,
		TTL:             ttl,
		Scopes:          authCode.Scopes,
	})
	if err != nil {
		return nil, err
	}

	accessToken.AccountID = authCode.AccountID
	accessToken.ProjectID = authCode.ProjectID
	accessToken.UserID = authCode.UserID

	// Issue refresh token for MCP clients only.
	if isMCP && s.refreshTokenSvc != nil {
		rtResult, rtErr := s.refreshTokenSvc.IssueRefreshToken(ctx, &RefreshTokenParams{
			ClientID:  req.ClientID,
			AccountID: authCode.AccountID,
			ProjectID: authCode.ProjectID,
			UserID:    authCode.UserID,
			Scopes:    strings.Join(authCode.Scopes, " "),
		})
		if rtErr != nil {
			log.Error().Err(rtErr).Msg("Failed to issue refresh token — returning access token only")
		} else {
			accessToken.RefreshToken = rtResult.RawToken
		}
	}

	return accessToken, nil
}

// refreshToken handles the refresh_token grant (RFC 6749 section 6).
// Implements single-use rotation with family-based reuse detection.
func (s *OAuthService) refreshToken(ctx context.Context, req TokenRequest) (*domain.AccessToken, error) {
	if req.RefreshTokenStr == "" || req.ClientID == "" {
		return nil, fmt.Errorf("refresh_token and client_id are required")
	}

	if s.refreshTokenSvc == nil {
		return nil, fmt.Errorf("refresh tokens not configured")
	}

	oldToken, newRT, err := s.refreshTokenSvc.RotateRefreshToken(ctx, req.RefreshTokenStr)
	if err != nil {
		return nil, fmt.Errorf("invalid_grant: %w", err)
	}

	if oldToken.ClientID != req.ClientID {
		return nil, fmt.Errorf("invalid_grant: client_id mismatch")
	}

	identity := &domain.Identity{
		AccountID: oldToken.AccountID,
		ProjectID: oldToken.ProjectID,
		Status:    domain.IdentityStatusActive,
	}

	accessToken, _, err := s.credentialSvc.IssueCredential(ctx, IssueRequest{
		Identity:        identity,
		GrantType:       domain.GrantTypeRefreshToken,
		UseRS256:        true,
		SubjectOverride: oldToken.UserID,
		ApplicationID:   oldToken.ClientID,
		TTL:             3600, // 1 hour
	})
	if err != nil {
		return nil, err
	}

	accessToken.AccountID = oldToken.AccountID
	accessToken.ProjectID = oldToken.ProjectID
	accessToken.UserID = oldToken.UserID
	accessToken.RefreshToken = newRT.RawToken

	return accessToken, nil
}

// parseECPublicKeyPEM parses a PEM-encoded EC public key and validates it is P-256.
// Only P-256 keys are accepted because ZeroID exclusively uses ES256 (RFC 7518 section 3.4).
func parseECPublicKeyPEM(pemStr string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ecKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not an ECDSA public key")
	}
	if ecKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("key must use P-256 curve (got %s)", ecKey.Curve.Params().Name)
	}
	return ecKey, nil
}

// Introspect implements RFC 7662 token introspection.
// Returns {active:false} for any invalid/expired/revoked/unknown token — never an error.
func (s *OAuthService) Introspect(ctx context.Context, tokenStr string) (map[string]any, error) {
	inactive := map[string]any{"active": false}

	parsed, err := s.parseToken(tokenStr, true)
	if err != nil {
		return inactive, nil // malformed, expired, or invalid — return active:false, no error
	}

	jti := parsed.JwtID()
	if jti == "" {
		return inactive, nil
	}

	cred, active, err := s.credentialSvc.IntrospectToken(ctx, jti)
	if err != nil || cred == nil {
		return inactive, nil
	}
	if !active {
		return inactive, nil
	}

	scopes := cred.Scopes

	result := map[string]any{
		"active":     true,
		"sub":        parsed.Subject(),
		"iss":        parsed.Issuer(),
		"jti":        jti,
		"iat":        parsed.IssuedAt().Unix(),
		"exp":        parsed.Expiration().Unix(),
		"scope":      strings.Join(scopes, " "),
		"account_id": cred.AccountID,
		"project_id": cred.ProjectID,
	}

	if v, ok := parsed.Get("agent_id"); ok {
		result["agent_id"] = v
	}
	if v, ok := parsed.Get("trust_level"); ok {
		result["trust_level"] = v
	}
	if v, ok := parsed.Get("identity_type"); ok {
		result["identity_type"] = v
	}
	if v, ok := parsed.Get("external_id"); ok {
		result["external_id"] = v
	}
	if v, ok := parsed.Get("delegation_depth"); ok {
		result["delegation_depth"] = v
	}
	if v, ok := parsed.Get("act"); ok {
		result["act"] = v
	}

	return result, nil
}

// Revoke implements RFC 7009 token revocation.
// The caller need only present the token — tenant is derived from the credential record.
// Per RFC 7009 section 2.2, always returns nil (success) even for unknown or already-revoked tokens.
func (s *OAuthService) Revoke(ctx context.Context, tokenStr string) error {
	// Parse without full validation — token may already be expired but still revocable.
	parsed, err := s.parseToken(tokenStr, false)
	if err != nil {
		return nil // malformed or invalid — treat as not found per RFC 7009 section 2.2
	}

	jti := parsed.JwtID()
	if jti == "" {
		return nil
	}

	cred, err := s.credentialSvc.repo.GetByJTI(ctx, jti)
	if err != nil {
		return nil // not found — treat as success per RFC 7009 section 2.2
	}

	// Already revoked or expired — success per RFC 7009.
	if cred.IsRevoked || time.Now().After(cred.ExpiresAt) {
		return nil
	}

	// Tenant is taken from the credential record — not caller-supplied headers.
	return s.credentialSvc.RevokeCredential(ctx, cred.ID, cred.AccountID, cred.ProjectID, "oauth2_revocation")
}

// parseToken verifies a JWT against the JWKS keyset. The library matches
// the token's kid + alg headers to the correct key automatically.
// If validate is true, expiry/nbf checks are enforced; if false, only signature is checked.
func (s *OAuthService) parseToken(tokenStr string, validate bool) (jwt.Token, error) {
	return jwt.Parse([]byte(tokenStr),
		jwt.WithKeySet(s.jwksSvc.KeySet()),
		jwt.WithValidate(validate),
	)
}

// parseWIMSEURI extracts the account_id and project_id embedded in a WIMSE URI.
// Expected format: spiffe://{domain}/{account_id}/{project_id}/{identity_type}/{external_id}
func (s *OAuthService) parseWIMSEURI(wimseURI string) (accountID, projectID string, err error) {
	prefix := "spiffe://" + s.wimseDomain + "/"
	if !strings.HasPrefix(wimseURI, prefix) {
		return "", "", fmt.Errorf("WIMSE URI must start with %s", prefix)
	}
	// Parts after the prefix: [account_id, project_id, identity_type, external_id]
	parts := strings.SplitN(strings.TrimPrefix(wimseURI, prefix), "/", 4)
	if len(parts) != 4 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("malformed WIMSE URI: expected spiffe://%s/{account}/{project}/{identity_type}/{id}", s.wimseDomain)
	}
	return parts[0], parts[1], nil
}

// isValidClientID checks if a client ID is registered or is a dynamic MCP client.
func (s *OAuthService) isValidClientID(clientID string) bool {
	if s.validClientIDs[clientID] {
		return true
	}
	if s.mcpClientPrefix != "" {
		return strings.HasPrefix(clientID, s.mcpClientPrefix)
	}
	return false
}

// isMCPClient returns true for MCP clients that receive short-lived tokens + refresh tokens.
func (s *OAuthService) isMCPClient(clientID string) bool {
	if s.mcpStaticClients[clientID] {
		return true
	}
	if s.mcpClientPrefix != "" {
		return strings.HasPrefix(clientID, s.mcpClientPrefix)
	}
	return false
}

// parseScopeString splits a space-delimited scope string into a slice.
func parseScopeString(scope string) []string {
	if scope == "" {
		return nil
	}
	return strings.Fields(scope)
}

// intersectScopes returns the subset of requested scopes that are in the allowed set.
//
// Two special cases follow RFC 6749 section 3.3:
//   - If allowed is empty the identity has no scope restriction; return requested as-is.
//   - If requested is empty the client omitted the scope parameter; grant all allowed
//     scopes as the pre-defined default (RFC 6749 section 3.3 requires a default or failure).
func intersectScopes(requested, allowed []string) []string {
	if len(allowed) == 0 {
		return requested
	}
	if len(requested) == 0 {
		return allowed
	}
	set := make(map[string]bool, len(allowed))
	for _, s := range allowed {
		set[s] = true
	}
	var result []string
	for _, s := range requested {
		if set[s] {
			result = append(result, s)
		}
	}
	return result
}
