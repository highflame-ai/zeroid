package service

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// ErrOAuthClientNotFound is returned when a client lookup fails.
var ErrOAuthClientNotFound = errors.New("oauth client not found")

// ErrOAuthClientAlreadyExists is returned when a client with the same client_id already exists.
var ErrOAuthClientAlreadyExists = errors.New("oauth client already exists")

// ErrInvalidClientSecret is returned when secret verification fails.
var ErrInvalidClientSecret = errors.New("invalid client secret")

// OAuthClientService manages OAuth2 client registration.
type OAuthClientService struct {
	repo *postgres.OAuthClientRepository
	// allowPrivateNotificationEndpoints relaxes the SSRF guard on
	// client_notification_endpoint registration when true. Defaults to
	// false (production-safe). Flipped via SetAllowPrivateNotificationEndpoints
	// in test / single-tenant dev deployments that need to register
	// loopback-style endpoints like https://localhost:9000/.
	allowPrivateNotificationEndpoints bool
}

// NewOAuthClientService creates a new OAuthClientService.
func NewOAuthClientService(repo *postgres.OAuthClientRepository) *OAuthClientService {
	return &OAuthClientService{repo: repo}
}

// SetAllowPrivateNotificationEndpoints toggles the SSRF guard on
// client_notification_endpoint registration. Production must keep this false
// (the default). Tests + single-tenant dev deployments needing loopback
// endpoints flip to true. Mirrors BackchannelServiceConfig's same-named
// field; both should be set from the same source in server.go.
func (s *OAuthClientService) SetAllowPrivateNotificationEndpoints(allow bool) {
	s.allowPrivateNotificationEndpoints = allow
}

// RegisterClientRequest holds all fields for creating an OAuth2 client.
// Confidential clients get a generated bcrypt secret; public clients have none.
type RegisterClientRequest struct {
	ClientID                string
	Name                    string
	Description             string
	Confidential            bool
	TokenEndpointAuthMethod string
	GrantTypes              []string
	Scopes                  []string
	RedirectURIs            []string
	AccessTokenTTL          int
	RefreshTokenTTL         int
	JWKSURI                 string
	JWKS                    json.RawMessage
	SoftwareID              string
	SoftwareVersion         string
	Contacts                []string
	Metadata                json.RawMessage
	// IdentityID optionally binds this OAuth client to an agent identity.
	// When set, authorization_code and refresh_token grants issued through
	// this client gate on the linked identity's expires_at + status (fail-
	// closed) and propagate the link to refresh_tokens.identity_id for
	// downstream rotation checks. Tenant-scoped IDOR validation happens
	// at the handler boundary before this struct is built. Empty = plain
	// human-session client.
	IdentityID string

	// CIBA ping/push endpoint. Must be HTTPS when non-empty; validated at registration.
	ClientNotificationEndpoint string
	// CIBA Core §10 token delivery mode: "poll" (default), "ping", or "push".
	// Validated against the domain enum at registration.
	BackchannelTokenDeliveryMode string
}

// RegisterClient creates a new OAuth2 client.
//
// If req.Confidential is true, a client_secret is generated and bcrypt-hashed;
// the plain-text secret is returned (shown once only). For public clients the
// returned secret string is empty.
//
// Identity link is resolved at token issuance time (client_credentials grant),
// not at registration time — matching industry standard (Auth0, Okta).
func (s *OAuthClientService) RegisterClient(ctx context.Context, req RegisterClientRequest) (*domain.OAuthClient, string, error) {
	if req.ClientID == "" || req.Name == "" {
		return nil, "", fmt.Errorf("clientID and name are required")
	}
	// CIBA Core §4: client_notification_endpoint MUST be an HTTPS URL when
	// supplied. Reject http:// / non-URL values at registration so a faulty
	// client cannot lead the server to POST credentials over plaintext. The
	// SSRF guard (resolved-IP check against private ranges) also fires here
	// unless allowPrivateNotificationEndpoints is set for test/dev.
	if req.ClientNotificationEndpoint != "" {
		if err := validateNotificationEndpoint(ctx, req.ClientNotificationEndpoint, s.allowPrivateNotificationEndpoints); err != nil {
			return nil, "", err
		}
	}

	// CIBA Core §10: validate the declared delivery mode. ping/push require
	// a registered notification endpoint — refuse the registration outright
	// rather than letting it fail at bc-authorize time. Empty defaults to "poll".
	deliveryMode := req.BackchannelTokenDeliveryMode
	if deliveryMode == "" {
		deliveryMode = string(domain.BackchannelNotificationPoll)
	}
	if !domain.IsValidBackchannelDeliveryMode(deliveryMode) {
		return nil, "", fmt.Errorf("invalid backchannel_token_delivery_mode %q", deliveryMode)
	}
	if (deliveryMode == string(domain.BackchannelNotificationPing) || deliveryMode == string(domain.BackchannelNotificationPush)) &&
		req.ClientNotificationEndpoint == "" {
		return nil, "", fmt.Errorf("backchannel_token_delivery_mode=%s requires client_notification_endpoint", deliveryMode)
	}

	var plainSecret string
	var hashedSecret string
	var clientType string
	var authMethod string

	if req.Confidential {
		secret, err := generateSecureToken(32)
		if err != nil {
			return nil, "", fmt.Errorf("failed to generate client_secret: %w", err)
		}
		hashed, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
		if err != nil {
			return nil, "", fmt.Errorf("failed to hash client secret: %w", err)
		}
		plainSecret = secret
		hashedSecret = string(hashed)
		clientType = "confidential"
		authMethod = "client_secret_basic"
	} else {
		clientType = "public"
		authMethod = "none"
	}

	if req.TokenEndpointAuthMethod != "" {
		authMethod = req.TokenEndpointAuthMethod
	}

	grantTypes := req.GrantTypes
	if len(grantTypes) == 0 {
		if req.Confidential {
			grantTypes = []string{"client_credentials"}
		} else {
			grantTypes = []string{"authorization_code"}
		}
	}

	redirectURIs := req.RedirectURIs
	if redirectURIs == nil {
		redirectURIs = []string{}
	}
	scopes := req.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	contacts := req.Contacts
	if contacts == nil {
		contacts = []string{}
	}

	var identityID *string
	if req.IdentityID != "" {
		id := req.IdentityID
		identityID = &id
	}

	now := time.Now()
	client := &domain.OAuthClient{
		ID:                           uuid.New().String(),
		ClientID:                     req.ClientID,
		ClientSecret:                 hashedSecret,
		Name:                         req.Name,
		Description:                  req.Description,
		ClientType:                   clientType,
		TokenEndpointAuthMethod:      authMethod,
		GrantTypes:                   grantTypes,
		RedirectURIs:                 redirectURIs,
		Scopes:                       scopes,
		AccessTokenTTL:               req.AccessTokenTTL,
		RefreshTokenTTL:              req.RefreshTokenTTL,
		JWKSURI:                      req.JWKSURI,
		JWKS:                         req.JWKS,
		SoftwareID:                   req.SoftwareID,
		SoftwareVersion:              req.SoftwareVersion,
		Contacts:                     contacts,
		Metadata:                     req.Metadata,
		IdentityID:                   identityID,
		ClientNotificationEndpoint:   req.ClientNotificationEndpoint,
		BackchannelTokenDeliveryMode: deliveryMode,
		RegistrationSource:           "internal",
		IsActive:                     true,
		CreatedAt:                    now,
		UpdatedAt:                    now,
	}

	if err := s.repo.Create(ctx, client); err != nil {
		if isDuplicateKeyError(err) {
			return nil, "", ErrOAuthClientAlreadyExists
		}
		return nil, "", fmt.Errorf("failed to register oauth client: %w", err)
	}

	log.Info().
		Str("client_id", req.ClientID).
		Str("client_type", clientType).
		Msg("OAuth2 client registered")

	return client, plainSecret, nil
}

// GetPublicClient retrieves a registered public PKCE client by client_id.
func (s *OAuthClientService) GetPublicClient(ctx context.Context, clientID string) (*domain.OAuthClient, error) {
	client, err := s.repo.GetPublicByClientID(ctx, clientID)
	if err != nil {
		return nil, ErrOAuthClientNotFound
	}
	if !client.IsActive {
		return nil, ErrOAuthClientNotFound
	}
	return client, nil
}

// GetClientByClientID retrieves any client (public or confidential) by client_id.
func (s *OAuthClientService) GetClientByClientID(ctx context.Context, clientID string) (*domain.OAuthClient, error) {
	client, err := s.repo.GetByClientID(ctx, clientID)
	if err != nil {
		return nil, ErrOAuthClientNotFound
	}

	return client, nil
}

// GetClient retrieves a client by UUID.
func (s *OAuthClientService) GetClient(ctx context.Context, id string) (*domain.OAuthClient, error) {
	client, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, ErrOAuthClientNotFound
	}
	return client, nil
}

// ListClients returns all registered OAuth2 clients.
func (s *OAuthClientService) ListClients(ctx context.Context) ([]*domain.OAuthClient, error) {
	return s.repo.List(ctx)
}

// VerifyClientSecret looks up a client by client_id and verifies the provided
// secret against the bcrypt hash.
func (s *OAuthClientService) VerifyClientSecret(ctx context.Context, clientID, secret string) (*domain.OAuthClient, error) {
	client, err := s.repo.GetByClientID(ctx, clientID)
	if err != nil {
		return nil, ErrOAuthClientNotFound
	}
	if !client.IsActive {
		return nil, ErrOAuthClientNotFound
	}
	if err := bcrypt.CompareHashAndPassword([]byte(client.ClientSecret), []byte(secret)); err != nil {
		return nil, ErrInvalidClientSecret
	}
	return client, nil
}

// RotateSecret generates and stores a new secret for a client.
// Returns the new plain-text secret (only shown once).
func (s *OAuthClientService) RotateSecret(ctx context.Context, id string) (*domain.OAuthClient, string, error) {
	client, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, "", ErrOAuthClientNotFound
	}

	plainSecret, err := generateSecureToken(32)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate secret: %w", err)
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(plainSecret), bcrypt.DefaultCost)
	if err != nil {
		return nil, "", fmt.Errorf("failed to hash secret: %w", err)
	}

	client.ClientSecret = string(hashed)
	client.UpdatedAt = time.Now()
	if err := s.repo.Update(ctx, client); err != nil {
		return nil, "", fmt.Errorf("failed to update client secret: %w", err)
	}

	return client, plainSecret, nil
}

// UpdateClient persists changes to a client record.
func (s *OAuthClientService) UpdateClient(ctx context.Context, client *domain.OAuthClient) error {
	return s.repo.Update(ctx, client)
}

// DeleteClient removes an OAuth2 client.
func (s *OAuthClientService) DeleteClient(ctx context.Context, id string) error {
	return s.repo.Delete(ctx, id)
}

// ── RFC 7591 / RFC 7592 Dynamic Client Registration ──────────────────────────

// dcrBcryptCost is the work factor used for hashing the registration_access_token.
// Stricter than the default to reflect the higher trust placed in a long-lived
// management bearer that survives a single registration call.
const dcrBcryptCost = 12

// dcrAllowedAuthMethods are the only token_endpoint_auth_method values
// dynamically-registered clients may declare. Enforced at the service layer
// as defense-in-depth so a direct call to DynamicRegisterClient or
// UpdateDynamicClient (bypassing the handler) cannot smuggle in "none" or
// an unsupported value.
var dcrAllowedAuthMethods = map[string]bool{
	"client_secret_post":  true,
	"client_secret_basic": true,
}

// dcrAllowedGrantTypes mirrors the handler-layer allow-list. Service-layer
// enforcement guards against direct service-method callers.
var dcrAllowedGrantTypes = map[string]bool{
	"client_credentials":                          true,
	"urn:ietf:params:oauth:grant-type:jwt-bearer": true,
}

// validateDCRSubmittedFields runs the service-layer defense for grant_types
// and token_endpoint_auth_method. Returns the normalised auth method (with
// the default applied for empty input) or an error.
func validateDCRSubmittedFields(grantTypes []string, authMethod string) (string, error) {
	for _, gt := range grantTypes {
		if !dcrAllowedGrantTypes[gt] {
			return "", fmt.Errorf("grant_type %q is not permitted for dynamically-registered clients", gt)
		}
	}
	if authMethod == "" {
		// RFC 7591 §2 default. Older drafts and some examples used
		// client_secret_post; we conform to the published spec for
		// interoperability with standards-compliant clients that omit
		// the field expecting the spec default.
		return "client_secret_basic", nil
	}
	if !dcrAllowedAuthMethods[authMethod] {
		return "", fmt.Errorf("token_endpoint_auth_method %q is not permitted for dynamically-registered clients", authMethod)
	}
	return authMethod, nil
}

// DynamicRegisterClientRequest is the input shape for RFC 7591 dynamic registration.
// Mirrors RegisterClientRequest's confidential-client subset — DCR-issued clients
// are always confidential (they get a client_secret and an opaque registration token).
type DynamicRegisterClientRequest struct {
	Name                    string
	GrantTypes              []string
	Scopes                  []string
	RedirectURIs            []string
	TokenEndpointAuthMethod string
	SoftwareID              string
	SoftwareVersion         string
	Contacts                []string
	Metadata                json.RawMessage
}

// DynamicRegisterClient creates an OAuth2 client via RFC 7591 dynamic registration.
// Returns the created client, the plain-text client_secret, and the plain-text
// registration_access_token. Both are shown once and never stored in plain form;
// callers MUST return them to the registrant on the registration response and
// then drop the values from memory.
func (s *OAuthClientService) DynamicRegisterClient(ctx context.Context, req DynamicRegisterClientRequest) (*domain.OAuthClient, string, string, error) {
	if req.Name == "" {
		return nil, "", "", fmt.Errorf("name is required")
	}

	clientID, err := generateSecureToken(16)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to generate client_id: %w", err)
	}

	plainSecret, err := generateSecureToken(32)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to generate client_secret: %w", err)
	}
	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(plainSecret), dcrBcryptCost)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to hash client secret: %w", err)
	}

	plainRegToken, err := generateSecureToken(32)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to generate registration_access_token: %w", err)
	}
	hashedRegToken, err := bcrypt.GenerateFromPassword([]byte(plainRegToken), dcrBcryptCost)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to hash registration token: %w", err)
	}

	grantTypes := req.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{"client_credentials"}
	}
	authMethod, err := validateDCRSubmittedFields(grantTypes, req.TokenEndpointAuthMethod)
	if err != nil {
		return nil, "", "", err
	}
	scopes := req.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	redirectURIs := req.RedirectURIs
	if redirectURIs == nil {
		redirectURIs = []string{}
	}
	contacts := req.Contacts
	if contacts == nil {
		contacts = []string{}
	}

	now := time.Now()
	client := &domain.OAuthClient{
		ID:                      uuid.New().String(),
		ClientID:                clientID,
		ClientSecret:            string(hashedSecret),
		Name:                    req.Name,
		ClientType:              "confidential",
		TokenEndpointAuthMethod: authMethod,
		GrantTypes:              grantTypes,
		RedirectURIs:            redirectURIs,
		Scopes:                  scopes,
		SoftwareID:              req.SoftwareID,
		SoftwareVersion:         req.SoftwareVersion,
		Contacts:                contacts,
		Metadata:                req.Metadata,
		// backchannel_token_delivery_mode has a NOT NULL DEFAULT 'poll' + a CHECK
		// constraint (migration 021). Bun inserts the Go zero value rather than
		// letting the DB default fire, so DCR clients must set this explicitly or
		// the INSERT fails the CHECK with SQLSTATE 23514 (a 500 at the handler).
		// DCR clients don't use CIBA, so 'poll' is the safe baseline.
		BackchannelTokenDeliveryMode: string(domain.BackchannelNotificationPoll),
		RegistrationSource:           "dynamic",
		RegistrationAccessToken:      string(hashedRegToken),
		IsActive:                     true,
		CreatedAt:                    now,
		UpdatedAt:                    now,
	}

	if err := s.repo.Create(ctx, client); err != nil {
		if isDuplicateKeyError(err) {
			return nil, "", "", ErrOAuthClientAlreadyExists
		}
		return nil, "", "", fmt.Errorf("failed to register oauth client: %w", err)
	}

	log.Info().
		Str("client_id", clientID).
		Msg("OAuth2 client registered via RFC 7591 dynamic registration")

	return client, plainSecret, plainRegToken, nil
}

// dummyRegistrationTokenHash is a pre-computed bcrypt hash used for constant-time
// comparison when a client_id is not found, preventing timing-based client_id enumeration.
// The plaintext is irrelevant — no real token will ever match this.
var dummyRegistrationTokenHash []byte

func init() {
	h, err := bcrypt.GenerateFromPassword([]byte("dummy-timing-equaliser"), dcrBcryptCost)
	if err != nil {
		panic("failed to generate dummy bcrypt hash for timing equalisation: " + err.Error())
	}
	dummyRegistrationTokenHash = h
}

// VerifyRegistrationToken looks up a dynamically registered client by client_id
// and verifies the provided registration_access_token against the stored bcrypt hash.
// Used to authenticate RFC 7592 management requests (GET/PUT/DELETE /oauth2/register/{client_id}).
//
// Always runs a bcrypt comparison regardless of whether the client_id exists, so that
// response time does not leak client_id existence to an attacker.
//
// Errors are distinguished:
//   - ErrOAuthClientNotFound: row absent or row is not a dynamic client or hash mismatch.
//     Callers map this to 401 invalid_token.
//   - any other error: a DB or infrastructure failure. Callers must map this to 5xx,
//     not 401, so an outage is not masquerading as an auth failure.
func (s *OAuthClientService) VerifyRegistrationToken(ctx context.Context, clientID, regToken string) (*domain.OAuthClient, error) {
	client, err := s.repo.GetByClientID(ctx, clientID)
	if err != nil {
		// sql.ErrNoRows is the genuine not-found; equalise timing and return 401.
		// Anything else is a DB/infra failure that the handler must propagate as 500.
		if errors.Is(err, sql.ErrNoRows) {
			_ = bcrypt.CompareHashAndPassword(dummyRegistrationTokenHash, []byte(regToken))
			return nil, ErrOAuthClientNotFound
		}
		return nil, fmt.Errorf("verify registration token: %w", err)
	}
	if client.RegistrationSource != "dynamic" {
		_ = bcrypt.CompareHashAndPassword(dummyRegistrationTokenHash, []byte(regToken))
		return nil, ErrOAuthClientNotFound
	}
	if err := bcrypt.CompareHashAndPassword([]byte(client.RegistrationAccessToken), []byte(regToken)); err != nil {
		return nil, ErrOAuthClientNotFound
	}
	return client, nil
}

// UpdateDynamicClient replaces the mutable metadata of a dynamically registered client
// per RFC 7592 §3 (full replacement, not partial update).
// The client_id and secrets are immutable after registration.
func (s *OAuthClientService) UpdateDynamicClient(ctx context.Context, clientID string, req DynamicRegisterClientRequest) (*domain.OAuthClient, error) {
	client, err := s.repo.GetByClientID(ctx, clientID)
	if err != nil {
		// Distinguish genuine not-found from infra failure so the handler
		// can return 401 vs 5xx appropriately. Same pattern as
		// VerifyRegistrationToken — a DB outage must not look like "no
		// such client".
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrOAuthClientNotFound
		}
		return nil, fmt.Errorf("update dynamic client: lookup failed: %w", err)
	}
	if client.RegistrationSource != "dynamic" {
		return nil, ErrOAuthClientNotFound
	}
	// RFC 7592 §3: PUT is a full replacement. The handler applies RFC 7591 defaults
	// for any omitted fields before calling here, so all fields are unconditionally replaced.
	grantTypes := req.GrantTypes
	if grantTypes == nil {
		grantTypes = []string{"client_credentials"}
	}
	authMethod, err := validateDCRSubmittedFields(grantTypes, req.TokenEndpointAuthMethod)
	if err != nil {
		return nil, err
	}
	scopes := req.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	redirectURIs := req.RedirectURIs
	if redirectURIs == nil {
		redirectURIs = []string{}
	}
	contacts := req.Contacts
	if contacts == nil {
		contacts = []string{}
	}

	client.Name = req.Name
	client.GrantTypes = grantTypes
	client.Scopes = scopes
	client.RedirectURIs = redirectURIs
	client.TokenEndpointAuthMethod = authMethod
	client.SoftwareID = req.SoftwareID
	client.SoftwareVersion = req.SoftwareVersion
	client.Contacts = contacts
	client.Metadata = req.Metadata
	client.UpdatedAt = time.Now()
	if err := s.repo.Update(ctx, client); err != nil {
		return nil, fmt.Errorf("failed to update dynamic client: %w", err)
	}
	return client, nil
}

// DeleteDynamicClient removes a dynamically registered client by its client_id.
// The registration_source = 'dynamic' guard is enforced at the repo layer too,
// so this method cannot accidentally remove an internal client.
func (s *OAuthClientService) DeleteDynamicClient(ctx context.Context, clientID string) error {
	return s.repo.DeleteByClientID(ctx, clientID)
}

// generateSecureToken creates a cryptographically random hex-encoded token.
func generateSecureToken(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate secure token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// ErrPrivateNotificationEndpoint is the sentinel returned when an outbound
// destination resolves to a private / loopback / link-local / multicast /
// CGN / unspecified address. Service-layer validation errors wrap this via
// %w so callers (registration handler, request-time dispatch checks) can use
// errors.Is to recognise the SSRF-guard rejection consistently. The error
// deliberately does NOT echo the resolved IP back to the caller — leaking
// our internal DNS view of the client's hostname is not a useful diagnostic
// for the client and could expose split-horizon DNS topology.
//
// Mitigation for GHSA-599q-j34m-33vc — unguarded outbound HTTPS from CIBA
// notification dispatch could be used as an SSRF primitive to scan internal
// networks or hit cloud-metadata services from inside the zeroid process.
var ErrPrivateNotificationEndpoint = errors.New("client_notification_endpoint resolves to a private or reserved address")

// dnsLookupTimeout caps each resolve call so a slow / hanging DNS server
// cannot stall a registration or dispatch indefinitely. 2 seconds is well
// above typical resolver latency and leaves headroom inside the surrounding
// HTTP request budget.
const dnsLookupTimeout = 2 * time.Second

// validateNotificationEndpoint enforces the CIBA Core §4 rule that
// client_notification_endpoint MUST be an absolute HTTPS URL. http:// is
// rejected so the server can never POST the per-request bearer
// (client_notification_token) over plaintext.
//
// When allowPrivate is false (production default), the host is resolved with
// a 2-second timeout and every returned IP is checked against a
// private/reserved-range blocklist. If ANY resolved IP is blocked, the
// registration is rejected — DNS-rebinding defence (a hostname pointing at
// both public and private IPs is treated as hostile). Pass allowPrivate=true
// ONLY in test/dev contexts where you register endpoints like
// https://localhost:8080/; in that mode DNS resolution is skipped entirely
// so synthetic RFC 6761 .test/.example/.invalid fixtures don't hard-fail.
func validateNotificationEndpoint(ctx context.Context, raw string, allowPrivate bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid client_notification_endpoint: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("client_notification_endpoint must be https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("client_notification_endpoint must include a host")
	}
	return resolveAndCheckHost(ctx, u.Hostname(), allowPrivate)
}

// resolveAndCheckHost performs a timeout-bounded DNS lookup for host and
// rejects if ANY returned IP is in the private/reserved blocklist (DNS-
// rebinding defence: a hostname that mixes public and private A records is
// treated as hostile). When allowPrivate is true, DNS resolution is skipped
// entirely — synthetic RFC 6761 .test/.example/.invalid fixtures in
// integration tests would otherwise hard-fail under NXDOMAIN.
//
// The resolved IP is logged at debug level for operator triage but NOT
// echoed back to the caller — leaking our internal DNS view of the client's
// hostname is not a useful diagnostic for the client and could expose
// split-horizon DNS topology.
//
// Pure-IP hostnames are also handled — the resolver returns a single-entry
// slice with the literal IP, so the blocklist check applies to direct
// IP-as-host registrations like https://10.0.0.5/.
func resolveAndCheckHost(ctx context.Context, host string, allowPrivate bool) error {
	if allowPrivate {
		return nil
	}
	lookupCtx, cancel := context.WithTimeout(ctx, dnsLookupTimeout)
	defer cancel()
	ips, err := lookupIPs(lookupCtx, host)
	if err != nil {
		return fmt.Errorf("client_notification_endpoint host %q does not resolve: %w", host, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("client_notification_endpoint host %q returned no IPs", host)
	}
	for _, ip := range ips {
		if isBlockedIP(ip) {
			log.Debug().
				Str("host", host).
				Str("blocked_ip", ip.String()).
				Msg("SSRF guard rejected notification endpoint")
			return ErrPrivateNotificationEndpoint
		}
	}
	return nil
}

// lookupIPs is a package-level var so tests can inject a stubbed resolver
// without touching real DNS. Production uses net.DefaultResolver.LookupIPAddr
// which honours the supplied context (so the dnsLookupTimeout actually
// bounds the call — net.LookupIP does not respect context).
var lookupIPs = func(ctx context.Context, host string) ([]net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, len(addrs))
	for i, a := range addrs {
		ips[i] = a.IP
	}
	return ips, nil
}

// isBlockedIP returns true for any IP that should not be reachable as a
// CIBA notification target. Covers, in order:
//
// Via stdlib helpers:
//   - RFC 1918 IPv4 private (10/8, 172.16/12, 192.168/16) — net.IP.IsPrivate
//   - RFC 4193 IPv6 ULA (fc00::/7) — net.IP.IsPrivate, also catches Azure
//     IMDS at fd00:ec2::254 which sits inside fc00::/7
//   - Loopback (127/8, ::1) — net.IP.IsLoopback
//   - Link-local unicast (169.254/16, fe80::/10) — net.IP.IsLinkLocalUnicast.
//     Catches AWS/GCP IMDS at 169.254.169.254.
//   - Multicast (224/4, ff00::/8) — net.IP.IsMulticast. Strict superset of
//     IsLinkLocalMulticast (224.0.0/24, ff02::/16), so the link-local check
//     is implied and not repeated.
//   - Unspecified (0.0.0.0, ::) — net.IP.IsUnspecified
//
// Manual ranges not exposed by stdlib:
//   - RFC 1122 "this network" (0.0.0.0/8) — IsUnspecified only catches the
//     single address 0.0.0.0; the rest of the /8 should also never appear
//     as a destination.
//   - RFC 6598 Carrier-Grade NAT (100.64.0.0/10)
//   - RFC 5737 documentation (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) —
//     not publicly routed; could be hijacked locally.
//   - RFC 2544 benchmarking (198.18.0.0/15) — for network-device testing,
//     never publicly routed.
//   - RFC 1112 / RFC 6890 reserved (240.0.0.0/4) — class E reserved, never
//     allocated for routing.
func isBlockedIP(ip net.IP) bool {
	if ip.IsPrivate() ||
		ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified() {
		return true
	}
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	switch {
	case v4[0] == 0:
		// RFC 1122 "this network": 0.0.0.0/8
		return true
	case v4[0] == 100 && v4[1]&0xC0 == 0x40:
		// RFC 6598 CGN: 100.64.0.0/10
		return true
	case v4[0] == 192 && v4[1] == 0 && v4[2] == 2:
		// RFC 5737 TEST-NET-1: 192.0.2.0/24
		return true
	case v4[0] == 198 && v4[1] == 51 && v4[2] == 100:
		// RFC 5737 TEST-NET-2: 198.51.100.0/24
		return true
	case v4[0] == 203 && v4[1] == 0 && v4[2] == 113:
		// RFC 5737 TEST-NET-3: 203.0.113.0/24
		return true
	case v4[0] == 198 && v4[1]&0xFE == 18:
		// RFC 2544 benchmarking: 198.18.0.0/15
		return true
	case v4[0]&0xF0 == 0xF0:
		// RFC 1112 / RFC 6890 reserved: 240.0.0.0/4. Excludes 255.255.255.255
		// only in the broadcast sense — that's caught by IsLinkLocalUnicast/
		// IsLoopback for typical interfaces, and would be hostile as a
		// destination either way.
		return true
	}
	return false
}
