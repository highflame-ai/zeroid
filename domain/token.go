package domain

import (
	"encoding/json"
	"time"

	"github.com/uptrace/bun"
)

// TokenClaims represents the claims embedded in an issued JWT.
type TokenClaims struct {
	Issuer    string    `json:"iss"`
	Subject   string    `json:"sub"`
	Audience  []string  `json:"aud,omitempty"`
	IssuedAt  time.Time `json:"iat"`
	ExpiresAt time.Time `json:"exp"`
	JWTID     string    `json:"jti"`
	AccountID string    `json:"account_id"`
	ProjectID string    `json:"project_id"`

	// Identity claims — canonical names.
	ExternalID   string `json:"external_id,omitempty"`
	IdentityType string `json:"identity_type,omitempty"`
	SubType      string `json:"sub_type,omitempty"`
	TrustLevel   string `json:"trust_level,omitempty"`
	Status       string `json:"status,omitempty"`
	Name         string `json:"name,omitempty"`

	// Auth context.
	UserID          string   `json:"user_id,omitempty"`
	Scopes          []string `json:"scopes,omitempty"`
	GrantType       string   `json:"grant_type,omitempty"`
	DelegationDepth int      `json:"delegation_depth,omitempty"`

	// Identity metadata — embedded so downstream services
	// can make decisions without calling back to ZeroID.
	Framework    string          `json:"framework,omitempty"`
	Version      string          `json:"version,omitempty"`
	Publisher    string          `json:"publisher,omitempty"`
	Capabilities json.RawMessage `json:"capabilities,omitempty"`
	ActorClaims  *ActorClaims    `json:"act,omitempty"`
}

// ActorClaims represents the nested "act" claim in delegated tokens (RFC 8693).
type ActorClaims struct {
	Subject string `json:"sub"`
	Issuer  string `json:"iss,omitempty"`
}

// AccessToken is the RFC 6749 §5.1 token response returned to the caller after issuance.
type AccessToken struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"` // "Bearer"
	ExpiresIn   int    `json:"expires_in"` // seconds
	Scope       string `json:"scope,omitempty"`
	JTI         string `json:"jti"`
	IssuedAt    int64  `json:"iat"`
	// Convenience fields — duplicated from JWT so callers don't need to decode.
	AccountID    string `json:"account_id,omitempty"`
	ProjectID    string `json:"project_id,omitempty"`
	ExternalID   string `json:"external_id,omitempty"`
	UserID       string `json:"user_id,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	// AuthorizationDetails is the granted RFC 9396 authorization_details
	// JSON array, included on the token response per §5.2 when the request
	// carried (and the AS granted) RAR. Empty / unset for non-CIBA flows
	// and for CIBA requests that did not supply authorization_details.
	// The raw bytes are the same array embedded in the access-token JWT
	// claim (§6.1) — kept verbatim so resource servers see the exact
	// payload the approver authorized.
	AuthorizationDetails json.RawMessage `json:"authorization_details,omitempty"`
}

// OAuthClient represents a registered OAuth2 client (RFC 7591).
// Clients are global — tenant scoping happens at token issuance, not registration.
// The ClientSecret field stores a bcrypt hash and is never serialised to JSON.
type OAuthClient struct {
	bun.BaseModel `bun:"table:oauth_clients"`

	// Core identity
	ID           string `bun:"id,pk"         json:"id"`
	ClientID     string `bun:"client_id"     json:"client_id"`
	ClientSecret string `bun:"client_secret" json:"-"`
	Name         string `bun:"name"          json:"name"`
	Description  string `bun:"description"   json:"description,omitempty"`

	// Classification (RFC 6749 §2.1, RFC 7591)
	ClientType              string `bun:"client_type"                json:"client_type"`
	TokenEndpointAuthMethod string `bun:"token_endpoint_auth_method" json:"token_endpoint_auth_method,omitempty"`

	// OAuth configuration
	GrantTypes   []string `bun:"grant_types,array"  json:"grant_types"`
	RedirectURIs []string `bun:"redirect_uris,array" json:"redirect_uris"`
	Scopes       []string `bun:"scopes,array"       json:"scopes"`

	// CIBA Core 1.0 — ping/push notification endpoint. Registered HTTPS URL
	// the server POSTs to when a backchannel authentication request resolves.
	// Empty when the client doesn't support ping/push mode (polling-only).
	ClientNotificationEndpoint string `bun:"client_notification_endpoint" json:"client_notification_endpoint,omitempty"`

	// CIBA Core 1.0 §10 — declared token delivery mode for this client.
	// "poll" (default), "ping", or "push". Determines how a CIBA-issued
	// token reaches the client: by polling /oauth2/token, by ping callback +
	// poll, or by push callback (token delivered directly).
	BackchannelTokenDeliveryMode string `bun:"backchannel_token_delivery_mode" json:"backchannel_token_delivery_mode,omitempty"`

	// Token lifetime (per-client, 0 = use server default)
	AccessTokenTTL  int `bun:"access_token_ttl"  json:"access_token_ttl,omitempty"`
	RefreshTokenTTL int `bun:"refresh_token_ttl" json:"refresh_token_ttl,omitempty"`

	// Secret management
	ClientSecretExpiresAt *time.Time `bun:"client_secret_expires_at" json:"client_secret_expires_at,omitempty"`

	// Key material (for private_key_jwt — RFC 7523)
	JWKSURI string          `bun:"jwks_uri"  json:"jwks_uri,omitempty"`
	JWKS    json.RawMessage `bun:"jwks,type:jsonb" json:"jwks,omitempty"`

	// Software identity (RFC 7591)
	SoftwareID      string `bun:"software_id"      json:"software_id,omitempty"`
	SoftwareVersion string `bun:"software_version"  json:"software_version,omitempty"`

	// Ownership
	Contacts []string `bun:"contacts,array" json:"contacts,omitempty"`

	// Extensibility
	Metadata json.RawMessage `bun:"metadata,type:jsonb" json:"metadata,omitempty"`

	// IdentityID optionally binds this OAuth client to an agent identity.
	// When set, authorization_code and refresh_token grants issued through
	// this client carry the identity_id forward (refresh_tokens.identity_id
	// already exists) and gate token issuance on the linked identity's
	// status + expires_at — same fail-closed semantics jwt_bearer and
	// api_key paths have. Nil for plain human-session clients (CLI, MCP).
	IdentityID *string `bun:"identity_id,type:uuid,nullzero" json:"identity_id,omitempty"`

	// Dynamic Client Registration (RFC 7591/7592)
	// RegistrationSource is "internal" for clients created via the admin/internal
	// API path, "dynamic" for clients created via POST /oauth2/register, and
	// RegistrationSourceCIMD for an ephemeral client synthesized from a Client ID
	// Metadata Document. See SelfAsserted.
	RegistrationSource string `bun:"registration_source" json:"registration_source,omitempty"`
	// RegistrationAccessToken is a bcrypt hash of the management bearer token
	// returned at RFC 7591 registration. NULL for internal clients (the column
	// is NULL-able in the schema; `nullzero` ensures bun INSERTs NULL when the
	// field is the Go zero value instead of persisting an empty string that
	// would defeat `IS NULL` queries). Never JSON-serialized.
	RegistrationAccessToken string `bun:"registration_access_token,nullzero" json:"-"`

	// Lifecycle
	IsActive  bool      `bun:"is_active"   json:"is_active"`
	CreatedAt time.Time `bun:"created_at"  json:"created_at"`
	UpdatedAt time.Time `bun:"updated_at"  json:"updated_at"`
}

// ── Client-authentication predicates ─────────────────────────────────────────
//
// `client_type` used to carry a usable implication: a "public" client holds no
// credential. RFC 7523 §2.2 private_key_jwt broke it (zeroid#206) — such a
// client holds a real credential, its signing key, while being neither
// confidential nor secret-bearing. Worse, the value it lands on depends on which
// path registered it, so it is not even consistently wrong.
//
// These predicates exist so that no security decision keys off the raw column
// again. Each names the question it answers, derives it from the REGISTERED
// authentication method, and keeps the old column only as a fallback for rows
// that predate the method being meaningful. Adding a bare `ClientType ==` check
// on an auth path is what zeroid#348 exists to prevent; a ratchet test enforces
// it.

// authMethodPrivateKeyJWT is the RFC 7591 token_endpoint_auth_method value for
// key-based client authentication. Declared here, not in internal/service, so
// the predicates below can be a property of the type rather than of one package.
const authMethodPrivateKeyJWT = "private_key_jwt"

// UsesPrivateKeyJWT reports whether this client authenticates with an RFC 7523
// §2.2 client assertion rather than a shared secret.
func (c *OAuthClient) UsesPrivateKeyJWT() bool {
	return c != nil && c.TokenEndpointAuthMethod == authMethodPrivateKeyJWT
}

// RequiresClientAuthentication reports whether this client MUST prove a
// credential before a grant proceeds — the question the old
// `ClientType == "confidential" || ClientSecret != ""` test was reaching for,
// asked correctly.
//
// Derived from the registered method first, because that is the authoritative
// statement of how the client authenticates. The ClientType/ClientSecret
// fallback covers rows written before the method column was enforced (it is
// unset on those), and is belt-and-braces against an inconsistent row carrying a
// secret with a non-confidential type — which would otherwise skip verification.
func (c *OAuthClient) RequiresClientAuthentication() bool {
	if c == nil {
		return false
	}
	switch c.TokenEndpointAuthMethod {
	case authMethodPrivateKeyJWT, "client_secret_post", "client_secret_basic":
		return true
	case "none":
		// Explicitly credential-less: PKCE is the proof of possession. Fall
		// through to the fallback anyway — a "none" client that somehow carries
		// a stored secret is an inconsistent row, and treating it as
		// credential-less is the unsafe direction.
	}
	return c.ClientType == "confidential" || c.ClientSecret != ""
}

// MayUseInteractiveFlows reports whether this client may obtain an authorization
// code at /oauth2/authorize.
//
// The rule it replaces was `ClientType == "public"`, described in its own
// comment as the inherited pre-CIMD GetPublicClient contract rather than a
// reasoned property. That is preserved: a secret-based confidential client still
// cannot obtain a code here, and widening that is deliberately NOT part of
// zeroid#348.
//
// What changes is that a key-based client qualifies regardless of the
// client_type its registration path happened to assign. A private_key_jwt client
// running authorization_code is ordinary OAuth — it authenticates at the token
// endpoint with its key — and gating it on a column whose value differs between
// the admin and DCR paths made the same client legal or illegal depending on how
// it was created.
func (c *OAuthClient) MayUseInteractiveFlows() bool {
	if c == nil {
		return false
	}
	return c.ClientType == "public" || c.UsesPrivateKeyJWT()
}

// ProofToken represents a persisted WIMSE Proof Token (WPT).
// WPTs are single-use; the nonce column has a DB UNIQUE constraint that provides
// atomic replay prevention without a separate pre-check query.
type ProofToken struct {
	bun.BaseModel `bun:"table:proof_tokens"`

	ID         string     `bun:"id,pk"          json:"id"`
	IdentityID string     `bun:"identity_id"    json:"identity_id"`
	AccountID  string     `bun:"account_id"     json:"account_id"`
	ProjectID  string     `bun:"project_id"     json:"project_id"`
	JTI        string     `bun:"jti"            json:"jti"`
	Nonce      string     `bun:"nonce"          json:"nonce"`
	Audience   string     `bun:"audience"       json:"audience"`
	IssuedAt   time.Time  `bun:"issued_at"      json:"issued_at"`
	ExpiresAt  time.Time  `bun:"expires_at"     json:"expires_at"`
	IsUsed     bool       `bun:"is_used"        json:"is_used"`
	UsedAt     *time.Time `bun:"used_at"        json:"used_at,omitempty"`
	CreatedAt  time.Time  `bun:"created_at"     json:"created_at"`
}

// RegistrationSourceCIMD marks a client synthesized from a Client ID Metadata
// Document rather than registered. See OAuthClient.SelfAsserted.
const RegistrationSourceCIMD = "cimd"

// SelfAsserted reports whether this client's registration came from a document
// the client itself published (CIMD) rather than from a registry row somebody
// vetted.
//
// The distinction matters wherever ZeroID is about to act on the client's own
// claims about itself. A CIMD document is anonymous by construction — no
// registration, no secret, and by default no host allow-list — so its
// redirect_uris are attacker-choosable, not merely attacker-supplied. Anywhere a
// registered client's redirect_uri can be treated as a vetted destination, a
// self-asserted one cannot.
func (c *OAuthClient) SelfAsserted() bool {
	return c != nil && c.RegistrationSource == RegistrationSourceCIMD
}
