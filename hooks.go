package zeroid

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/service"
)

// ClaimsEnricher is called during JWT issuance to add custom claims.
// The claims map already contains standard ZeroID claims; the enricher may add or override entries.
type ClaimsEnricher func(claims map[string]any, identity *domain.Identity, grantType domain.GrantType)

// GrantHandler implements a custom OAuth2 grant type.
// The handler receives the full token request and returns an access token.
// Returning an error causes a 400 response.
type GrantHandler func(ctx context.Context, req GrantRequest) (*domain.AccessToken, error)

// GrantRequest holds the parsed token endpoint fields passed to custom grant handlers.
type GrantRequest struct {
	GrantType        string
	AccountID        string
	ProjectID        string
	ClientID         string
	Scope            string
	UserID           string
	UserEmail        string
	UserName         string
	ApplicationID    string
	AdditionalClaims map[string]any
	// Role and PrivilegeScope are authorization claims
	// minted into the `role` (string) and `privilege_scope` (array) JWT claims.
	// They are honoured ONLY on the trusted-service external-principal exchange
	// path (Server.ExternalPrincipalExchange, gated by TrustedServiceValidator)
	// and can never be injected via AdditionalClaims (both names are reserved).
	Role           string
	PrivilegeScope []string
}

// Principal is the resolved caller at /oauth2/authorize — the tenant +
// user binding that gets baked into the issued authorization code JWT.
// Re-exported from internal/service so deployer code stays at the
// top-level zeroid public surface; both names refer to the same type.
//
// See internal/service/principal.go for the canonical doc comment.
type Principal = service.Principal

// AuthorizeRequest is the typed, read-only snapshot of the parsed
// /oauth2/authorize request handed to every PrincipalResolver. Resolvers
// see this — never net/http types — so the extensibility hook stays
// consistent with zeroid's other typed-struct boundaries.
//
// See internal/service/principal.go for the canonical doc comment.
type AuthorizeRequest = service.AuthorizeRequest

// PrincipalResolver authenticates the caller at /oauth2/authorize.
// Registered via Server.RegisterPrincipalResolver and tried in
// registration order; the first resolver to return a non-nil Principal
// wins. Return ErrPrincipalNotApplicable to defer to the next resolver;
// any other error fails the request with 401 invalid_client.
//
// See internal/service/principal.go for the canonical doc comment.
type PrincipalResolver = service.PrincipalResolver

// ErrPrincipalNotApplicable is the sentinel returned by a
// PrincipalResolver that does not apply to the current request. zeroid
// moves to the next registered resolver; when every resolver returns
// this sentinel, the request fails with 401 invalid_client.
var ErrPrincipalNotApplicable = service.ErrPrincipalNotApplicable

// ErrNoResolversRegistered is the sentinel surfaced by zeroid when
// /oauth2/authorize is reached but no PrincipalResolver has been
// registered via Server.RegisterPrincipalResolver. The handler maps
// this to 503 Service Unavailable so the deployer sees a clear
// "you forgot to wire this up" signal rather than an ambiguous 401.
//
// Deployers don't typically observe this sentinel directly — it's
// emitted by zeroid's chain walker and consumed by the handler. The
// re-export exists so deployer tests can match on it via errors.Is.
var ErrNoResolversRegistered = service.ErrNoResolversRegistered

// APIKeyResolution is the public projection returned by
// Server.ResolveAPIKey. Narrow + stable — does not leak zeroid
// internals (*domain.Identity, *domain.APIKey row, credential-policy
// records). Consumers map this onto whatever shape their layer needs
// (typically zeroid.Principal in a PrincipalResolver implementation).
//
// See internal/service/oauth.go (APIKeyResolution definition) for the
// canonical doc comment + field-level semantics.
type APIKeyResolution = service.APIKeyResolution

// AdminAuthMiddleware is an optional middleware applied to the admin API router.
// When set, every request to the admin port passes through this middleware before
// reaching any handler. Use this to add authentication (Bearer JWT, mTLS, API key,
// or any custom scheme) when embedding ZeroID as a library.
//
// When nil (the default), the admin API has no authentication — protect it at the
// network layer (VPN, service mesh, localhost-only binding, firewall rules).
type AdminAuthMiddleware func(next http.Handler) http.Handler

// OAuthClientConfig holds all fields for registering an OAuth2 client (RFC 7591).
// Used by EnsureClient for startup seeding and by deployers for programmatic registration.
type OAuthClientConfig struct {
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
	// ClientNotificationEndpoint is the HTTPS callback CIBA ping mode posts to.
	// Empty for clients that only use polling mode.
	ClientNotificationEndpoint string
	// BackchannelTokenDeliveryMode declares which CIBA delivery mode the client
	// supports: "poll" (default), "ping", or "push". ping/push require a
	// non-empty ClientNotificationEndpoint.
	BackchannelTokenDeliveryMode string
}

// TrustedServiceValidator checks whether the current request comes from a trusted
// internal service that is allowed to perform external principal token exchange
// (RFC 8693). Implementations read from context (set by deployer-provided global
// middleware) and return the service name on success, or an error to reject.
//
// Set via Server.TrustedServiceValidator() after NewServer.
type TrustedServiceValidator func(ctx context.Context) (serviceName string, err error)

// BackchannelNotification is the payload handed to a BackchannelNotifier when
// a new CIBA authentication request is created. The notifier is responsible
// for delivering an approval prompt to the user out-of-band — push, email,
// SMS, voice, anything — and must not block the request-creation response
// (the service invokes the notifier in a goroutine).
//
// Fields mirror the OpenID CIBA spec's request shape so deployers can pass
// the payload directly to their notification provider without re-mapping.
type BackchannelNotification struct {
	AuthReqID string
	AccountID string
	ProjectID string
	ClientID  string
	LoginHint string
	// GroupHint is the CIBA extension parameter for role/group-targeted
	// approval. zeroid treats the value as opaque; deployers choose
	// their own namespace convention (e.g. "highflame:role:finance_lead",
	// "pd:schedule:P12345"). At least one of {LoginHint, GroupHint} is
	// guaranteed non-empty when this notifier fires — the server-side
	// validator enforces it at bc-authorize time. Empty when the client
	// supplied LoginHint only (the canonical CIBA per-user case).
	GroupHint      string
	Scope          string
	BindingMessage string
	ExpiresAt      time.Time
	// AuthorizationDetails carries the RFC 9396 RAR payload parsed at
	// bc-authorize time. Empty when the client did not supply
	// authorization_details (legacy CIBA flow), or when the payload was
	// rejected by a registered per-type validator (in which case the
	// request was never created and this notifier is not invoked).
	// Notifiers should render typed approval prompts from this field when
	// non-empty; scope and binding_message remain the fallback for clients
	// that have not adopted RAR.
	AuthorizationDetails domain.AuthorizationDetails
}

// BackchannelNotifier delivers a CIBA approval prompt to the end user via an
// out-of-band channel selected by the deployer (push, email, SMS, etc.).
//
// ZeroID ships with no built-in notifier. Set one via Server.SetBackchannelNotifier.
// Returning an error records last_notify_error on the request row for
// debuggability but does not block request creation — the user may approve
// through another channel.
type BackchannelNotifier func(ctx context.Context, n BackchannelNotification) error

// AuthorizationDetailValidator is the deployer-supplied per-type validator
// for RFC 9396 RAR `authorization_details` entries. Registered against a
// specific `type` discriminator via Server.RegisterAuthorizationDetailValidator;
// invoked at bc-authorize time for every element whose `type` field matches.
//
// The validator receives the original JSON bytes of the element (preserving
// key order and any deployer-specific fields beyond `type`). It MUST return
// nil to accept or a descriptive error to reject — a rejection fails the
// entire bc-authorize request with OAuth error `invalid_authorization_details`
// (RFC 9396 §5.4).
//
// The registry is strictly per-`type`: unregistered `type` values pass
// outer-shape validation and are forwarded to the BackchannelNotifier
// with no extra checks. A type-allowlist that REJECTS unknown types is
// not expressible via this hook in the current release — there is no
// catch-all / fallback registration, and the BackchannelNotifier fires
// after the bc-authorize response is sent (an error there records
// `last_notify_error` on the row but does not surface as a 400 to the
// client). Deployers that need strict allow-listing today must front
// zeroid with a thin shim that screens `authorization_details` before
// forwarding. A future release may add a fallback validator hook.
//
// Validators run synchronously on the bc-authorize request path; keep them
// fast (no network I/O, no DB queries beyond in-process caches).
type AuthorizationDetailValidator func(raw json.RawMessage) error

// RevocationEvent is the payload handed to a RevocationNotifier after a
// token or credential has been revoked and the revocation has committed to
// the database. Exactly one event is emitted per revoked JTI — a cascade
// that revokes N credentials (e.g. an identity deactivation that walks the
// delegation tree) fires N events, one per affected credential.
//
// zeroid ships no built-in fan-out for these events: it does not own a
// Redis channel, a message bus, or any deny-set. The embedding application
// sets a RevocationNotifier via
// Server.SetRevocationNotifier and is responsible for whatever propagation
// it needs — publishing to its own Redis channel, writing to a shared
// deny-set, emitting a webhook, etc. This keeps zeroid Redis-agnostic by
// design.
//
// Fields:
//   - JTI is the revoked credential's `jti` claim — the deny-set key the
//     subscriber should block. For refresh-token reuse revocation (which
//     concerns opaque, hashed refresh tokens that carry no JWT id), JTI
//     carries the refresh-token row's UUID instead, so the value is still a
//     stable, unique handle for the revoked artifact.
//   - IdentityID is the owning identity's UUID. Empty when the revoked
//     credential was not tied to a stored identity row (e.g. a synthetic
//     external-principal carrier) or, for refresh tokens, when no identity
//     was linked.
//   - AccountID / ProjectID scope the revocation to a tenant. Subscribers
//     MUST key their deny-set by (account_id, project_id, jti) to preserve
//     multi-tenant isolation.
//   - ExpiresAt is the revoked artifact's own expiry. Subscribers can size
//     their deny-set entry's TTL to this instant: once the token would have
//     expired anyway, the deny-set entry can be dropped because verification
//     fails on `exp` regardless.
//   - Reason mirrors the revoke reason recorded on the row
//     (e.g. "oauth2_revocation", "identity_deactivated",
//     "auto-revoked by CAE signal …", "refresh_token_reuse").
//   - RevokedAt is the wall-clock instant the revocation was applied.
type RevocationEvent struct {
	JTI        string    `json:"jti"`
	IdentityID string    `json:"identity_id"`
	AccountID  string    `json:"account_id"`
	ProjectID  string    `json:"project_id"`
	ExpiresAt  time.Time `json:"exp"`
	Reason     string    `json:"reason"`
	RevokedAt  time.Time `json:"revoked_at"`
}

// RevocationNotifier observes every token/credential revocation so the
// embedding application can fan it out to its own infrastructure (a Redis
// deny-set channel, a webhook, an audit pipeline). zeroid ships with no
// built-in notifier; set one via Server.SetRevocationNotifier.
//
// The notifier fires AFTER the revocation has committed to the database, on
// a detached goroutine, so its latency never blocks the request that caused
// the revocation (RFC 7009 revoke, CAE signal ingest, refresh-token reuse
// detection, identity deactivation). It is invoked exactly once per revoked
// JTI: a cascade revoking N credentials fires N times.
//
// Returning an error is logged (zerolog, warn level) but is NOT propagated
// to the caller — a failed fan-out must never roll back or fail the
// revocation itself, which has already committed. The notifier MUST be
// safe for concurrent invocation and MUST NOT block indefinitely; it runs
// under a bounded-timeout context derived from the server's lifecycle
// context (cancelled on Server.Shutdown).
//
// When no notifier is set (the default), revocation behaviour is unchanged
// — there is no new required configuration and no behavioural difference for
// existing deployers.
type RevocationNotifier func(ctx context.Context, e RevocationEvent) error
