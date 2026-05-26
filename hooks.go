package zeroid

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/highflame-ai/zeroid/domain"
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
}

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
	AuthReqID      string
	AccountID      string
	ProjectID      string
	ClientID       string
	LoginHint      string
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
