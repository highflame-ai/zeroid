package zeroid

import (
	"context"
	"encoding/json"
	"net/http"

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
}

// TrustedServiceValidator checks whether the current request comes from a trusted
// internal service that is allowed to perform external principal token exchange
// (RFC 8693). Implementations read from context (set by deployer-provided global
// middleware) and return the service name on success, or an error to reject.
//
// Set via Server.TrustedServiceValidator() after NewServer.
type TrustedServiceValidator func(ctx context.Context) (serviceName string, err error)
