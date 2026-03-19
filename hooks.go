package zeroid

import (
	"context"
	"net/http"

	"github.com/highflame-ai/zeroid/domain"
)

// ClaimsEnricher is called during JWT issuance to add custom claims.
// The claims map already contains standard ZeroID claims; the enricher may add or override entries.
type ClaimsEnricher func(claims map[string]any, identity *domain.Identity, grantType domain.GrantType)

// GrantHandler implements a custom OAuth2 grant type.
// Return a non-nil AccessToken on success. Returning an error causes a 400 response.
type GrantHandler func(ctx context.Context, req map[string]string) (*domain.AccessToken, error)

// AdminAuthMiddleware is an optional middleware applied to the admin API router.
// When set, every request to the admin port passes through this middleware before
// reaching any handler. Use this to add authentication (Bearer JWT, mTLS, API key,
// or any custom scheme) when embedding ZeroID as a library.
//
// When nil (the default), the admin API has no authentication — protect it at the
// network layer (VPN, service mesh, localhost-only binding, firewall rules).
type AdminAuthMiddleware func(next http.Handler) http.Handler

// TrustedServiceValidator checks whether the current request comes from a trusted
// internal service that is allowed to perform external principal token exchange
// (RFC 8693). Implementations read from context (set by deployer-provided global
// middleware) and return the service name on success, or an error to reject.
//
// Set via Server.TrustedServiceValidator() after NewServer.
type TrustedServiceValidator func(ctx context.Context) (serviceName string, err error)
