package service

import (
	"context"
	"fmt"
	"sync"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/attestation"
	"github.com/highflame-ai/zeroid/pkg/authjwt"
)

// ExternalIssuerEntry pairs a configured external IdP with its live JWKS
// client. The registry owns the client's lifecycle — it is created on
// NewExternalIssuerRegistry and shut down on Close.
type ExternalIssuerEntry struct {
	Config domain.ExternalIssuerConfig
	JWKS   *authjwt.JWKSClient
}

// ExternalIssuerRegistry resolves a token's iss claim to a configured
// upstream IdP and holds a cached JWKS for it. Lookup is read-only after
// construction; the JWKS clients themselves refresh in the background.
//
// The registry is intentionally separate from OAuthService so that a deployer
// can construct it with custom HTTP clients (proxies, mTLS) before wiring it
// into the server.
type ExternalIssuerRegistry struct {
	mu      sync.RWMutex
	byIss   map[string]*ExternalIssuerEntry
	closers []func()
}

// NewExternalIssuerRegistry builds a registry from validated config. Each
// entry's JWKS client warms up best-effort: authjwt.NewJWKSClient does an
// initial fetch but deliberately does NOT fail on an unreachable JWKS — it
// logs a warning and relies on background refresh plus a synchronous
// EnsureLoaded on the first verification (externalIDTokenExchange calls it).
// This keeps ZeroID startup resilient to a transient external-IdP outage;
// a genuinely unreachable issuer fails closed at token-exchange time rather
// than blocking boot. Only config-level errors (e.g. empty jwks_uri) fail
// here. Entries are created in order; partial failure closes whatever
// clients were already created and returns the failing issuer's error.
func NewExternalIssuerRegistry(ctx context.Context, configs []domain.ExternalIssuerConfig, opts ...authjwt.JWKSOption) (*ExternalIssuerRegistry, error) {
	_ = ctx // reserved for future use; current authjwt.NewJWKSClient does its own fetch context
	r := &ExternalIssuerRegistry{
		byIss: make(map[string]*ExternalIssuerEntry, len(configs)),
	}
	for _, cfg := range configs {
		// SSRF-guarded HTTP client for the JWKS fetch: reject a jwks_uri host
		// that resolves to a private/loopback/metadata address unless the
		// issuer opted in (AllowPrivateEndpoints) for an internal IdP. Reuses
		// the audited guard the attestation OIDC verifier uses (issue #198).
		// Listed first so a deployer/test can still override the HTTP client
		// via opts (WithExternalIssuerJWKSOption) — the last WithHTTPClient
		// wins. Then the per-issuer refresh interval overrides the package
		// default; caller-supplied opts follow so they can override anything.
		issuerOpts := append([]authjwt.JWKSOption{
			authjwt.WithHTTPClient(attestation.NewSSRFGuardedHTTPClient(cfg.AllowPrivateEndpoints)),
			authjwt.WithRefreshInterval(cfg.JWKSCacheTTL),
		}, opts...)
		client, err := authjwt.NewJWKSClient(cfg.JWKSURI, issuerOpts...)
		if err != nil {
			r.Close()
			return nil, fmt.Errorf("external issuer %s: %w", cfg.Issuer, err)
		}
		entry := &ExternalIssuerEntry{Config: cfg, JWKS: client}
		r.byIss[cfg.Issuer] = entry
		r.closers = append(r.closers, client.Close)
	}
	return r, nil
}

// Lookup returns the entry registered for the given upstream iss, or nil if
// the issuer is not configured. Safe for concurrent use.
func (r *ExternalIssuerRegistry) Lookup(iss string) *ExternalIssuerEntry {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byIss[iss]
}

// HasAny reports whether any external issuer is configured. The OAuth service
// uses this to short-circuit dispatch when the deployer has not opted into
// direct federation.
func (r *ExternalIssuerRegistry) HasAny() bool {
	if r == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byIss) > 0
}

// Close stops every background JWKS refresh goroutine. Idempotent.
func (r *ExternalIssuerRegistry) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	closers := r.closers
	r.closers = nil
	r.mu.Unlock()
	for _, c := range closers {
		c()
	}
}
