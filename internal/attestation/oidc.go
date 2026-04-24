package attestation

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/highflame-ai/zeroid/domain"
)

// OIDCVerifier verifies JWTs issued by upstream OIDC providers (GitHub
// Actions, GCP Workload Identity, Kubernetes projected SA tokens, AWS IAM
// OIDC, etc.) against a tenant-configured issuer allowlist. It is the
// default workload-attestation verifier: every major agent runtime ships
// an OIDC token issuer, so this one verifier covers the realistic deployment
// shapes without per-provider code.
//
// Verification flow:
//  1. Parse JWT header without verifying to read the iss claim.
//  2. Match iss against the tenant's OIDCPolicyConfig.Issuers allowlist.
//     Unknown issuers fail here — no JWKS fetch, no network call.
//  3. Fetch JWKS for the matched issuer (cached per-issuer for 1h) via
//     OIDC discovery (.well-known/openid-configuration → jwks_uri).
//  4. Verify the JWT signature and standard time claims (exp/iat/nbf).
//  5. Enforce audience constraint if Audiences is non-empty.
//  6. Enforce RequiredClaims exact-string-match on each listed claim.
type OIDCVerifier struct {
	cache    *jwksCache
	http     *http.Client
	cacheTTL time.Duration
}

// NewOIDCVerifier creates a verifier with a shared JWKS cache. httpClient
// is used for both OIDC discovery and JWKS fetches; passing a custom one
// is useful in tests (httptest.NewServer has no DNS).
func NewOIDCVerifier(httpClient *http.Client) *OIDCVerifier {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &OIDCVerifier{
		cache:    newJWKSCache(),
		http:     httpClient,
		cacheTTL: 1 * time.Hour,
	}
}

// ProofType reports oidc_token. One OIDCVerifier per registry.
func (v *OIDCVerifier) ProofType() domain.ProofType { return domain.ProofTypeOIDCToken }

// Verify implements the full OIDC flow described on OIDCVerifier.
func (v *OIDCVerifier) Verify(ctx context.Context, record *domain.AttestationRecord, policyConfig []byte) (*Result, error) {
	if len(policyConfig) == 0 {
		return nil, fmt.Errorf("oidc verifier: policy config is empty")
	}
	var cfg domain.OIDCPolicyConfig
	if err := json.Unmarshal(policyConfig, &cfg); err != nil {
		return nil, fmt.Errorf("oidc verifier: invalid policy config: %w", err)
	}
	if len(cfg.Issuers) == 0 {
		return nil, fmt.Errorf("oidc verifier: policy has no trusted issuers configured")
	}

	rawToken := strings.TrimSpace(record.ProofValue)
	if rawToken == "" {
		return nil, fmt.Errorf("oidc verifier: empty proof value")
	}

	// Step 1–2: peek at the token's iss claim to pick the matching issuer
	// config. ParseInsecure skips signature verification — safe because we
	// treat the result as untrusted until step 4 runs the real check.
	peek, err := jwt.ParseInsecure([]byte(rawToken))
	if err != nil {
		return nil, fmt.Errorf("oidc verifier: malformed JWT: %w", err)
	}
	issuerClaim := peek.Issuer()
	if issuerClaim == "" {
		return nil, fmt.Errorf("oidc verifier: JWT has no iss claim")
	}
	matchedIssuer, ok := findIssuer(cfg.Issuers, issuerClaim)
	if !ok {
		return nil, fmt.Errorf("oidc verifier: issuer not in allowlist: %s", issuerClaim)
	}

	// Step 3: resolve JWKS (cached).
	keySet, err := v.cache.get(ctx, v.http, matchedIssuer.URL, v.cacheTTL)
	if err != nil {
		return nil, fmt.Errorf("oidc verifier: JWKS fetch failed: %w", err)
	}

	// Step 4: verify signature + standard claims. jwt.Parse enforces
	// exp/iat/nbf by default, and the KeySet option requires a matching
	// kid — so a tampered token or one from a foreign signer will fail.
	tok, err := jwt.Parse(
		[]byte(rawToken),
		jwt.WithKeySet(keySet),
		jwt.WithIssuer(matchedIssuer.URL),
		jwt.WithValidate(true),
		jwt.WithAcceptableSkew(30*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("oidc verifier: token validation failed: %w", err)
	}

	// Step 5: audience. jwx's WithAudience rejects the token unless the
	// aud claim contains the given string — we OR across configured
	// audiences by trying each. Empty audiences means no audience check.
	if len(matchedIssuer.Audiences) > 0 {
		if !anyAudienceMatches(tok.Audience(), matchedIssuer.Audiences) {
			return nil, fmt.Errorf("oidc verifier: aud claim does not match any configured audience")
		}
	}

	// Step 6: required claims — exact string match on each key. These are
	// the workload-identity binders (e.g. repository, ref for GitHub).
	allClaims, err := tok.AsMap(ctx)
	if err != nil {
		return nil, fmt.Errorf("oidc verifier: unable to read token claims: %w", err)
	}
	for wantKey, wantVal := range matchedIssuer.RequiredClaims {
		got, ok := allClaims[wantKey]
		if !ok {
			return nil, fmt.Errorf("oidc verifier: required claim missing: %s", wantKey)
		}
		gotStr, ok := got.(string)
		if !ok || gotStr != wantVal {
			return nil, fmt.Errorf("oidc verifier: required claim mismatch: %s", wantKey)
		}
	}

	var expiresAt *time.Time
	if exp := tok.Expiration(); !exp.IsZero() {
		e := exp
		expiresAt = &e
	}

	return &Result{
		Subject:   tok.Subject(),
		Issuer:    tok.Issuer(),
		ExpiresAt: expiresAt,
		Claims:    allClaims,
	}, nil
}

// findIssuer returns the config entry whose URL matches issuerClaim. The
// match is exact after trimming trailing slashes — OIDC discovery treats
// "https://x" and "https://x/" as the same issuer, and we follow suit so
// mild config typos don't lock clients out.
func findIssuer(configured []domain.OIDCIssuerConfig, issuerClaim string) (domain.OIDCIssuerConfig, bool) {
	norm := strings.TrimRight(issuerClaim, "/")
	for _, c := range configured {
		if strings.TrimRight(c.URL, "/") == norm {
			return c, true
		}
	}
	return domain.OIDCIssuerConfig{}, false
}

// anyAudienceMatches reports whether any element of got is present in want.
func anyAudienceMatches(got, want []string) bool {
	wantSet := make(map[string]struct{}, len(want))
	for _, w := range want {
		wantSet[w] = struct{}{}
	}
	for _, g := range got {
		if _, ok := wantSet[g]; ok {
			return true
		}
	}
	return false
}

// jwksCache is a tiny per-issuer in-memory JWKS cache. It coalesces misses
// so a burst of verification requests doesn't fan out into multiple JWKS
// HTTP calls for the same issuer.
type jwksCache struct {
	mu      sync.Mutex
	entries map[string]*jwksEntry
}

type jwksEntry struct {
	keys      jwk.Set
	expiresAt time.Time
}

func newJWKSCache() *jwksCache {
	return &jwksCache{entries: make(map[string]*jwksEntry)}
}

// get returns a cached key set for issuerURL, refreshing via OIDC discovery
// when the entry is absent or stale.
func (c *jwksCache) get(ctx context.Context, httpClient *http.Client, issuerURL string, ttl time.Duration) (jwk.Set, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if e, ok := c.entries[issuerURL]; ok && time.Now().Before(e.expiresAt) {
		return e.keys, nil
	}

	jwksURL, err := discoverJWKSURL(ctx, httpClient, issuerURL)
	if err != nil {
		return nil, err
	}
	keySet, err := jwk.Fetch(ctx, jwksURL, jwk.WithHTTPClient(httpClient))
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS %s: %w", jwksURL, err)
	}

	c.entries[issuerURL] = &jwksEntry{keys: keySet, expiresAt: time.Now().Add(ttl)}
	return keySet, nil
}

// discoverJWKSURL pulls the jwks_uri out of the issuer's OIDC discovery
// document. Issuers that don't serve /.well-known/openid-configuration are
// not supported by this verifier — they'd need a dedicated pinned-keys
// verifier, which can be added later if a concrete tenant needs it.
func discoverJWKSURL(ctx context.Context, httpClient *http.Client, issuerURL string) (string, error) {
	url := strings.TrimRight(issuerURL, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("build discovery request: %w", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("discovery GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("discovery %s returned %d", url, resp.StatusCode)
	}
	var doc struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", fmt.Errorf("parse discovery doc: %w", err)
	}
	if doc.JWKSURI == "" {
		return "", fmt.Errorf("discovery doc at %s has no jwks_uri", url)
	}
	return doc.JWKSURI, nil
}
