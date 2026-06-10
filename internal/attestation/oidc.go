package attestation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"

	"github.com/highflame-ai/zeroid/domain"
)

// maxDiscoveryDocBytes caps how much of an OIDC discovery response we will
// read and decode. Real-world discovery docs are a few kilobytes; a 1 MiB
// ceiling gives generous headroom while bounding memory a malicious or
// compromised issuer can force this process to allocate during a fetch.
const maxDiscoveryDocBytes = 1 << 20 // 1 MiB

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

	// allowPrivate disables the SSRF blocklist on issuer / jwks_uri hosts.
	// Production default is false: both the discovery GET and the JWKS GET
	// resolve their target host and reject if ANY resolved IP falls in a
	// private / loopback / link-local / metadata / CGN / multicast /
	// unspecified range, re-checked at dial time as DNS-rebinding defence.
	// Set to true ONLY in test/dev contexts that point issuers at loopback
	// (httptest.NewServer, http://localhost:port). See SetAllowPrivate.
	allowPrivate bool
}

// NewOIDCVerifier creates a verifier with a shared JWKS cache. httpClient
// is used for both OIDC discovery and JWKS fetches; passing a custom one
// is useful in tests (httptest.NewServer has no DNS).
//
// SSRF guard: when httpClient is nil, the verifier builds a hardened client
// whose dialer rejects connections to private / reserved IP ranges. When a
// custom client is supplied (tests), the caller owns transport behaviour —
// but the pre-fetch host resolution check in discoverJWKSURL / fetchJWKS
// still applies unless allowPrivate is set via SetAllowPrivate.
//
// allowPrivate defaults to false (production-safe). A tenant-configured
// issuer that resolves to an internal address is rejected before any byte
// leaves this process. To run against loopback fixtures, call
// v.SetAllowPrivate(true) after construction.
func NewOIDCVerifier(httpClient *http.Client) *OIDCVerifier {
	v := &OIDCVerifier{
		cache:    newJWKSCache(),
		cacheTTL: 1 * time.Hour,
	}
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout:   10 * time.Second,
			Transport: ssrfGuardedTransport(func() bool { return v.allowPrivate }),
		}
	}
	v.http = httpClient
	return v
}

// SetAllowPrivate toggles the SSRF blocklist on issuer / jwks_uri hosts.
// It is the seam through which a dev/test deployment opts out of the guard;
// production must leave it false. Returns the verifier for chaining.
//
// Wired from operator config: server.go passes
// cfg.Attestation.AllowPrivateIssuerEndpoints (env
// ZEROID_ATTESTATION_ALLOW_PRIVATE_ISSUER_ENDPOINTS, default false) into both
// this verifier and the PolicyService, so the write-time and verify-time
// guards agree. The guard is on unless an operator explicitly opts out.
func (v *OIDCVerifier) SetAllowPrivate(allow bool) *OIDCVerifier {
	v.allowPrivate = allow
	return v
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
	// jwx v4: Issuer() returns (string, present); empty/missing → reject.
	issuerClaim, _ := peek.Issuer()
	if issuerClaim == "" {
		return nil, fmt.Errorf("oidc verifier: JWT has no iss claim")
	}
	matchedIssuer, ok := findIssuer(cfg.Issuers, issuerClaim)
	if !ok {
		return nil, fmt.Errorf("oidc verifier: issuer not in allowlist: %s", issuerClaim)
	}

	// Step 3: resolve JWKS (cached). The cache fetch path runs the SSRF
	// blocklist on both the issuer host (discovery GET) and the
	// discovery-provided jwks_uri host (JWKS GET) before any network call.
	keySet, err := v.cache.get(ctx, v.http, matchedIssuer.URL, v.cacheTTL, v.allowPrivate)
	if err != nil {
		return nil, fmt.Errorf("oidc verifier: JWKS fetch failed: %w", err)
	}

	// Step 4: verify signature + standard claims. jwt.Parse enforces
	// exp/iat/nbf by default, and the KeySet option requires a matching
	// kid — so a tampered token or one from a foreign signer will fail.
	//
	// Use issuerClaim (not matchedIssuer.URL) for WithIssuer because
	// jwx's WithIssuer does a strict string compare; a trailing-slash
	// mismatch between the configured policy URL and the token's iss
	// claim would reject an otherwise-valid token. The iss claim was
	// already trust-checked by findIssuer (normalized-equality against
	// the allowlist), so feeding it back here is safe.
	tok, err := jwt.Parse(
		[]byte(rawToken),
		jwt.WithKeySet(keySet),
		jwt.WithIssuer(issuerClaim),
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
		// jwx v4: Audience() returns ([]string, present).
		aud, _ := tok.Audience()
		if !anyAudienceMatches(aud, matchedIssuer.Audiences) {
			return nil, fmt.Errorf("oidc verifier: aud claim does not match any configured audience")
		}
	}

	// Step 6: required claims — exact string match on each key. These are
	// the workload-identity binders (e.g. repository, ref for GitHub).
	//
	// jwx v4 removed Token.AsMap; the v4-idiomatic replacement is
	// Token.Claims() — an iter.Seq2[string, any] yielding every claim
	// without per-key error handling.
	allClaims := maps.Collect(tok.Claims())
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

	// jwx v4: Expiration / Subject / Issuer all return (value, present).
	var expiresAt *time.Time
	if exp, ok := tok.Expiration(); ok && !exp.IsZero() {
		e := exp
		expiresAt = &e
	}
	sub, _ := tok.Subject()
	iss, _ := tok.Issuer()

	return &Result{
		Subject:   sub,
		Issuer:    iss,
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

// jwksCache is a per-issuer in-memory JWKS cache. Each issuer entry carries
// its own mutex so a cold-cache miss on issuer A doesn't block lookups for
// issuer B. Concurrent misses on the SAME issuer coalesce via the entry
// mutex — one fetch, everyone else waits for it to populate.
type jwksCache struct {
	mu      sync.Mutex // protects the entries map only, not the fetch
	entries map[string]*jwksEntry
}

type jwksEntry struct {
	mu        sync.Mutex // held during fetch; released when keys is populated
	keys      jwk.Set
	expiresAt time.Time
}

func newJWKSCache() *jwksCache {
	return &jwksCache{entries: make(map[string]*jwksEntry)}
}

// get returns a cached key set for issuerURL, refreshing via OIDC discovery
// when the entry is absent or stale. The two-phase locking pattern (map
// mutex for entry lookup, then entry mutex for fetch) ensures cross-issuer
// lookups don't serialize on a single slow upstream.
func (c *jwksCache) get(ctx context.Context, httpClient *http.Client, issuerURL string, ttl time.Duration, allowPrivate bool) (jwk.Set, error) {
	c.mu.Lock()
	entry, ok := c.entries[issuerURL]
	if !ok {
		entry = &jwksEntry{}
		c.entries[issuerURL] = entry
	}
	c.mu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()

	if entry.keys != nil && time.Now().Before(entry.expiresAt) {
		return entry.keys, nil
	}

	jwksURL, err := discoverJWKSURL(ctx, httpClient, issuerURL, allowPrivate)
	if err != nil {
		return nil, err
	}
	// jwx v4 moved jwk.Fetch / jwk.WithHTTPClient out into a separate
	// jwx-go/jwkfetch module. Rather than pull in a companion dep just for
	// a single GET, fetch the JWKS bytes ourselves and let jwk.Parse turn
	// them into a Set. Bound the body at maxDiscoveryDocBytes for the same
	// reason we do on the discovery endpoint — defend against an issuer
	// streaming attacker-chosen volumes into our process.
	keySet, err := fetchJWKS(ctx, httpClient, jwksURL, allowPrivate)
	if err != nil {
		return nil, err
	}

	entry.keys = keySet
	entry.expiresAt = time.Now().Add(ttl)
	return keySet, nil
}

// fetchJWKS performs a bounded HTTP GET against jwksURL and parses the
// response as a jwk.Set. Replaces the v2 jwk.Fetch helper that v4 removed.
func fetchJWKS(ctx context.Context, httpClient *http.Client, jwksURL string, allowPrivate bool) (jwk.Set, error) {
	// SSRF guard: the jwks_uri came from the (untrusted) discovery document
	// and may point at a different host than the issuer — resolve and block
	// internal targets before connecting. Re-checked at dial time too.
	if err := assertURLHostAllowed(ctx, jwksURL, allowPrivate); err != nil {
		return nil, fmt.Errorf("jwks_uri %s: %w", jwksURL, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build JWKS request: %w", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS %s: %w", jwksURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS fetch %s returned %d", jwksURL, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDiscoveryDocBytes))
	if err != nil {
		return nil, fmt.Errorf("read JWKS body from %s: %w", jwksURL, err)
	}
	keySet, err := jwk.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("parse JWKS %s: %w", jwksURL, err)
	}
	return keySet, nil
}

// discoverJWKSURL pulls the jwks_uri out of the issuer's OIDC discovery
// document. Issuers that don't serve /.well-known/openid-configuration are
// not supported by this verifier — they'd need a dedicated pinned-keys
// verifier, which can be added later if a concrete tenant needs it.
//
// Per RFC 8414 §3.3, the issuer field in the discovery document MUST match
// the issuer URL used to fetch it — otherwise a DNS-hijacked or MITM'd
// discovery endpoint could redirect jwks_uri at attacker-controlled keys
// while pretending to serve the trusted issuer's metadata.
func discoverJWKSURL(ctx context.Context, httpClient *http.Client, issuerURL string, allowPrivate bool) (string, error) {
	discoveryURL := strings.TrimRight(issuerURL, "/") + "/.well-known/openid-configuration"
	// SSRF guard: resolve the issuer host and block internal targets before
	// the discovery GET. A tenant with policy-write access could otherwise
	// point the issuer at 169.254.169.254 (cloud metadata) or an RFC 1918
	// service for blind SSRF / port probing. Re-checked at dial time too.
	if err := assertURLHostAllowed(ctx, discoveryURL, allowPrivate); err != nil {
		return "", fmt.Errorf("issuer %s: %w", issuerURL, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return "", fmt.Errorf("build discovery request: %w", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("discovery GET %s: %w", discoveryURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("discovery %s returned %d", discoveryURL, resp.StatusCode)
	}
	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	// Bound the decode at maxDiscoveryDocBytes. Without the limit a
	// malicious issuer could stream gigabytes into json.Decode, exhausting
	// memory before we ever inspected a byte.
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxDiscoveryDocBytes)).Decode(&doc); err != nil {
		return "", fmt.Errorf("parse discovery doc: %w", err)
	}
	if doc.JWKSURI == "" {
		return "", fmt.Errorf("discovery doc at %s has no jwks_uri", discoveryURL)
	}
	// RFC 8414 §3.3: the discovery doc's issuer field MUST match the URL
	// we used to fetch it. Trailing slashes are insignificant (same
	// normalisation as findIssuer).
	want := strings.TrimRight(issuerURL, "/")
	got := strings.TrimRight(doc.Issuer, "/")
	if got != want {
		return "", fmt.Errorf("discovery doc issuer mismatch: got %q, want %q", doc.Issuer, issuerURL)
	}
	return doc.JWKSURI, nil
}

// ── SSRF guard ────────────────────────────────────────────────────────────
//
// OIDC issuer URLs and the jwks_uri inside their discovery documents are
// tenant-controlled and fetched server-side at verify time. Without a guard,
// a tenant with policy-write access (or a stolen admin token) could point an
// issuer at 169.254.169.254 (cloud metadata), an RFC 1918 service, or any
// internal port — turning /attestation/verify into a blind-SSRF / internal
// port-probe primitive. The discovery-provided jwks_uri can also redirect the
// second fetch to a different internal host.
//
// Defence (mirrors the CIBA notification guard in internal/service):
//  1. Before each GET, resolve the target host and reject if ANY resolved IP
//     is in a blocked range (DNS-rebinding defence — a hostname mixing public
//     and private answers is treated as hostile).
//  2. The default HTTP client's dialer re-checks the actually-dialed IP, so a
//     hostname that flips its answer between the pre-flight resolve and the
//     dial (TOCTOU rebind) is still refused at connect time.

// dnsLookupTimeout caps each resolve so a slow/hanging DNS server cannot stall
// a verify call indefinitely. Well above typical resolver latency.
const dnsLookupTimeout = 2 * time.Second

// ErrPrivateAttestationEndpoint is the sentinel returned when an issuer or
// jwks_uri host resolves to a private / loopback / link-local / metadata /
// CGN / multicast / unspecified address. Callers can errors.Is on it. The
// error deliberately does NOT echo the resolved IP — leaking our internal DNS
// view is not a useful diagnostic and could expose split-horizon topology.
var ErrPrivateAttestationEndpoint = errors.New("attestation issuer/jwks_uri resolves to a private or reserved address")

// assertURLHostAllowed parses rawURL and runs the SSRF blocklist on its host.
// allowPrivate short-circuits the check for dev/test (loopback fixtures).
func assertURLHostAllowed(ctx context.Context, rawURL string, allowPrivate bool) error {
	if allowPrivate {
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("malformed URL: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("URL has no host")
	}
	return resolveAndCheckHost(ctx, host)
}

// resolveAndCheckHost performs a timeout-bounded DNS lookup for host and
// rejects if ANY returned IP is blocked. Pure-IP hosts resolve to a single
// literal entry, so direct IP-as-host issuers (https://10.0.0.5/) are covered.
func resolveAndCheckHost(ctx context.Context, host string) error {
	lookupCtx, cancel := context.WithTimeout(ctx, dnsLookupTimeout)
	defer cancel()
	ips, err := lookupIPs(lookupCtx, host)
	if err != nil {
		return fmt.Errorf("host %q does not resolve: %w", host, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("host %q returned no IPs", host)
	}
	for _, ip := range ips {
		if isBlockedIP(ip) {
			return ErrPrivateAttestationEndpoint
		}
	}
	return nil
}

// lookupIPs is a package-level var so tests can inject a stubbed resolver
// without touching real DNS. Production uses LookupIPAddr which honours the
// supplied context (net.LookupIP does not), so dnsLookupTimeout actually binds.
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

// ssrfGuardedTransport wraps http.DefaultTransport with a dialer that rejects
// any connection whose resolved IP is blocked. allowPrivate is read through a
// func so the verifier's flag can be flipped after the transport is built.
// This is the dial-time half of the DNS-rebinding defence.
func ssrfGuardedTransport(allowPrivate func() bool) *http.Transport {
	base := http.DefaultTransport.(*http.Transport).Clone()
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	base.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if allowPrivate() {
			return dialer.DialContext(ctx, network, addr)
		}
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			host, port = addr, ""
		}
		// IP-literal host: validate and dial it directly.
		if ip := net.ParseIP(host); ip != nil {
			if isBlockedIP(ip) {
				return nil, ErrPrivateAttestationEndpoint
			}
			return dialer.DialContext(ctx, network, addr)
		}
		// Hostname: resolve ONCE, validate every answer, then dial a
		// validated IP literal — not the hostname — so the kernel connects to
		// exactly the address we checked. Re-resolving and dialing the
		// hostname again (letting net.Dialer resolve a third time) would leave
		// a DNS-rebinding window between the check and the connect; pinning the
		// dial to the validated IP closes it. TLS still verifies against the
		// original hostname because the Transport sets ServerName from the URL,
		// not from the dial address.
		ips, err := lookupIPs(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("attestation issuer host resolution failed: %w", err)
		}
		if len(ips) == 0 {
			return nil, ErrPrivateAttestationEndpoint
		}
		for _, ip := range ips {
			if isBlockedIP(ip) {
				return nil, ErrPrivateAttestationEndpoint
			}
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
	}
	return base
}

// isBlockedIP returns true for any IP that must never be a verify-time fetch
// target. Mirrors the CIBA notification guard's blocklist:
//
// Via stdlib helpers:
//   - RFC 1918 IPv4 private + RFC 4193 IPv6 ULA (fc00::/7, incl. Azure IMDS
//     fd00:ec2::254) — net.IP.IsPrivate
//   - Loopback (127/8, ::1) — net.IP.IsLoopback
//   - Link-local unicast (169.254/16, fe80::/10, incl. AWS/GCP IMDS
//     169.254.169.254) — net.IP.IsLinkLocalUnicast
//   - Multicast (224/4, ff00::/8) — net.IP.IsMulticast
//   - Unspecified (0.0.0.0, ::) — net.IP.IsUnspecified
//
// Manual ranges not exposed by stdlib:
//   - RFC 1122 "this network" (0.0.0.0/8)
//   - RFC 6598 Carrier-Grade NAT (100.64.0.0/10)
//   - RFC 5737 documentation (192.0.2/24, 198.51.100/24, 203.0.113/24)
//   - RFC 2544 benchmarking (198.18.0.0/15)
//   - RFC 1112 / RFC 6890 reserved (240.0.0.0/4)
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
		// RFC 1112 / RFC 6890 reserved: 240.0.0.0/4
		return true
	}
	return false
}
