package service

// Client ID Metadata Documents (CIMD) —
// draft-ietf-oauth-client-id-metadata-document.
//
// CIMD lets an OAuth client onboard with ZERO pre-registration by using an
// HTTPS URL as its `client_id`. Instead of storing client metadata in the
// authorization server's database (pre-registration or RFC 7591 dynamic
// registration), the client self-publishes a JSON metadata document at a
// stable URL it controls. When ZeroID sees a `client_id` shaped like an
// https:// URL on the authorization_code flow, it fetches that document,
// validates it came from — and describes — the claimed URL, and treats it as
// an ephemeral PUBLIC PKCE client.
//
// The trust model shifts from "central authority database" to "domain
// ownership verified through TLS + DNS": the redirect_uris array in the
// document is the primary defence against client_id theft (an attacker who
// steals a client_id cannot redirect the authorization code to their own
// domain, because their domain won't appear in the legitimate document's
// redirect_uris). This is the MCP Authorization 2025-11-25 preferred default
// for open agent ecosystems.
//
// Scope of this implementation (v1):
//   - PUBLIC clients only: token_endpoint_auth_method MUST be "none" (PKCE is
//     the proof of possession). Confidential CIMD clients (private_key_jwt with
//     a published jwks_uri) are future work — ZeroID does not yet accept
//     private_key_jwt token-endpoint auth for any client.
//   - authorization_code (+ optional refresh_token) grants only.
//   - Synthesized clients are NEVER persisted — they live only for the request
//     that resolves them, plus a short in-memory cache.
//
// Security posture mirrors the rest of ZeroID's outbound-fetch surface (CIBA
// notification dispatch, OIDC attestation): the fetch runs through an
// SSRF-guarded HTTP client (private/loopback/link-local/metadata ranges are
// blocked with a DNS-rebinding-safe dialer), the response is size-capped, and
// the request is timeout-bounded.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
)

// CIMD defaults. Values are drawn from the draft / MCP guidance:
//   - 5 KiB document cap — a CIMD document is a handful of small string fields;
//     anything larger is either hostile or misconfigured.
//   - 1 hour default cache TTL, hard-capped at 24 h. The draft lets an AS cap
//     the cache lifetime at 24 h regardless of the document's Cache-Control.
//   - 5 second fetch timeout — server-to-server fetch of a tiny JSON doc.
const (
	defaultCIMDMaxDocumentBytes int64 = 5 * 1024
	defaultCIMDCacheTTL               = time.Hour
	maxCIMDCacheTTL                   = 24 * time.Hour
	cimdFetchTimeout                  = 5 * time.Second

	// cimdNegativeCacheTTL is how long a FAILED validation (invalid document,
	// self-reference mismatch) is remembered. Short — a client fixing its
	// document shouldn't wait long — but enough that a hostile caller replaying
	// the same dead URL cannot force revalidation work per request. Validation
	// failures are deterministic, so a longer TTL costs a healthy client nothing.
	cimdNegativeCacheTTL = time.Minute

	// cimdTransientNegativeCacheTTL is the negative-cache TTL for FETCH
	// failures (network error, timeout, non-200). These are transient: a
	// single origin blip during a refresh_token call must not lock a healthy
	// client out for a full minute after the origin recovers. 10s still caps
	// hostile replays of a dead URL at one 5s-timeout outbound fetch per 10s.
	cimdTransientNegativeCacheTTL = 10 * time.Second

	// cimdPositiveCacheFloor is the minimum positive-cache TTL even when the
	// document's Cache-Control asks for less (max-age=0, no-store): honoring
	// zero would let a document force a fresh outbound fetch on every request.
	cimdPositiveCacheFloor = time.Minute

	// maxCIMDCacheEntries bounds the resolution cache. Entries are evicted
	// lazily on same-key access and swept at insert time when the cap is hit,
	// so a caller cycling through many distinct URLs cannot grow the map
	// without bound.
	maxCIMDCacheEntries = 1000

	// maxCIMDClientIDLength caps the client_id URL length. The auth-code and
	// CIBA schemas store client_id in VARCHAR(255) columns; a longer CIMD URL
	// would surface as a DB error (500) deep in the exchange path instead of a
	// clean 400 here. 255 is far above any reasonable metadata-document URL.
	maxCIMDClientIDLength = 255

	// cimdRegistrationSource marks synthesized CIMD clients so logs and any
	// downstream code can distinguish them from "internal" (admin) and
	// "dynamic" (RFC 7591) clients. Kept out of the DB — CIMD clients are
	// never persisted.
	cimdRegistrationSource = domain.RegistrationSourceCIMD
)

// CIMD error sentinels. Callers wrap these into RFC 6749 §5.2 OAuth errors via
// cimdOAuthError so the /oauth2/authorize and /oauth2/token responses carry the
// right code + HTTP status without leaking fetch internals to the client.
var (
	// ErrCIMDDisabled — CIMD resolution was attempted but the feature is off.
	ErrCIMDDisabled = errors.New("client id metadata documents are not enabled")
	// ErrCIMDInvalidClientID — the client_id is not a well-formed CIMD URL
	// (not https, no host/path, or carries a query string or fragment).
	ErrCIMDInvalidClientID = errors.New("client_id is not a valid metadata document URL")
	// ErrCIMDDomainNotAllowed — the client_id host is not in the configured
	// allowed_domains allowlist (only meaningful when the allowlist is set).
	ErrCIMDDomainNotAllowed = errors.New("client_id host is not in the CIMD allowed_domains list")
	// ErrCIMDFetch — the document could not be retrieved (network error,
	// non-200 status, SSRF-guard rejection, timeout).
	ErrCIMDFetch = errors.New("failed to fetch client id metadata document")
	// ErrCIMDInvalidDocument — the document was retrieved but failed validation
	// (bad JSON, self-reference mismatch, missing/forbidden fields, oversize).
	ErrCIMDInvalidDocument = errors.New("client id metadata document is invalid")
)

// cimdMetadataDocument is the subset of the CIMD / RFC 7591 client metadata we
// consume. Unknown fields are ignored (forward-compatible). logo_uri / client_uri
// are accepted for spec-completeness but not acted on in v1.
type cimdMetadataDocument struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name"`
	ClientURI               string   `json:"client_uri"`
	LogoURI                 string   `json:"logo_uri"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	Scope                   string   `json:"scope"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

// cimdAllowedGrantTypes is the grant-type allow-list for CIMD clients. CIMD is
// the interactive-onboarding path, so authorization_code (and its refresh
// companion) are the only sensible grants — client_credentials / token-exchange
// clients register through the admin or RFC 7591 path instead.
var cimdAllowedGrantTypes = map[string]bool{
	string(domain.GrantTypeAuthorizationCode): true,
	string(domain.GrantTypeRefreshToken):      true,
}

// cimdCacheEntry memoizes one resolution outcome — a synthesized client on
// success, the resolution error on failure (negative caching, short TTL).
// Exactly one of client / err is set.
type cimdCacheEntry struct {
	client    *domain.OAuthClient
	err       error
	expiresAt time.Time
}

// CIMDService resolves CIMD client_id URLs into ephemeral public OAuth clients.
//
// A nil *CIMDService is a valid "disabled" instance: Enabled() reports false
// and the auth-code flow falls back to the registry. This lets tests construct
// an OAuthService without wiring CIMD.
type CIMDService struct {
	httpClient       *http.Client
	enabled          bool
	allowedDomains   map[string]struct{} // lower-cased host set; empty ⇒ any host
	maxDocumentBytes int64
	cacheTTL         time.Duration

	mu    sync.Mutex
	cache map[string]cimdCacheEntry

	// flights collapses concurrent resolutions of the SAME client_id into one
	// outbound fetch. The cache only helps once a fetch has COMPLETED; until
	// then every arriving request was a miss and started its own fetch, so N
	// simultaneous first-time requests for one client_id meant N DNS
	// resolutions, N TLS handshakes, and N × up-to-5s of request occupancy for
	// a document that is identical every time.
	//
	// That is the amplification an unauthenticated endpoint should not offer:
	// client resolution runs BEFORE the principal chain, so no credential is
	// needed to trigger it, and concurrency was free to the caller.
	//
	// This bounds duplicate work per client_id. It does NOT bound distinct-URL
	// abuse — a caller cycling unique paths gets a fresh flight each time, and
	// walks past negative caching too. Only an edge rate limit closes that;
	// see the "Fetch abuse" note in docs/cimd.md.
	flights singleflight.Group
	// maxCacheEntries is maxCIMDCacheEntries in production; overridable in
	// tests to exercise eviction without inserting a thousand entries.
	maxCacheEntries int

	// now is injectable so tests can drive cache expiry deterministically.
	now func() time.Time
}

// CIMDConfig configures a CIMDService.
type CIMDConfig struct {
	// Enabled turns CIMD resolution on. When false, ResolveClient returns
	// ErrCIMDDisabled and the auth-code flow uses only the client registry.
	Enabled bool
	// AllowedDomains, when non-empty, restricts CIMD to client_id URLs whose
	// host is in this set (exact, case-insensitive). Empty ⇒ any public HTTPS
	// host (still SSRF-guarded).
	AllowedDomains []string
	// MaxDocumentBytes caps the fetched document size. <= 0 ⇒ default (5 KiB).
	MaxDocumentBytes int64
	// CacheTTL is how long a resolved client is cached. <= 0 ⇒ default (1 h);
	// values above 24 h are clamped to 24 h.
	CacheTTL time.Duration
	// HTTPClient is the (SSRF-guarded) client used to fetch documents. Required
	// in production; nil falls back to a plain timeout-only client (tests).
	HTTPClient *http.Client
}

// NewCIMDService builds a CIMDService from cfg, applying defaults + clamps.
func NewCIMDService(cfg CIMDConfig) *CIMDService {
	maxBytes := cfg.MaxDocumentBytes
	if maxBytes <= 0 {
		maxBytes = defaultCIMDMaxDocumentBytes
	}
	ttl := cfg.CacheTTL
	if ttl <= 0 {
		ttl = defaultCIMDCacheTTL
	}
	if ttl > maxCIMDCacheTTL {
		ttl = maxCIMDCacheTTL
	}
	allowed := make(map[string]struct{}, len(cfg.AllowedDomains))
	for _, d := range cfg.AllowedDomains {
		if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
			allowed[d] = struct{}{}
		}
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: cimdFetchTimeout}
	}
	// Never follow redirects: the client_id is a canonical document location,
	// and a 3xx would let the effective fetch target drift from the URL every
	// validation (domain allowlist, self-reference) anchors to. A shallow copy
	// keeps the caller's client (shared SSRF-guarded transport) unmutated.
	// ErrUseLastResponse makes Do return the 3xx itself, which the fetch path
	// rejects as a non-200.
	hcCopy := *hc
	hcCopy.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &CIMDService{
		httpClient:       &hcCopy,
		enabled:          cfg.Enabled,
		allowedDomains:   allowed,
		maxDocumentBytes: maxBytes,
		cacheTTL:         ttl,
		cache:            make(map[string]cimdCacheEntry),
		maxCacheEntries:  maxCIMDCacheEntries,
		now:              time.Now,
	}
}

// Enabled reports whether CIMD resolution is active. Safe on a nil receiver.
func (s *CIMDService) Enabled() bool {
	return s != nil && s.enabled
}

// AllowedDomainCount reports how many domains are in the EFFECTIVE allow-list,
// after the constructor has lower-cased and dropped blank/whitespace-only
// entries. Zero means open mode: domainAllowed admits any host.
//
// Callers reporting or gating on allow-list policy must use this rather than
// len(cfg.CIMD.AllowedDomains). The two disagree exactly where it matters:
// allowed_domains: [""] has length 1 and an effective count of 0, so a caller
// reading the raw slice concludes the deployment is locked down at the one
// moment it is wide open.
func (s *CIMDService) AllowedDomainCount() int {
	if s == nil {
		return 0
	}

	return len(s.allowedDomains)
}

// IsCIMDClientID reports whether clientID is shaped like a CIMD identifier: an
// absolute https:// URL with a host and a non-root path component. The path
// requirement is what distinguishes a CIMD identifier from a bare issuer URL,
// and matches the draft's "the client identifier is a URL [...] the path
// component MUST be present" guidance.
//
// This is a cheap syntactic gate used at the two auth-code call sites to decide
// whether to route to CIMD resolution or the client registry. Full validation
// (query/fragment rejection, self-reference, field checks) happens in
// ResolveClient. A query string or fragment still counts as CIMD-shaped here so
// ResolveClient can reject it with an actionable error instead of the request
// silently falling through to a "no such client" registry miss.
func IsCIMDClientID(clientID string) bool {
	u, err := url.Parse(clientID)
	if err != nil {
		return false
	}
	return u.Scheme == "https" && u.Host != "" && len(u.Path) > 1
}

// ResolveClient fetches, validates, and synthesizes an ephemeral public OAuth
// client from the CIMD document published at clientID. Returns a CIMD error
// sentinel (see the Err* vars) on any failure; callers map these via
// cimdOAuthError.
func (s *CIMDService) ResolveClient(ctx context.Context, clientID string) (*domain.OAuthClient, error) {
	if !s.Enabled() {
		return nil, ErrCIMDDisabled
	}

	// Length cap before anything else — client_id is persisted into
	// VARCHAR(255) columns (auth_codes, backchannel) downstream; catching an
	// oversize URL here turns a would-be 500 at code consumption into a clean
	// 400 at the door.
	if len(clientID) > maxCIMDClientIDLength {
		return nil, fmt.Errorf("%w: exceeds %d characters", ErrCIMDInvalidClientID, maxCIMDClientIDLength)
	}
	u, err := url.Parse(clientID)
	if err != nil || u.Scheme != "https" || u.Host == "" || len(u.Path) <= 1 {
		return nil, fmt.Errorf("%w: must be an absolute https:// URL with a path", ErrCIMDInvalidClientID)
	}
	// draft-02 §3: a fragment is MUST NOT, a query is SHOULD NOT. We reject
	// both. Being stricter than the draft on the query is deliberate — the
	// client_id must be a stable, canonical document location, and rejecting
	// rather than stripping keeps the identifier the client presents everywhere
	// byte-identical to the URL the document was fetched from, which is what
	// the §4 self-reference check compares.
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("%w: must not contain a query string or fragment", ErrCIMDInvalidClientID)
	}
	// draft-02 §3: userinfo is MUST NOT. Beyond conformance this is the
	// phishing shape — https://legit.example.com@evil.example/client.json
	// resolves to evil.example (domainAllowed sees the right host, so this is
	// not an allow-list bypass) while READING as legit.example.com everywhere
	// the client_id is displayed: consent screens and audit logs, which are
	// exactly where a human is asked to trust the string.
	if u.User != nil {
		return nil, fmt.Errorf("%w: must not contain userinfo", ErrCIMDInvalidClientID)
	}
	// draft-02 §3: no single- or double-dot path segments. Without this one
	// document has many spellings — /a/../client.json and /client.json name the
	// same resource — which splits the resolution cache and lets one client
	// hold several identities that the self-reference check cannot tell apart.
	// u.Path is decoded, so %2e%2e is caught here too.
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == "." || seg == ".." {
			return nil, fmt.Errorf("%w: must not contain %q path segments", ErrCIMDInvalidClientID, seg)
		}
	}
	if !s.domainAllowed(u.Hostname()) {
		return nil, ErrCIMDDomainNotAllowed
	}

	if client, cachedErr, hit := s.cachedResult(clientID); hit {
		return client, cachedErr
	}

	// Cache miss. Collapse concurrent misses for this client_id into one
	// fetch; every other caller waits on that result rather than issuing its
	// own. See CIMDService.flights.
	//
	// The returned client is cloned PER CALLER below: singleflight hands the
	// same value to every waiter, and callers get a mutable *domain.OAuthClient
	// — the same reason cachedResult returns a copy. Sharing one instance
	// across waiters would let any of them mutate what the others hold.
	res, err, _ := s.flights.Do(clientID, func() (any, error) {
		// Re-check under the flight. A fetch may have completed and populated
		// the cache between the miss above and this call, in which case
		// starting a fetch would be duplicate work the flight cannot see.
		if client, cachedErr, hit := s.cachedResult(clientID); hit {
			if cachedErr != nil {
				return nil, cachedErr
			}

			return client, nil
		}

		return s.resolveUncached(ctx, clientID, u.Hostname())
	})
	if err != nil {
		return nil, err
	}

	client, ok := res.(*domain.OAuthClient)
	if !ok || client == nil {
		// Unreachable: every non-error path above returns a non-nil
		// *domain.OAuthClient. Kept because singleflight erases the type, so a
		// future edit that returns something else would otherwise surface as a
		// nil-pointer panic inside the authorize handler rather than an error.
		return nil, fmt.Errorf("%w: resolution returned no client", ErrCIMDInvalidDocument)
	}

	return cloneCIMDClient(client), nil
}

// resolveUncached performs the actual fetch, validation, synthesis and caching
// for one client_id. Split out of ResolveClient so the singleflight callback
// stays readable; it must only be called from inside a flight, because it
// assumes the caller has established there is no usable cache entry.
//
// clientIDHost is the already-parsed host of clientID, passed in rather than
// re-derived: ResolveClient has parsed it and run it past domainAllowed before
// entering the flight, so re-parsing here would repeat that work and introduce
// an error branch that cannot be reached. It is a pure function of clientID,
// which is the singleflight key, so every caller sharing a flight agrees on it.
func (s *CIMDService) resolveUncached(
	ctx context.Context, clientID, clientIDHost string,
) (*domain.OAuthClient, error) {
	doc, docTTL, err := s.fetch(ctx, clientID)
	if err != nil {
		// Negative-cache the failure so replaying a dead URL can't force a
		// fresh timeout-bounded outbound fetch per request. Fetch errors are
		// transient (origin blip) and get the short TTL; validation errors are
		// deterministic and keep the longer one.
		ttl := cimdNegativeCacheTTL
		if errors.Is(err, ErrCIMDFetch) {
			ttl = cimdTransientNegativeCacheTTL
		}
		s.storeResult(clientID, cimdCacheEntry{err: err}, ttl)
		return nil, err
	}
	client, err := synthesizeCIMDClient(clientID, doc, s.now())
	if err != nil {
		s.storeResult(clientID, cimdCacheEntry{err: err}, cimdNegativeCacheTTL)
		return nil, err
	}
	if err := s.redirectHostsAllowed(clientIDHost, client.RedirectURIs); err != nil {
		s.storeResult(clientID, cimdCacheEntry{err: err}, cimdNegativeCacheTTL)
		return nil, err
	}

	s.storeResult(clientID, cimdCacheEntry{client: client}, docTTL)
	log.Info().
		Str("client_id", clientID).
		Str("client_name", client.Name).
		Int("redirect_uris", len(client.RedirectURIs)).
		Msg("CIMD: resolved client from metadata document")
	return client, nil
}

// redirectHostsAllowed enforces the allow-list on https redirect destinations,
// not just on the host that published the document.
//
// The allow-list is what lets a CIMD client be redirected to at all — see
// API.refusesRedirectTo. That gate reads "an allow-listed publisher is a vetted
// party", and the two only mean the same thing if the destination is vetted too.
// Without this check they come apart on any host where more than one party can
// publish a path: a user-content path, a raw-file CDN, a bucket with broad
// write, a shared internal app host. Publish a document there naming
// redirect_uri https://evil.example/cb and the deployment 302s an
// unauthenticated caller to evil.example — and worse, sends a victim through
// the real login page first, so the code arrives after a genuine sign-in. That
// is exactly what the self-asserted carve-out was added to prevent, reachable
// through the switch that is supposed to lift it safely.
//
// Same host as the client_id passes without being listed: a document may always
// name callbacks on the host that published it, which is the ordinary case and
// needs no extra configuration.
//
// Loopback http and private-use schemes are exempt. Their destination is the
// caller's own machine, not a host anybody publishes to, so a deployment-wide
// host allow-list has nothing to say about them — and they are the native and
// MCP client shape, which must keep working.
//
// In open mode (no allow-list) domainAllowed admits everything, so this is a
// no-op — correctly, since open mode refuses these redirects outright.
func (s *CIMDService) redirectHostsAllowed(clientIDHost string, redirectURIs []string) error {
	for _, raw := range redirectURIs {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" {
			// Non-https was already scheme-checked by validateCIMDRedirectURI;
			// a parse failure cannot survive it either.
			continue
		}

		host := u.Hostname()
		if strings.EqualFold(host, clientIDHost) || s.domainAllowed(host) {
			continue
		}

		return fmt.Errorf("%w: redirect_uri host %q is neither the client_id host nor in cimd.allowed_domains",
			ErrCIMDDomainNotAllowed, host)
	}

	return nil
}

// domainAllowed reports whether host passes the optional allowlist. An empty
// allowlist means "any host" (SSRF guard still applies at fetch time).
func (s *CIMDService) domainAllowed(host string) bool {
	if len(s.allowedDomains) == 0 {
		return true
	}
	_, ok := s.allowedDomains[strings.ToLower(host)]
	return ok
}

// fetch performs the SSRF-guarded GET and JSON-decodes the (size-capped) body.
// The returned duration is the positive-cache TTL for the document: the
// response's Cache-Control max-age when it asks for LESS than the configured
// TTL (clamped to cimdPositiveCacheFloor), the configured TTL otherwise. A
// client that rotates its redirect_uris can thus shorten how long a stale
// document is honored; it can never extend past the configured/24h cap.
func (s *CIMDService) fetch(ctx context.Context, docURL string) (*cimdMetadataDocument, time.Duration, error) {
	// Bound the fetch at cimdFetchTimeout regardless of the injected client's
	// own Timeout (the production SSRF-guarded client is wired at 10s), so the
	// documented 5s ceiling holds and a slow origin can't stall the request
	// path longer than that.
	ctx, cancel := context.WithTimeout(ctx, cimdFetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, docURL, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", ErrCIMDFetch, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		// Network error, timeout, or SSRF-guard dial rejection. Don't echo the
		// underlying message to the client (it can reveal our DNS view / internal
		// topology); the wrapped cause is preserved for server-side logs.
		return nil, 0, fmt.Errorf("%w: %v", ErrCIMDFetch, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("%w: unexpected HTTP status %d", ErrCIMDFetch, resp.StatusCode)
	}

	// Read one byte past the cap so an over-limit document is detected rather
	// than silently truncated into malformed JSON.
	body, err := io.ReadAll(io.LimitReader(resp.Body, s.maxDocumentBytes+1))
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", ErrCIMDFetch, err)
	}
	if int64(len(body)) > s.maxDocumentBytes {
		return nil, 0, fmt.Errorf("%w: document exceeds %d-byte limit", ErrCIMDInvalidDocument, s.maxDocumentBytes)
	}

	var doc cimdMetadataDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, 0, fmt.Errorf("%w: response is not valid JSON: %v", ErrCIMDInvalidDocument, err)
	}
	return &doc, s.positiveCacheTTL(resp.Header.Get("Cache-Control")), nil
}

// positiveCacheTTL derives the positive-cache TTL from a response's
// Cache-Control header. A max-age (or no-store/no-cache) SHORTER than the
// configured TTL is honored, clamped to cimdPositiveCacheFloor; anything
// else — absent header, unparseable value, or a max-age longer than the
// configured TTL — yields the configured TTL. Directives only ever shorten
// the window (draft: the AS caps cache lifetime regardless of Cache-Control).
func (s *CIMDService) positiveCacheTTL(cacheControl string) time.Duration {
	ttl := s.cacheTTL
	for _, directive := range strings.Split(cacheControl, ",") {
		directive = strings.ToLower(strings.TrimSpace(directive))
		if directive == "no-store" || directive == "no-cache" {
			return cimdPositiveCacheFloor
		}
		if v, ok := strings.CutPrefix(directive, "max-age="); ok {
			secs, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil || secs < 0 {
				continue
			}
			if maxAge := time.Duration(secs) * time.Second; maxAge < ttl {
				ttl = max(maxAge, cimdPositiveCacheFloor)
			}
		}
	}
	return ttl
}

// synthesizeCIMDClient validates the document against the fetch URL and turns it
// into an ephemeral public OAuth client. Pure (no I/O) so it is unit-testable in
// isolation. `now` timestamps the synthesized record.
func synthesizeCIMDClient(clientID string, doc *cimdMetadataDocument, now time.Time) (*domain.OAuthClient, error) {
	// Self-reference (draft §4): the document's own client_id MUST equal the URL
	// it was fetched from. This is what stops an attacker from hosting a document
	// that claims someone else's client_id.
	if doc.ClientID != clientID {
		return nil, fmt.Errorf("%w: document client_id %q does not match its URL", ErrCIMDInvalidDocument, doc.ClientID)
	}

	// redirect_uris is required and must be non-empty for the authorization_code
	// flow — it is CIMD's primary anti-impersonation control. Each entry must
	// also pass the OAuth 2.1 scheme rules (https, loopback http, or a
	// private-use scheme) so a document cannot allow-list a plaintext
	// non-loopback callback for its own codes.
	if len(doc.RedirectURIs) == 0 {
		return nil, fmt.Errorf("%w: redirect_uris is required and must be non-empty", ErrCIMDInvalidDocument)
	}
	for _, ru := range doc.RedirectURIs {
		if err := validateCIMDRedirectURI(ru); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrCIMDInvalidDocument, err)
		}
	}

	// Public client only in v1. An omitted token_endpoint_auth_method defaults to
	// "none" for a CIMD (public) client; any explicit confidential method is
	// rejected — ZeroID does not accept private_key_jwt token-endpoint auth yet.
	authMethod := doc.TokenEndpointAuthMethod
	if authMethod == "" {
		authMethod = "none"
	}
	if authMethod != "none" {
		return nil, fmt.Errorf("%w: token_endpoint_auth_method must be \"none\" (public PKCE); %q is not supported",
			ErrCIMDInvalidDocument, doc.TokenEndpointAuthMethod)
	}

	// grant_types default to [authorization_code]; must include it and stay
	// inside the CIMD allow-list.
	grantTypes := doc.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{string(domain.GrantTypeAuthorizationCode)}
	}
	if !slices.Contains(grantTypes, string(domain.GrantTypeAuthorizationCode)) {
		return nil, fmt.Errorf("%w: grant_types must include authorization_code", ErrCIMDInvalidDocument)
	}
	for _, gt := range grantTypes {
		if !cimdAllowedGrantTypes[gt] {
			return nil, fmt.Errorf("%w: grant_type %q is not permitted for a CIMD client", ErrCIMDInvalidDocument, gt)
		}
	}

	// response_types, when present, must contain "code" (the only response type
	// the authorization_code flow supports).
	if len(doc.ResponseTypes) > 0 && !slices.Contains(doc.ResponseTypes, "code") {
		return nil, fmt.Errorf("%w: response_types must include \"code\"", ErrCIMDInvalidDocument)
	}

	// client_name is REQUIRED here, though the draft only RECOMMENDS it.
	//
	// It is the string a human is asked to trust: a consent screen identifies the
	// application by client_name, so an absent one degrades the prompt to a raw
	// URL — both less legible and, for a URL an attacker chose, actively
	// misleading. The document's publisher is anonymous by construction: there is
	// no registration and no secret, so this label is most of what consent has to
	// go on.
	//
	// We used to fall back to the client_id. That made the weakest case — a
	// document that declined to name itself — silently indistinguishable from a
	// well-formed one, and put the choice of what the user reads in the hands of
	// whoever picked the URL.
	name := strings.TrimSpace(doc.ClientName)
	if name == "" {
		return nil, fmt.Errorf("%w: client_name is required and must be non-empty", ErrCIMDInvalidDocument)
	}

	// An empty scope means "no client-side scope ceiling": the principal
	// resolver's narrowing governs (intersectScopes treats an empty allowed set
	// as unrestricted). Same as a registry public client with no scopes.
	// strings.Fields never returns nil, so no empty-slice normalization needed.
	scopes := strings.Fields(doc.Scope)

	return &domain.OAuthClient{
		ClientID:                clientID,
		Name:                    name,
		ClientType:              "public",
		TokenEndpointAuthMethod: "none",
		GrantTypes:              grantTypes,
		RedirectURIs:            doc.RedirectURIs,
		Scopes:                  scopes,
		RegistrationSource:      cimdRegistrationSource,
		IsActive:                true,
		CreatedAt:               now,
		UpdatedAt:               now,
	}, nil
}

// validateCIMDRedirectURI enforces OAuth 2.1 §2.3-style redirect URI scheme
// rules on a CIMD document entry: https:// always OK; http:// only for
// loopback hosts (native/CLI callbacks per RFC 8252 §7.3); any other non-empty
// scheme is treated as a private-use scheme (native apps, e.g. myapp:/cb).
// Relative URIs are rejected — a redirect target must be absolute.
func validateCIMDRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("redirect_uri %q is not a valid URI", raw)
	}
	// A fragment is never valid on a redirect URI (RFC 6749 §3.1.2) — it would
	// clobber the fragment the server appends. Reject regardless of scheme.
	if u.Fragment != "" {
		return fmt.Errorf("redirect_uri %q must not contain a fragment", raw)
	}
	switch u.Scheme {
	case "https", "http":
		// https:// and loopback http:// must be absolute (host present) and
		// carry no userinfo. url.Parse accepts rootless forms like "https:/cb"
		// (Host == "") — those are not usable redirect targets and must not
		// pass validation just because the scheme matched.
		if u.Host == "" {
			return fmt.Errorf("redirect_uri %q must be an absolute URI with a host", raw)
		}
		if u.User != nil {
			return fmt.Errorf("redirect_uri %q must not contain userinfo", raw)
		}
		if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
			return fmt.Errorf("redirect_uri %q: http is only permitted for loopback hosts", raw)
		}
		return nil
	case "":
		return fmt.Errorf("redirect_uri %q must be an absolute URI", raw)
	default:
		// Private-use scheme (RFC 8252 §7.1) — native app callback.
		return nil
	}
}

// cachedResult returns the memoized outcome for clientID if present and
// unexpired: (client, nil, true) for a positive entry, (nil, err, true) for a
// negative one, (nil, nil, false) on a miss. Stale entries are evicted on
// access. Positive hits return a COPY so a caller cannot mutate the cached
// instance.
func (s *CIMDService) cachedResult(clientID string) (*domain.OAuthClient, error, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.cache[clientID]
	if !ok {
		return nil, nil, false
	}
	if s.now().After(e.expiresAt) {
		delete(s.cache, clientID)
		return nil, nil, false
	}
	if e.err != nil {
		return nil, e.err, true
	}
	return cloneCIMDClient(e.client), nil, true
}

// cloneCIMDClient copies c so the result shares no slice backing storage with
// c. A plain `*c` struct copy leaves the slice fields (GrantTypes/RedirectURIs/
// Scopes/Contacts) aliasing the original — a caller appending to or mutating
// one of those slices would corrupt the cached entry (and race other callers).
func cloneCIMDClient(c *domain.OAuthClient) *domain.OAuthClient {
	cp := *c
	cp.GrantTypes = slices.Clone(c.GrantTypes)
	cp.RedirectURIs = slices.Clone(c.RedirectURIs)
	cp.Scopes = slices.Clone(c.Scopes)
	cp.Contacts = slices.Clone(c.Contacts)
	return &cp
}

// storeResult caches entry under clientID for ttl, keeping the map bounded:
// when the cap is reached it sweeps expired entries, and if the map is somehow
// still full it evicts one arbitrary entry rather than growing. Positive
// entries store a COPY of the client.
func (s *CIMDService) storeResult(clientID string, entry cimdCacheEntry, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.cache[clientID]; !exists && len(s.cache) >= s.maxCacheEntries {
		now := s.now()
		for k, v := range s.cache {
			if now.After(v.expiresAt) {
				delete(s.cache, k)
			}
		}
		if len(s.cache) >= s.maxCacheEntries {
			for k := range s.cache {
				delete(s.cache, k)
				break
			}
		}
	}
	if entry.client != nil {
		entry.client = cloneCIMDClient(entry.client)
	}
	entry.expiresAt = s.now().Add(ttl)
	s.cache[clientID] = entry
}
