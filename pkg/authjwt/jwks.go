package authjwt

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/rs/zerolog"
)

// maxJWKSBodyBytes caps the JWKS response body to prevent a malicious or
// compromised issuer from exhausting memory during a fetch. JWKS documents
// are typically a few KB; 1 MiB is generous headroom.
const maxJWKSBodyBytes = 1 << 20 // 1 MiB

const (
	defaultRefreshInterval = 5 * time.Minute
	defaultRequestTimeout  = 10 * time.Second
	minRefreshInterval     = 30 * time.Second
)

// JWKSClient fetches and caches a JWKS from a remote endpoint.
// It supports periodic background refresh and on-demand refresh when
// a token presents an unknown kid.
type JWKSClient struct {
	jwksURL         string
	refreshInterval time.Duration
	requestTimeout  time.Duration
	httpClient      *http.Client
	logger          zerolog.Logger

	mu     sync.RWMutex
	keySet jwk.Set
	kids   map[string]struct{} // known key IDs for fast miss detection

	// loadMu guards loadInFlight so concurrent EnsureLoaded callers either
	// elect a single leader (cold cache, no fetch in flight) or attach to
	// an existing leader's broadcast channel.
	loadMu       sync.Mutex
	loadInFlight *jwksFetch

	cancel context.CancelFunc
	done   chan struct{}
}

// jwksFetch is the broadcast handle for an in-flight cold-cache fetch.
// The leader runs the fetch with its own fresh context; followers wait on
// done with their own ctx so they can return on their own deadline rather
// than blocking on whatever timeout the leader chose.
type jwksFetch struct {
	done chan struct{} // closed when the fetch completes
	err  error         // populated before close(done); read-only after
}

// JWKSOption configures a JWKSClient.
type JWKSOption func(*JWKSClient)

// WithRefreshInterval sets how often the JWKS is refreshed in the background.
// Minimum 30 seconds. Default 5 minutes.
func WithRefreshInterval(d time.Duration) JWKSOption {
	return func(c *JWKSClient) {
		if d >= minRefreshInterval {
			c.refreshInterval = d
		}
	}
}

// WithRequestTimeout sets the timeout for individual JWKS HTTP requests.
// Default 10 seconds.
func WithRequestTimeout(d time.Duration) JWKSOption {
	return func(c *JWKSClient) {
		if d > 0 {
			c.requestTimeout = d
		}
	}
}

// WithHTTPClient sets a custom HTTP client for JWKS fetching.
func WithHTTPClient(client *http.Client) JWKSOption {
	return func(c *JWKSClient) {
		c.httpClient = client
	}
}

// WithLogger sets the logger for the JWKS client.
func WithLogger(logger zerolog.Logger) JWKSOption {
	return func(c *JWKSClient) {
		c.logger = logger
	}
}

// NewJWKSClient creates a JWKS client that fetches keys from the given URL.
//
// It attempts a best-effort initial fetch with the configured request timeout,
// but does NOT fail if the endpoint is unreachable: a transient cross-service
// startup race (e.g., the issuer's pod hasn't bound its TCP listener yet) used
// to crash callers and is now papered over by the background refresh loop and
// by EnsureLoaded(), which is invoked lazily on the first Verify() call.
//
// Returns an error only for config-level problems (empty URL). Call Close()
// to stop the background refresh.
func NewJWKSClient(jwksURL string, opts ...JWKSOption) (*JWKSClient, error) {
	if jwksURL == "" {
		return nil, fmt.Errorf("authjwt: JWKSURL is required")
	}

	c := &JWKSClient{
		jwksURL:         jwksURL,
		refreshInterval: defaultRefreshInterval,
		requestTimeout:  defaultRequestTimeout,
		httpClient:      http.DefaultClient,
		logger:          zerolog.Nop(),
		kids:            make(map[string]struct{}),
		done:            make(chan struct{}),
	}

	for _, opt := range opts {
		opt(c)
	}

	// Best-effort warm-up. A failure here is not fatal: the issuer may be
	// starting in parallel (kind/CI bootstrap, regional failover, simultaneous
	// rolling restart). EnsureLoaded() will retry synchronously on the first
	// Verify() and the background refresh loop will catch it on its next tick.
	if err := c.refresh(context.Background()); err != nil {
		c.logger.Warn().
			Err(err).
			Str("url", jwksURL).
			Msg("initial JWKS fetch failed; continuing — will retry on first verify and via background refresh")
	}

	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	go c.refreshLoop(ctx)

	return c, nil
}

// KeySet returns the current cached JWKS. Thread-safe.
func (c *JWKSClient) KeySet() jwk.Set {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.keySet
}

// HasKID returns true if the given key ID is in the current JWKS.
func (c *JWKSClient) HasKID(kid string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.kids[kid]
	return ok
}

// EnsureLoaded fetches the JWKS synchronously if the local cache is empty.
// This is the lazy path used on the first Verify() call when the initial
// fetch from NewJWKSClient failed (e.g., the issuer's pod was still starting).
//
// Concurrent callers coalesce on a single fetch: exactly one leader runs the
// network request, the rest wait on a broadcast channel. Each waiter respects
// its own ctx — a caller with a 100ms deadline returns on its deadline rather
// than blocking up to requestTimeout for the leader. The fetch itself runs
// with a fresh context so one caller's cancellation doesn't break the result
// for the others.
//
// Returns nil if the cache is populated (already, or by this call).
func (c *JWKSClient) EnsureLoaded(ctx context.Context) error {
	if c.populated() {
		return nil
	}

	c.loadMu.Lock()
	if c.populated() {
		c.loadMu.Unlock()
		return nil
	}

	leader := c.loadInFlight == nil
	if leader {
		c.loadInFlight = &jwksFetch{done: make(chan struct{})}
	}
	fetch := c.loadInFlight
	c.loadMu.Unlock()

	if leader {
		// Run with a fresh context detached from any single caller. If the
		// caller that triggered the fetch cancels mid-flight, the result is
		// still useful to every other waiter, so we use requestTimeout as
		// the upper bound and let net/http handle cancellation cleanly.
		fetchCtx, cancel := context.WithTimeout(context.Background(), c.requestTimeout)
		fetch.err = c.refresh(fetchCtx)
		cancel()

		// Clear in-flight before broadcasting so a subsequent cold-start
		// (e.g., this fetch failed and a later caller retries) elects a
		// fresh leader instead of attaching to the stale handle.
		c.loadMu.Lock()
		c.loadInFlight = nil
		c.loadMu.Unlock()

		close(fetch.done)
		return fetch.err
	}

	// Follower path. Wait for the leader, but only as long as our own ctx
	// allows. Returning early here does NOT cancel the leader's fetch —
	// the leader keeps going on its detached context and serves whichever
	// other followers are still around to consume the result.
	select {
	case <-fetch.done:
		return fetch.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// populated reports whether the cache currently holds at least one key.
func (c *JWKSClient) populated() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.keySet != nil && c.keySet.Len() > 0
}

// RefreshIfMissing triggers an immediate JWKS refresh if the given kid is not
// in the current key set. Returns true if a refresh was performed.
// This handles key rotation — when ZeroID rotates keys, the first request
// with the new kid triggers a refresh rather than failing.
func (c *JWKSClient) RefreshIfMissing(ctx context.Context, kid string) bool {
	if c.HasKID(kid) {
		return false
	}

	c.logger.Info().Str("kid", kid).Msg("unknown kid, refreshing JWKS")
	if err := c.refresh(ctx); err != nil {
		c.logger.Error().Err(err).Msg("on-demand JWKS refresh failed")
		return false
	}
	return true
}

// Close stops the background refresh goroutine and releases resources.
func (c *JWKSClient) Close() {
	c.cancel()
	<-c.done
}

func (c *JWKSClient) refresh(ctx context.Context) error {
	fetchCtx, cancel := context.WithTimeout(ctx, c.requestTimeout)
	defer cancel()

	// jwx v4 dropped jwk.Fetch / jwk.WithHTTPClient (the helper moved into
	// the optional jwx-go/jwkfetch companion module). We already manage an
	// http.Client here, so do the GET ourselves and feed the body into
	// jwk.Parse — keeps the dependency footprint flat.
	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, c.jwksURL, nil)
	if err != nil {
		return fmt.Errorf("build JWKS request: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBodyBytes))
	if err != nil {
		return fmt.Errorf("read JWKS body: %w", err)
	}
	set, err := jwk.Parse(body)
	if err != nil {
		return fmt.Errorf("parse JWKS: %w", err)
	}

	// SPIFFE bundles publish use=JWT-SVID (JWT-SVID §4). lestrrat-go/jwx's
	// verifier treats anything other than "sig" as non-signing and skips the
	// key, so we normalize on ingest. The spec value is "JWT-SVID" but match
	// case-insensitively in case an upstream emits lowercase. RFC 7517 says
	// use is informational — rewriting it doesn't change what the key is.
	kids := make(map[string]struct{}, set.Len())
	for i := 0; i < set.Len(); i++ {
		key, ok := set.Key(i)
		if !ok {
			continue
		}
		if use, ok := key.KeyUsage(); ok && strings.EqualFold(use, "JWT-SVID") {
			_ = key.Set(jwk.KeyUsageKey, jwk.ForSignature)
		}
		// jwx v4: KeyID() returns (string, present); the index loop is keyed
		// on insertion order, so this is the cleanest way to get a kid string.
		if kid, ok := key.KeyID(); ok {
			kids[kid] = struct{}{}
		}
	}

	c.mu.Lock()
	c.keySet = set
	c.kids = kids
	c.mu.Unlock()

	c.logger.Debug().Int("key_count", set.Len()).Msg("JWKS refreshed")
	return nil
}

func (c *JWKSClient) refreshLoop(ctx context.Context) {
	defer close(c.done)
	ticker := time.NewTicker(c.refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.refresh(ctx); err != nil {
				c.logger.Warn().Err(err).Msg("background JWKS refresh failed, using cached keys")
			}
		}
	}
}
