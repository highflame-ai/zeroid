package authjwt

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/rs/zerolog"
)

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

	cancel context.CancelFunc
	done   chan struct{}
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
// It performs an initial fetch synchronously and starts a background refresh goroutine.
// Call Close() to stop the background refresh.
func NewJWKSClient(jwksURL string, opts ...JWKSOption) (*JWKSClient, error) {
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

	// Initial synchronous fetch — fail fast if JWKS is unreachable.
	if err := c.refresh(context.Background()); err != nil {
		return nil, fmt.Errorf("authjwt: initial JWKS fetch from %s failed: %w", jwksURL, err)
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

	set, err := jwk.Fetch(fetchCtx, c.jwksURL, jwk.WithHTTPClient(c.httpClient))
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}

	kids := make(map[string]struct{}, set.Len())
	for i := 0; i < set.Len(); i++ {
		key, ok := set.Key(i)
		if !ok {
			continue
		}
		kids[key.KeyID()] = struct{}{}
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
