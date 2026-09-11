package service

import (
	"container/list"
	"context"
	"sync"

	"github.com/lestrrat-go/jwx/v4/jwk"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/pkg/authjwt"
)

// defaultClientJWKSCacheSize bounds how many remote client JWKS endpoints are
// cached concurrently. Each entry owns a background refresh goroutine and an
// HTTP client, so this is not merely a memory bound — an unbounded map keyed by
// client_id would let anyone able to register clients (DCR is open in some
// deployments) spawn one goroutine and one outbound-fetch loop per registration.
// Least-recently-used entries are evicted and closed when the cap is reached.
const defaultClientJWKSCacheSize = 256

// ClientJWKSCache holds a live authjwt.JWKSClient per remote client `jwks_uri`.
//
// Keyed by clientID+"\x00"+jwksURI rather than clientID alone: when a client
// rotates its jwks_uri, a clientID-only key would keep serving keys fetched from
// the OLD endpoint until eviction — i.e. a revoked key would keep authenticating.
// Including the URI in the key makes a rotation a cache miss by construction.
type ClientJWKSCache struct {
	mu      sync.Mutex
	maxSize int
	entries map[string]*list.Element // key -> element in lru
	lru     *list.List               // front = most recently used; values are *clientJWKSEntry
	opts    []authjwt.JWKSOption
}

type clientJWKSEntry struct {
	key    string
	client *authjwt.JWKSClient
}

// NewClientJWKSCache builds an empty cache. opts are applied to every JWKS
// client it creates — server.go supplies the SSRF-guarded HTTP client there, so
// a registered jwks_uri cannot be used to probe link-local metadata endpoints or
// internal services (the same guard the external-issuer registry uses).
func NewClientJWKSCache(maxSize int, opts ...authjwt.JWKSOption) *ClientJWKSCache {
	if maxSize <= 0 {
		maxSize = defaultClientJWKSCacheSize
	}
	return &ClientJWKSCache{
		maxSize: maxSize,
		entries: make(map[string]*list.Element, maxSize),
		lru:     list.New(),
		opts:    opts,
	}
}

// get returns a JWKS client for the given client_id + jwks_uri, creating one on
// a miss and evicting the least-recently-used entry when the cache is full.
func (c *ClientJWKSCache) get(clientID, jwksURI string) (*authjwt.JWKSClient, error) {
	key := clientID + "\x00" + jwksURI

	c.mu.Lock()
	defer c.mu.Unlock()

	if el, ok := c.entries[key]; ok {
		c.lru.MoveToFront(el)
		return el.Value.(*clientJWKSEntry).client, nil
	}

	client, err := authjwt.NewJWKSClient(jwksURI, c.opts...)
	if err != nil {
		return nil, err
	}

	// Evict before insert so the cache never exceeds maxSize. Closing the
	// evicted client stops its background refresh goroutine — without this the
	// cache would bound memory but leak goroutines.
	for c.lru.Len() >= c.maxSize {
		oldest := c.lru.Back()
		if oldest == nil {
			break
		}
		entry := oldest.Value.(*clientJWKSEntry)
		c.lru.Remove(oldest)
		delete(c.entries, entry.key)
		entry.client.Close()
	}

	c.entries[key] = c.lru.PushFront(&clientJWKSEntry{key: key, client: client})
	return client, nil
}

// Close stops every cached client's background refresh. Idempotent.
func (c *ClientJWKSCache) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, el := range c.entries {
		el.Value.(*clientJWKSEntry).client.Close()
	}
	c.entries = make(map[string]*list.Element)
	c.lru.Init()
}

// clientVerificationKeys resolves the public keys a client's assertions are
// verified against: its inline `jwks` document, or the JWKS fetched from its
// registered `jwks_uri`.
//
// Every failure is invalid_client (401) rather than a server error, with one
// exception: an unreachable jwks_uri is an operational fault on OUR side of the
// fetch and surfaces as 500, matching how the external-IdP path treats an
// unloadable issuer JWKS. A client cannot distinguish the two from the response,
// but the server's own metrics can.
func (s *OAuthService) clientVerificationKeys(ctx context.Context, client *domain.OAuthClient) (jwk.Set, error) {
	hasInline := len(client.JWKS) > 0
	hasURI := client.JWKSURI != ""

	switch {
	case hasInline && hasURI:
		// RFC 7591 §2: jwks and jwks_uri MUST NOT both be present. Registration
		// refuses this, so a row carrying both predates that check or was
		// written directly. Refusing beats silently picking one — the operator
		// cannot tell which key set is actually authenticating their client.
		return nil, oauthUnauthorized(
			"client registration carries both jwks and jwks_uri; exactly one is required for private_key_jwt", nil)

	case hasInline:
		set, err := jwk.Parse(client.JWKS)
		if err != nil {
			return nil, oauthUnauthorized("client jwks is not a valid JWK Set", err)
		}
		if set.Len() == 0 {
			return nil, oauthUnauthorized("client jwks contains no keys", nil)
		}
		return set, nil

	case hasURI:
		if s.clientJWKS == nil {
			return nil, oauthServerError("client JWKS cache is not configured", nil)
		}
		jwksClient, err := s.clientJWKS.get(client.ClientID, client.JWKSURI)
		if err != nil {
			return nil, oauthServerError("failed to construct a JWKS client for jwks_uri", err)
		}
		// Synchronous load: authjwt warms up best-effort and refreshes in the
		// background, so the first request after a cold start (or after a
		// failed warm-up) must not fail merely because the fetch has not
		// happened yet.
		if err := jwksClient.EnsureLoaded(ctx); err != nil {
			return nil, oauthServerError("failed to load the client's jwks_uri", err)
		}
		set := jwksClient.KeySet()
		if set == nil || set.Len() == 0 {
			return nil, oauthUnauthorized("the client's jwks_uri returned no keys", nil)
		}
		return set, nil

	default:
		return nil, oauthUnauthorized(
			"client is registered for private_key_jwt but published no jwks or jwks_uri", nil)
	}
}
