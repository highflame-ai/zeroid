package service

import (
	"bytes"
	"container/list"
	"context"
	"encoding/json"
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
// The construction is deliberately performed OUTSIDE the lock.
// authjwt.NewJWKSClient does a synchronous warm-up fetch of a client-supplied
// URL, bounded only by a 10s timeout. Holding the cache mutex across it would
// let anyone who can register clients stall every private_key_jwt verification
// server-wide: point >maxSize registrations at hosts that accept TCP and never
// answer, then send unauthenticated token requests naming each one. Every
// request misses the cache and spends 10s holding the one mutex the whole auth
// path needs. The JWKS fetch happens before any signature check, so no
// credential is required to drive it.
//
// The cost of building outside the lock is that two concurrent misses on the
// same key may both construct; the loser is closed immediately and the winner
// is returned to both callers, so no goroutine leaks and callers still share one
// client.
func (c *ClientJWKSCache) get(clientID, jwksURI string) (*authjwt.JWKSClient, error) {
	key := clientID + "\x00" + jwksURI

	c.mu.Lock()
	if el, ok := c.entries[key]; ok {
		c.lru.MoveToFront(el)
		client := el.Value.(*clientJWKSEntry).client
		c.mu.Unlock()
		return client, nil
	}
	c.mu.Unlock()

	client, err := authjwt.NewJWKSClient(jwksURI, c.opts...)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	// Re-check: another caller may have inserted this key while we fetched.
	if el, ok := c.entries[key]; ok {
		winner := el.Value.(*clientJWKSEntry).client
		c.lru.MoveToFront(el)
		c.mu.Unlock()
		client.Close() // we lost the race; don't leak our refresh goroutine
		return winner, nil
	}

	// Evict before insert so the cache never exceeds maxSize. Collect the
	// evicted clients and Close them AFTER releasing the lock — Close blocks on
	// the refresh goroutine winding down, which can itself be inside a fetch.
	var evicted []*authjwt.JWKSClient
	for c.lru.Len() >= c.maxSize {
		oldest := c.lru.Back()
		if oldest == nil {
			break
		}
		entry := oldest.Value.(*clientJWKSEntry)
		c.lru.Remove(oldest)
		delete(c.entries, entry.key)
		evicted = append(evicted, entry.client)
	}

	c.entries[key] = c.lru.PushFront(&clientJWKSEntry{key: key, client: client})
	c.mu.Unlock()

	for _, e := range evicted {
		e.Close()
	}
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

// HasInlineJWKS reports whether raw carries an actual inline JWK Set, as
// opposed to being absent.
//
// The length check this replaces (`len(raw) > 0`) is wrong against real stored
// data. `jwks` is a nullable jsonb column, and bun writes a nil json.RawMessage
// as JSON `null` rather than SQL NULL — so a client registered WITHOUT a jwks
// reads back as the four bytes `null`, which is non-empty. Every one of the
// clients deployed in dev1 and prod today has exactly that value.
//
// Left unhandled, a private_key_jwt client that published a `jwks_uri` and no
// inline set would be read as carrying BOTH, be rejected as an ambiguous
// registration, and never authenticate at all — a failure no in-memory unit test
// would surface, because a hand-built domain.OAuthClient has a genuinely nil
// JWKS while a database round trip does not.
func HasInlineJWKS(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null"))
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
	hasInline := HasInlineJWKS(client.JWKS)
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
