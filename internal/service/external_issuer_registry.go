package service

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/attestation"
	"github.com/highflame-ai/zeroid/pkg/jwks"
)

// ExternalIssuerEntry pairs a trusted external IdP with its live JWKS client.
// Row is the account row the entry was read from, nil for a static
// external_issuers entry.
type ExternalIssuerEntry struct {
	Config domain.ExternalIssuerConfig
	JWKS   *jwks.Client
	Row    *domain.ExternalIssuer
}

// issuerRowSource reads issuer rows; *postgres.ExternalIssuerRepository.
type issuerRowSource interface {
	ListByIssuer(ctx context.Context, issuer string) ([]*domain.ExternalIssuer, error)
}

// ExternalIssuerRegistry resolves a token's iss to a trusted upstream IdP and
// holds a cached JWKS for it.
//
// Static mode (standalone ZeroID): entries come from external_issuers config
// and are fixed for the life of the process.
//
// Database mode (ADR 0042 D4): rows are read live on every federated grant,
// with no row cache, so disabling or deleting a row takes effect at the next
// request on every replica. Only the JWKS clients are cached, shared by
// (jwks_uri, refresh interval).
type ExternalIssuerRegistry struct {
	mu      sync.RWMutex
	byIss   map[string]*ExternalIssuerEntry
	closers []func()

	rows  issuerRowSource
	cache *issuerJWKSCache
}

// Resolution failures, wrapped by ResolvePerson. Grants map them to OAuth
// errors: ErrUnknownExternalIssuer keeps each path's code, the rest are
// invalid_grant.
var (
	errIssuerNotPerson    = errors.New("issuer is not trusted for person grants")
	errIssuerDisabled     = errors.New("issuer is disabled")
	errIssuerConstraints  = errors.New("token does not satisfy the issuer's claim constraints")
	errIssuerAmbiguous    = errors.New("token matches more than one trusted issuer row")
	errIssuerLookupFailed = errors.New("issuer lookup failed")
)

// NewExternalIssuerRegistry builds a static registry from validated config.
// Each entry's JWKS client warms up best-effort: jwks.New does an initial
// fetch but deliberately does NOT fail on an unreachable JWKS — it logs a
// warning and relies on background refresh plus a synchronous EnsureLoaded
// on the first verification. Only config-level errors (e.g. empty jwks_uri)
// fail here; partial failure closes the clients already created.
func NewExternalIssuerRegistry(ctx context.Context, configs []domain.ExternalIssuerConfig, opts ...jwks.Option) (*ExternalIssuerRegistry, error) {
	_ = ctx // reserved for future use; current jwks.New does its own fetch context
	r := &ExternalIssuerRegistry{
		byIss: make(map[string]*ExternalIssuerEntry, len(configs)),
	}
	for _, cfg := range configs {
		// SSRF-guarded HTTP client for the JWKS fetch (issue #198), listed
		// first so a deployer or test can still override it via opts; the
		// last WithHTTPClient wins.
		issuerOpts := append([]jwks.Option{
			jwks.WithHTTPClient(attestation.NewSSRFGuardedHTTPClient(cfg.AllowPrivateEndpoints)),
			jwks.WithRefreshInterval(cfg.JWKSCacheTTL),
		}, opts...)
		client, err := jwks.New(cfg.JWKSURI, issuerOpts...)
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

// NewDBExternalIssuerRegistry builds a registry that reads account rows.
// allowPrivate relaxes the SSRF guard on JWKS fetches; opts follow it and
// may replace the HTTP client.
func NewDBExternalIssuerRegistry(rows issuerRowSource, allowPrivate bool, opts ...jwks.Option) *ExternalIssuerRegistry {
	base := append([]jwks.Option{jwks.WithHTTPClient(attestation.NewSSRFGuardedHTTPClient(allowPrivate))}, opts...)
	return &ExternalIssuerRegistry{
		byIss: map[string]*ExternalIssuerEntry{},
		rows:  rows,
		cache: newIssuerJWKSCache(base),
	}
}

// Lookup returns the static entry for iss, or nil. Safe for concurrent use.
func (r *ExternalIssuerRegistry) Lookup(iss string) *ExternalIssuerEntry {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byIss[iss]
}

// HasAny reports whether federation can be served: a static entry exists, or
// the registry reads rows.
func (r *ExternalIssuerRegistry) HasAny() bool {
	if r == nil {
		return false
	}
	if r.rows != nil {
		return true
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byIss) > 0
}

// DBMode reports whether issuers are account rows.
func (r *ExternalIssuerRegistry) DBMode() bool { return r != nil && r.rows != nil }

// ResolvePerson returns the entry a person grant (ID-JAG, ID-token
// exchange) verifies iss against. claims are the token's UNVERIFIED claims:
// they only choose among a shared issuer's rows, and the caller re-checks
// the chosen row's constraints after verification.
func (r *ExternalIssuerRegistry) ResolvePerson(ctx context.Context, iss string, claims map[string]any) (*ExternalIssuerEntry, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: %s", ErrUnknownExternalIssuer, iss)
	}
	if r.rows == nil {
		entry := r.Lookup(iss)
		if entry == nil {
			return nil, fmt.Errorf("%w: %s", ErrUnknownExternalIssuer, iss)
		}
		if entry.Config.EffectiveKind() != domain.IssuerKindPerson {
			return nil, errIssuerNotPerson
		}
		return entry, nil
	}

	rows, err := r.rows.ListByIssuer(ctx, iss)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errIssuerLookupFailed, err)
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrUnknownExternalIssuer, iss)
	}
	var person, enabled, matched []*domain.ExternalIssuer
	for _, row := range rows {
		if row.Kind == domain.IssuerKindPerson {
			person = append(person, row)
		}
	}
	if len(person) == 0 {
		return nil, errIssuerNotPerson
	}
	for _, row := range person {
		if row.Enabled {
			enabled = append(enabled, row)
		}
	}
	if len(enabled) == 0 {
		return nil, errIssuerDisabled
	}
	for _, row := range enabled {
		if row.ConstraintsMatch(claims) {
			matched = append(matched, row)
		}
	}
	switch len(matched) {
	case 0:
		return nil, errIssuerConstraints
	case 1:
	default:
		return nil, errIssuerAmbiguous
	}
	row := matched[0]
	client, err := r.cache.get(row)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errIssuerLookupFailed, err)
	}
	return &ExternalIssuerEntry{Config: row.AsConfig(), JWKS: client, Row: row}, nil
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
	r.cache.close()
}

// ── JWKS cache for issuer rows ───────────────────────────────────────────────

const (
	issuerJWKSIdleTTL     = 30 * time.Minute
	issuerJWKSPerAccount  = MaxExternalIssuersPerAccount
	issuerJWKSTotal       = 1000
	issuerJWKSSweepPeriod = time.Minute
)

// issuerJWKSCache holds JWKS clients for issuer rows, shared by every row
// with the same (jwks_uri, refresh interval): created on first use, one
// fetch per cold key however many requests race for it, closed when idle
// or past the caps. Each client owns a refresh goroutine, so the caps bound
// goroutines as well as memory. An entry remembers which accounts use it,
// so one account's churn evicts only its own use of a shared client.
type issuerJWKSCache struct {
	mu        sync.Mutex
	entries   map[string]*issuerJWKSEntry
	inflight  map[string]*issuerJWKSFlight
	opts      []jwks.Option
	now       func() time.Time
	lastSweep time.Time
	newClient func(url string, opts ...jwks.Option) (*jwks.Client, error)
}

type issuerJWKSEntry struct {
	key      string
	client   *jwks.Client
	owners   map[string]time.Time // account -> last use
	lastUsed time.Time
}

type issuerJWKSFlight struct {
	done   chan struct{}
	client *jwks.Client
	err    error
}

func newIssuerJWKSCache(opts []jwks.Option) *issuerJWKSCache {
	return &issuerJWKSCache{
		entries:   map[string]*issuerJWKSEntry{},
		inflight:  map[string]*issuerJWKSFlight{},
		opts:      opts,
		now:       time.Now,
		newClient: jwks.New,
	}
}

// issuerJWKSKey is what a client is shared on. jwks_uri changes only by
// re-discovery, which makes a new key, so a row never verifies with keys
// fetched from a URI it no longer names.
func issuerJWKSKey(row *domain.ExternalIssuer) string {
	return fmt.Sprintf("%s\x00%d", row.JWKSURI, row.JWKSCacheTTLSeconds)
}

func (c *issuerJWKSCache) get(row *domain.ExternalIssuer) (*jwks.Client, error) {
	key := issuerJWKSKey(row)
	c.mu.Lock()
	if e, ok := c.entries[key]; ok {
		c.touchLocked(e, row.AccountID)
		closed := c.sweepLocked(false)
		c.mu.Unlock()
		closeAll(closed)
		return e.client, nil
	}
	if f, ok := c.inflight[key]; ok {
		c.mu.Unlock()
		<-f.done
		if f.err != nil {
			return nil, f.err
		}
		c.mu.Lock()
		if e, ok := c.entries[key]; ok {
			c.touchLocked(e, row.AccountID)
		}
		c.mu.Unlock()
		return f.client, nil
	}
	f := &issuerJWKSFlight{done: make(chan struct{})}
	c.inflight[key] = f
	c.mu.Unlock()

	// Outside the lock: jwks.New fetches synchronously.
	opts := append(append([]jwks.Option{}, c.opts...), jwks.WithRefreshInterval(time.Duration(row.JWKSCacheTTLSeconds)*time.Second))
	client, err := c.newClient(row.JWKSURI, opts...)

	c.mu.Lock()
	delete(c.inflight, key)
	var closed []*jwks.Client
	if err == nil {
		e := &issuerJWKSEntry{key: key, client: client, owners: map[string]time.Time{}}
		c.entries[key] = e
		c.touchLocked(e, row.AccountID)
		closed = c.sweepLocked(true)
	}
	f.client, f.err = client, err
	close(f.done)
	c.mu.Unlock()
	closeAll(closed)
	return client, err
}

func (c *issuerJWKSCache) touchLocked(e *issuerJWKSEntry, account string) {
	now := c.now()
	e.lastUsed = now
	e.owners[account] = now
}

// sweepLocked drops idle uses and entries (at most once a minute unless
// forced) and enforces the per-account and total caps, least recently used
// first.
func (c *issuerJWKSCache) sweepLocked(force bool) []*jwks.Client {
	now := c.now()
	if !force && now.Sub(c.lastSweep) < issuerJWKSSweepPeriod {
		return nil
	}
	c.lastSweep = now
	var closed []*jwks.Client
	drop := func(e *issuerJWKSEntry) {
		delete(c.entries, e.key)
		closed = append(closed, e.client)
	}
	perAccount := map[string][]*issuerJWKSEntry{}
	for _, e := range c.entries {
		for acct, used := range e.owners {
			if now.Sub(used) > issuerJWKSIdleTTL {
				delete(e.owners, acct)
			}
		}
		if len(e.owners) == 0 || now.Sub(e.lastUsed) > issuerJWKSIdleTTL {
			drop(e)
			continue
		}
		for acct := range e.owners {
			perAccount[acct] = append(perAccount[acct], e)
		}
	}
	for acct, list := range perAccount {
		for len(list) > issuerJWKSPerAccount {
			victim := list[0]
			for _, e := range list[1:] {
				if e.owners[acct].Before(victim.owners[acct]) {
					victim = e
				}
			}
			delete(victim.owners, acct)
			if len(victim.owners) == 0 {
				drop(victim)
			}
			list = removeEntry(list, victim)
		}
	}
	for len(c.entries) > issuerJWKSTotal {
		var victim *issuerJWKSEntry
		for _, e := range c.entries {
			if victim == nil || e.lastUsed.Before(victim.lastUsed) {
				victim = e
			}
		}
		drop(victim)
	}
	return closed
}

func removeEntry(list []*issuerJWKSEntry, victim *issuerJWKSEntry) []*issuerJWKSEntry {
	out := list[:0]
	for _, e := range list {
		if e != victim {
			out = append(out, e)
		}
	}
	return out
}

func (c *issuerJWKSCache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

func (c *issuerJWKSCache) close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	var closed []*jwks.Client
	for k, e := range c.entries {
		delete(c.entries, k)
		closed = append(closed, e.client)
	}
	c.mu.Unlock()
	closeAll(closed)
}

func closeAll(clients []*jwks.Client) {
	for _, cl := range clients {
		cl.Close()
	}
}
