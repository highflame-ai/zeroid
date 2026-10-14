package service

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/pkg/jwks"
)

// fakeIssuerRows is an in-memory issuer row source whose rows a test edits
// between lookups, the way an admin edits the table between requests.
type fakeIssuerRows struct {
	mu    sync.Mutex
	rows  []*domain.ExternalIssuer
	calls int
	err   error
}

func (f *fakeIssuerRows) ListByIssuer(_ context.Context, iss string) ([]*domain.ExternalIssuer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	var out []*domain.ExternalIssuer
	for _, r := range f.rows {
		if r.Issuer == iss {
			c := *r
			out = append(out, &c)
		}
	}
	return out, nil
}

func (f *fakeIssuerRows) set(mut func([]*domain.ExternalIssuer)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	mut(f.rows)
}

func issuerRow(id, acct, iss string, kind domain.IssuerKind, jwksURI string) *domain.ExternalIssuer {
	return &domain.ExternalIssuer{
		ID: id, AccountID: acct, Issuer: iss, Kind: kind, JWKSURI: jwksURI,
		Audiences: []string{"aud"}, Algorithms: []string{"ES256"}, Enabled: true,
		ClaimMapping: map[string]string{"user_id": "sub"}, ClaimConstraints: map[string][]string{},
		MaxTokenAgeSeconds: 600, JWKSCacheTTLSeconds: 300, UpdatedAt: time.Unix(1, 0),
	}
}

func TestDBRegistry_ResolvePerson(t *testing.T) {
	jwksSrv := newFakeJWKSServer(t, "k1")
	const iss = "https://idp.example"
	rows := &fakeIssuerRows{rows: []*domain.ExternalIssuer{issuerRow("r1", "acct-a", iss, domain.IssuerKindPerson, jwksSrv.srv.URL)}}
	reg := NewDBExternalIssuerRegistry(rows, true, jwks.WithHTTPClient(insecureHTTPClient(2*time.Second)))
	defer reg.Close()
	ctx := context.Background()

	entry, err := reg.ResolvePerson(ctx, iss, nil)
	if err != nil {
		t.Fatal(err)
	}
	if entry.Row == nil || entry.Row.ID != "r1" || entry.Config.AllowedAccounts[0] != "acct-a" {
		t.Fatalf("entry = %+v", entry)
	}

	t.Run("unknown issuer", func(t *testing.T) {
		if _, err := reg.ResolvePerson(ctx, "https://nobody", nil); !errors.Is(err, ErrUnknownExternalIssuer) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("rows are read live: a disable applies at the next lookup", func(t *testing.T) {
		before := rows.calls
		rows.set(func(r []*domain.ExternalIssuer) { r[0].Enabled = false })
		if _, err := reg.ResolvePerson(ctx, iss, nil); !errors.Is(err, errIssuerDisabled) {
			t.Fatalf("err = %v", err)
		}
		if rows.calls != before+1 {
			t.Fatal("every resolution reads the store; no row cache")
		}
		rows.set(func(r []*domain.ExternalIssuer) { r[0].Enabled = true })
		if _, err := reg.ResolvePerson(ctx, iss, nil); err != nil {
			t.Fatalf("re-enabled: %v", err)
		}
	})
	t.Run("a deleted row is unknown at the next lookup", func(t *testing.T) {
		rows.mu.Lock()
		saved := rows.rows
		rows.rows = nil
		rows.mu.Unlock()
		if _, err := reg.ResolvePerson(ctx, iss, nil); !errors.Is(err, ErrUnknownExternalIssuer) {
			t.Fatalf("err = %v", err)
		}
		rows.mu.Lock()
		rows.rows = saved
		rows.mu.Unlock()
	})
	t.Run("a workload row is not a person issuer", func(t *testing.T) {
		rows.set(func(r []*domain.ExternalIssuer) { r[0].Kind = domain.IssuerKindWorkload })
		defer rows.set(func(r []*domain.ExternalIssuer) { r[0].Kind = domain.IssuerKindPerson })
		if _, err := reg.ResolvePerson(ctx, iss, nil); !errors.Is(err, errIssuerNotPerson) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("store failure fails closed", func(t *testing.T) {
		rows.mu.Lock()
		rows.err = errors.New("db down")
		rows.mu.Unlock()
		defer func() { rows.mu.Lock(); rows.err = nil; rows.mu.Unlock() }()
		if _, err := reg.ResolvePerson(ctx, iss, nil); !errors.Is(err, errIssuerLookupFailed) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestDBRegistry_SharedIssuerConstraints(t *testing.T) {
	jwksSrv := newFakeJWKSServer(t, "k1")
	const iss = "https://accounts.google.com"
	a := issuerRow("ra", "acct-a", iss, domain.IssuerKindPerson, jwksSrv.srv.URL)
	a.ClaimConstraints = map[string][]string{"hd": {"a.com"}}
	b := issuerRow("rb", "acct-b", iss, domain.IssuerKindPerson, jwksSrv.srv.URL)
	b.ClaimConstraints = map[string][]string{"hd": {"b.com"}}
	rows := &fakeIssuerRows{rows: []*domain.ExternalIssuer{a, b}}
	reg := NewDBExternalIssuerRegistry(rows, true, jwks.WithHTTPClient(insecureHTTPClient(2*time.Second)))
	defer reg.Close()
	ctx := context.Background()

	entry, err := reg.ResolvePerson(ctx, iss, map[string]any{"hd": "b.com"})
	if err != nil || entry.Row.AccountID != "acct-b" {
		t.Fatalf("entry %+v err %v", entry, err)
	}
	if _, err := reg.ResolvePerson(ctx, iss, map[string]any{"hd": "c.com"}); !errors.Is(err, errIssuerConstraints) {
		t.Fatalf("no row matches: %v", err)
	}
	rows.set(func(r []*domain.ExternalIssuer) { r[1].ClaimConstraints = map[string][]string{"hd": {"a.com"}} })
	if _, err := reg.ResolvePerson(ctx, iss, map[string]any{"hd": "a.com"}); !errors.Is(err, errIssuerAmbiguous) {
		t.Fatalf("two rows match: %v", err)
	}
}

func TestStaticRegistry_ResolvePersonKind(t *testing.T) {
	jwksSrv := newFakeJWKSServer(t, "k1")
	reg, err := NewExternalIssuerRegistry(context.Background(), []domain.ExternalIssuerConfig{
		{Issuer: "https://person", JWKSURI: jwksSrv.srv.URL, Audience: "a", JWKSCacheTTL: time.Minute},
		{Issuer: "https://workload", JWKSURI: jwksSrv.srv.URL, Audience: "a", Kind: domain.IssuerKindWorkload, JWKSCacheTTL: time.Minute},
	}, jwks.WithHTTPClient(insecureHTTPClient(2*time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()
	if _, err := reg.ResolvePerson(context.Background(), "https://person", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.ResolvePerson(context.Background(), "https://workload", nil); !errors.Is(err, errIssuerNotPerson) {
		t.Fatalf("a static workload issuer is refused on person grants: %v", err)
	}
}

// refusedURL is a JWKS URL nothing listens on, so jwks.New returns at once.
const refusedURL = "http://127.0.0.1:1/keys"

func TestIssuerJWKSCache_SharingAndEviction(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	c := newIssuerJWKSCache(nil)
	c.now = func() time.Time { return now }
	defer c.close()

	row := issuerRow("r1", "acct", "https://i", domain.IssuerKindPerson, refusedURL)
	first, err := c.get(row)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("rows with the same key set share a client, across accounts", func(t *testing.T) {
		other := issuerRow("r9", "acct-2", "https://i2", domain.IssuerKindPerson, refusedURL)
		got, _ := c.get(other)
		if got != first || c.size() != 1 {
			t.Fatalf("shared = %v, size %d", got == first, c.size())
		}
	})
	t.Run("a re-discovered jwks_uri gets its own client", func(t *testing.T) {
		moved := *row
		moved.JWKSURI = refusedURL + "?v=2"
		got, _ := c.get(&moved)
		if got == first {
			t.Fatal("a new jwks_uri must not reuse the old client")
		}
	})
	t.Run("an idle client is evicted", func(t *testing.T) {
		live := issuerRow("r2", "acct", "https://j", domain.IssuerKindPerson, refusedURL+"?live")
		if _, err := c.get(live); err != nil {
			t.Fatal(err)
		}
		now = now.Add(issuerJWKSIdleTTL + 2*issuerJWKSSweepPeriod)
		if _, err := c.get(live); err != nil {
			t.Fatal(err)
		}
		c.mu.Lock()
		_, kept := c.entries[issuerJWKSKey(row)]
		c.mu.Unlock()
		if kept {
			t.Fatal("the first key set sat idle past the TTL and must be gone")
		}
	})
	t.Run("per-account cap evicts only that account's use", func(t *testing.T) {
		shared := issuerRow("s", "quiet", "https://s", domain.IssuerKindPerson, refusedURL+"?shared")
		if _, err := c.get(shared); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < issuerJWKSPerAccount+5; i++ {
			now = now.Add(time.Millisecond)
			r := issuerRow(fmt.Sprintf("cap-%d", i), "busy", "https://x", domain.IssuerKindPerson, fmt.Sprintf("%s?cap=%d", refusedURL, i))
			if i == 0 {
				r.JWKSURI = shared.JWKSURI
			}
			if _, err := c.get(r); err != nil {
				t.Fatal(err)
			}
		}
		c.mu.Lock()
		n := 0
		for _, e := range c.entries {
			if _, ok := e.owners["busy"]; ok {
				n++
			}
		}
		_, sharedKept := c.entries[issuerJWKSKey(shared)]
		c.mu.Unlock()
		if n != issuerJWKSPerAccount {
			t.Fatalf("busy uses %d clients, cap %d", n, issuerJWKSPerAccount)
		}
		if !sharedKept {
			t.Fatal("busy's churn must not close a client another account still uses")
		}
	})
}

func TestIssuerJWKSCache_SingleFlight(t *testing.T) {
	c := newIssuerJWKSCache(nil)
	defer c.close()
	var made atomic.Int64
	c.newClient = func(url string, opts ...jwks.Option) (*jwks.Client, error) {
		made.Add(1)
		time.Sleep(50 * time.Millisecond)
		return jwks.New(url, opts...)
	}
	var wg sync.WaitGroup
	clients := make([]*jwks.Client, 10)
	for i := range clients {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			clients[i], _ = c.get(issuerRow(fmt.Sprintf("r%d", i), fmt.Sprintf("acct-%d", i), "https://i", domain.IssuerKindPerson, refusedURL))
		}(i)
	}
	wg.Wait()
	if made.Load() != 1 {
		t.Fatalf("a cold key set was fetched %d times, want 1", made.Load())
	}
	for _, cl := range clients {
		if cl != clients[0] {
			t.Fatal("every caller gets the one client")
		}
	}
}

func TestIssuerJWKSCache_TotalCap(t *testing.T) {
	if testing.Short() {
		t.Skip("creates a thousand JWKS clients")
	}
	now := time.Unix(1_000_000, 0)
	c := newIssuerJWKSCache(nil)
	c.now = func() time.Time { return now }
	defer c.close()
	for i := 0; i < issuerJWKSTotal+10; i++ {
		now = now.Add(time.Millisecond)
		row := issuerRow(fmt.Sprintf("t-%d", i), fmt.Sprintf("acct-%d", i), "https://x", domain.IssuerKindPerson, fmt.Sprintf("%s?n=%d", refusedURL, i))
		if _, err := c.get(row); err != nil {
			t.Fatal(err)
		}
	}
	if c.size() != issuerJWKSTotal {
		t.Fatalf("size = %d, cap %d", c.size(), issuerJWKSTotal)
	}
}
