package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/highflame-ai/zeroid/domain"
)

func TestIsCIMDClientID(t *testing.T) {
	cases := []struct {
		clientID string
		want     bool
	}{
		{"https://app.example.com/oauth/client.json", true},
		{"https://app.example.com/c", true},
		{"https://app.example.com:8443/oauth/client.json", true},
		// query / fragment are still CIMD-shaped (rejected later with a clear error)
		{"https://app.example.com/client.json?x=1", true},
		{"https://app.example.com/client.json#frag", true},
		// not CIMD-shaped → registry lookup
		{"https://app.example.com", false},            // no path
		{"https://app.example.com/", false},           // root path only
		{"http://app.example.com/client.json", false}, // not https
		{"9f43b1c2deadbeef", false},                   // opaque registry client_id
		{"", false},
		{"ftp://host/x", false},
	}
	for _, tc := range cases {
		if got := IsCIMDClientID(tc.clientID); got != tc.want {
			t.Errorf("IsCIMDClientID(%q) = %v, want %v", tc.clientID, got, tc.want)
		}
	}
}

func TestSynthesizeCIMDClient(t *testing.T) {
	const url = "https://app.example.com/oauth/client.json"
	now := time.Unix(1_700_000_000, 0)

	t.Run("minimal valid document", func(t *testing.T) {
		doc := &cimdMetadataDocument{
			ClientID:     url,
			ClientName:   "Example MCP Client",
			RedirectURIs: []string{"http://127.0.0.1:3000/callback"},
		}
		c, err := synthesizeCIMDClient(url, doc, now)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.ClientID != url {
			t.Errorf("ClientID = %q, want %q", c.ClientID, url)
		}
		if c.ClientType != "public" || c.TokenEndpointAuthMethod != "none" {
			t.Errorf("expected public/none, got %q/%q", c.ClientType, c.TokenEndpointAuthMethod)
		}
		if c.RegistrationSource != cimdRegistrationSource {
			t.Errorf("RegistrationSource = %q, want %q", c.RegistrationSource, cimdRegistrationSource)
		}
		if !c.IsActive {
			t.Error("synthesized client should be active")
		}
		// grant_types default to [authorization_code]
		if len(c.GrantTypes) != 1 || c.GrantTypes[0] != string(domain.GrantTypeAuthorizationCode) {
			t.Errorf("GrantTypes = %v, want [authorization_code]", c.GrantTypes)
		}
	})

	// client_name is the string a consent screen shows the user, and a CIMD
	// document's publisher is anonymous by construction — no registration, no
	// secret — so this label is most of what consent has to go on. It used to
	// fall back to the client_id, which made a document that declined to name
	// itself indistinguishable from a well-formed one and let whoever chose the
	// URL choose what the user reads.
	t.Run("missing client_name is rejected", func(t *testing.T) {
		doc := &cimdMetadataDocument{ClientID: url, RedirectURIs: []string{"https://x/cb"}}
		if _, err := synthesizeCIMDClient(url, doc, now); !errors.Is(err, ErrCIMDInvalidDocument) {
			t.Errorf("expected ErrCIMDInvalidDocument for absent client_name, got %v", err)
		}
	})

	t.Run("whitespace-only client_name is rejected", func(t *testing.T) {
		doc := &cimdMetadataDocument{ClientID: url, ClientName: "   \t ", RedirectURIs: []string{"https://x/cb"}}
		if _, err := synthesizeCIMDClient(url, doc, now); !errors.Is(err, ErrCIMDInvalidDocument) {
			t.Errorf("expected ErrCIMDInvalidDocument for whitespace-only client_name, got %v", err)
		}
	})

	t.Run("client_name is carried through verbatim", func(t *testing.T) {
		doc := &cimdMetadataDocument{ClientID: url, ClientName: "Example MCP Client", RedirectURIs: []string{"https://x/cb"}}
		c, err := synthesizeCIMDClient(url, doc, now)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.Name != "Example MCP Client" {
			t.Errorf("Name = %q, want the document's client_name", c.Name)
		}
	})

	t.Run("scope parsed into slice", func(t *testing.T) {
		doc := &cimdMetadataDocument{ClientID: url, ClientName: "N", RedirectURIs: []string{"https://x/cb"}, Scope: "read write"}
		c, err := synthesizeCIMDClient(url, doc, now)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(c.Scopes) != 2 || c.Scopes[0] != "read" || c.Scopes[1] != "write" {
			t.Errorf("Scopes = %v, want [read write]", c.Scopes)
		}
	})

	t.Run("refresh_token grant is allowed", func(t *testing.T) {
		doc := &cimdMetadataDocument{
			ClientID:     url,
			ClientName:   "N",
			RedirectURIs: []string{"https://x/cb"},
			GrantTypes:   []string{"authorization_code", "refresh_token"},
		}
		if _, err := synthesizeCIMDClient(url, doc, now); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	// Rejection cases.
	bad := []struct {
		name string
		doc  *cimdMetadataDocument
	}{
		{"self-reference mismatch", &cimdMetadataDocument{ClientID: "https://evil.example/other.json", ClientName: "N", RedirectURIs: []string{"https://x/cb"}}},
		{"missing redirect_uris", &cimdMetadataDocument{ClientID: url, ClientName: "N"}},
		{"empty redirect_uris", &cimdMetadataDocument{ClientID: url, ClientName: "N", RedirectURIs: []string{}}},
		{"confidential auth method", &cimdMetadataDocument{ClientID: url, ClientName: "N", RedirectURIs: []string{"https://x/cb"}, TokenEndpointAuthMethod: "client_secret_basic"}},
		{"private_key_jwt auth method", &cimdMetadataDocument{ClientID: url, ClientName: "N", RedirectURIs: []string{"https://x/cb"}, TokenEndpointAuthMethod: "private_key_jwt"}},
		{"grant_types missing authorization_code", &cimdMetadataDocument{ClientID: url, ClientName: "N", RedirectURIs: []string{"https://x/cb"}, GrantTypes: []string{"refresh_token"}}},
		{"disallowed grant type", &cimdMetadataDocument{ClientID: url, ClientName: "N", RedirectURIs: []string{"https://x/cb"}, GrantTypes: []string{"authorization_code", "client_credentials"}}},
		{"response_types without code", &cimdMetadataDocument{ClientID: url, ClientName: "N", RedirectURIs: []string{"https://x/cb"}, ResponseTypes: []string{"token"}}},
		{"plaintext non-loopback redirect_uri", &cimdMetadataDocument{ClientID: url, ClientName: "N", RedirectURIs: []string{"http://app.example.com/cb"}}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := synthesizeCIMDClient(url, tc.doc, now); !errors.Is(err, ErrCIMDInvalidDocument) {
				t.Errorf("expected ErrCIMDInvalidDocument, got %v", err)
			}
		})
	}
}

// newCIMDTestServer stands up an HTTPS test server serving a fixed body and
// returns a CIMDService wired to trust it (via the server's own client, which
// bypasses the SSRF-guard/private-IP concern for the loopback test address).
// hits counts document fetches.
func newCIMDTestServer(t *testing.T, cfg CIMDConfig, handler http.HandlerFunc) (*CIMDService, string, *int32) {
	t.Helper()
	var hits int32
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		handler(w, r)
	}))
	t.Cleanup(ts.Close)
	cfg.HTTPClient = ts.Client()
	svc := NewCIMDService(cfg)
	return svc, ts.URL, &hits
}

func docJSON(clientID string, extra string) string {
	return fmt.Sprintf(`{"client_id":%q,"client_name":"Test","redirect_uris":["http://127.0.0.1:9000/cb"]%s}`, clientID, extra)
}

func TestCIMDResolveClient_Success(t *testing.T) {
	var docURL string
	svc, base, hits := newCIMDTestServer(t, CIMDConfig{Enabled: true}, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, docJSON(docURL, `,"scope":"read"`))
	})
	docURL = base + "/oauth/client.json"

	c, err := svc.ResolveClient(context.Background(), docURL)
	if err != nil {
		t.Fatalf("ResolveClient: %v", err)
	}
	if c.ClientID != docURL {
		t.Errorf("ClientID = %q, want %q", c.ClientID, docURL)
	}
	if c.ClientType != "public" {
		t.Errorf("ClientType = %q, want public", c.ClientType)
	}
	if atomic.LoadInt32(hits) != 1 {
		t.Errorf("expected 1 fetch, got %d", *hits)
	}
}

func TestCIMDResolveClient_Disabled(t *testing.T) {
	svc := NewCIMDService(CIMDConfig{Enabled: false})
	if svc.Enabled() {
		t.Fatal("service should be disabled")
	}
	_, err := svc.ResolveClient(context.Background(), "https://app.example.com/client.json")
	if !errors.Is(err, ErrCIMDDisabled) {
		t.Errorf("expected ErrCIMDDisabled, got %v", err)
	}
	// nil receiver is a valid disabled instance.
	var nilSvc *CIMDService
	if nilSvc.Enabled() {
		t.Error("nil *CIMDService should report disabled")
	}
}

func TestCIMDResolveClient_InvalidClientID(t *testing.T) {
	svc := NewCIMDService(CIMDConfig{Enabled: true})
	for _, id := range []string{
		"http://app.example.com/client.json",       // not https
		"https://app.example.com",                  // no path
		"https://app.example.com/client.json?a=b",  // query (draft-02 §3 SHOULD NOT; we reject)
		"https://app.example.com/client.json#frag", // fragment (§3 MUST NOT)

		// Userinfo (§3 MUST NOT). Reads as legit.example.com wherever the
		// client_id is displayed — consent screen, audit log — while resolving
		// to evil.example. Not an allow-list bypass (domainAllowed sees the
		// real host); a spoof of the string a human is asked to trust.
		"https://legit.example.com@evil.example/client.json",
		"https://user:pw@app.example.com/client.json",

		// Dot segments (§3 MUST NOT). Otherwise one document has many
		// spellings, splitting the cache and giving one client several
		// identities the §4 self-reference check cannot tell apart.
		"https://app.example.com/a/../client.json",
		"https://app.example.com/./client.json",
		"https://app.example.com/%2e%2e/client.json", // percent-encoded, decoded by url.Parse
	} {
		if _, err := svc.ResolveClient(context.Background(), id); !errors.Is(err, ErrCIMDInvalidClientID) {
			t.Errorf("ResolveClient(%q): expected ErrCIMDInvalidClientID, got %v", id, err)
		}
	}
}

func TestCIMDResolveClient_SelfReferenceMismatch(t *testing.T) {
	svc, base, _ := newCIMDTestServer(t, CIMDConfig{Enabled: true}, func(w http.ResponseWriter, _ *http.Request) {
		// Document claims a different client_id than its URL.
		fmt.Fprint(w, docJSON("https://evil.example.com/other.json", ""))
	})
	_, err := svc.ResolveClient(context.Background(), base+"/oauth/client.json")
	if !errors.Is(err, ErrCIMDInvalidDocument) {
		t.Errorf("expected ErrCIMDInvalidDocument, got %v", err)
	}
}

func TestCIMDResolveClient_Non200(t *testing.T) {
	svc, base, _ := newCIMDTestServer(t, CIMDConfig{Enabled: true}, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	_, err := svc.ResolveClient(context.Background(), base+"/missing.json")
	if !errors.Is(err, ErrCIMDFetch) {
		t.Errorf("expected ErrCIMDFetch, got %v", err)
	}
}

func TestCIMDResolveClient_SizeCap(t *testing.T) {
	var docURL string
	svc, base, _ := newCIMDTestServer(t, CIMDConfig{Enabled: true, MaxDocumentBytes: 64}, func(w http.ResponseWriter, _ *http.Request) {
		// Pad the document well past the 64-byte cap.
		fmt.Fprint(w, docJSON(docURL, `,"client_uri":"`+strings.Repeat("a", 200)+`"`))
	})
	docURL = base + "/big.json"
	_, err := svc.ResolveClient(context.Background(), docURL)
	if !errors.Is(err, ErrCIMDInvalidDocument) {
		t.Errorf("expected ErrCIMDInvalidDocument (oversize), got %v", err)
	}
}

func TestCIMDResolveClient_DomainAllowlist(t *testing.T) {
	var docURL string
	handler := func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, docJSON(docURL, "")) }

	// Allowlist containing the wrong host → rejected before fetch.
	svcDeny, base, hits := newCIMDTestServer(t, CIMDConfig{Enabled: true, AllowedDomains: []string{"other.example.com"}}, handler)
	docURL = base + "/client.json"
	if _, err := svcDeny.ResolveClient(context.Background(), docURL); !errors.Is(err, ErrCIMDDomainNotAllowed) {
		t.Errorf("expected ErrCIMDDomainNotAllowed, got %v", err)
	}
	if atomic.LoadInt32(hits) != 0 {
		t.Errorf("allowlist rejection must not fetch; got %d fetches", *hits)
	}

	// Allowlist containing 127.0.0.1 (the test server host) → allowed.
	svcAllow, base2, _ := newCIMDTestServer(t, CIMDConfig{Enabled: true, AllowedDomains: []string{"127.0.0.1"}}, handler)
	docURL = base2 + "/client.json"
	if _, err := svcAllow.ResolveClient(context.Background(), docURL); err != nil {
		t.Errorf("allowlisted host should resolve, got %v", err)
	}
}

// TestCIMDAllowedDomainCount_ReportsEffectivePolicy — the constructor lower-cases
// and drops blank/whitespace-only entries, so the raw config slice and the policy
// actually in force disagree. They disagree in the worst direction: a config of
// allowed_domains: [""] has length 1 but admits every host, so anything reading
// the raw slice reports a locked-down deployment at the exact moment it is wide
// open. That is what the startup warning in NewServer keys on.
func TestCIMDAllowedDomainCount_ReportsEffectivePolicy(t *testing.T) {
	cases := []struct {
		name    string
		domains []string
		want    int
	}{
		{"nil is open mode", nil, 0},
		{"empty is open mode", []string{}, 0},
		{"single blank entry is STILL open mode", []string{""}, 0},
		{"whitespace-only entries are still open mode", []string{"  ", "\t", "\n"}, 0},
		{"one real domain", []string{"client.example.com"}, 1},
		{"blanks alongside a real domain do not inflate the count", []string{"", "client.example.com", "   "}, 1},
		{"case-insensitive duplicates collapse", []string{"Client.Example.com", "client.example.com"}, 1},
		{"two distinct domains", []string{"a.example.com", "b.example.com"}, 2},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := NewCIMDService(CIMDConfig{Enabled: true, AllowedDomains: tc.domains})
			if got := svc.AllowedDomainCount(); got != tc.want {
				t.Errorf("AllowedDomainCount() = %d, want %d (raw slice length %d)",
					got, tc.want, len(tc.domains))
			}
		})
	}

	// Nil-safe, matching Enabled().
	var nilSvc *CIMDService
	if got := nilSvc.AllowedDomainCount(); got != 0 {
		t.Errorf("nil *CIMDService AllowedDomainCount() = %d, want 0", got)
	}
}

// TestCIMDBlankAllowedDomainIsOpenMode is the behavioural half of the above: a
// blank-only allow-list must not merely count as zero, it must actually admit a
// host that no entry names.
func TestCIMDBlankAllowedDomainIsOpenMode(t *testing.T) {
	var docURL string
	handler := func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, docJSON(docURL, "")) }

	svc, base, _ := newCIMDTestServer(t,
		CIMDConfig{Enabled: true, AllowedDomains: []string{"", "   "}}, handler)
	docURL = base + "/client.json"

	if _, err := svc.ResolveClient(context.Background(), docURL); err != nil {
		t.Errorf("a blank-only allowlist is open mode and must admit any host, got %v", err)
	}
}

func TestCIMDResolveClient_Cache(t *testing.T) {
	var docURL string
	svc, base, hits := newCIMDTestServer(t, CIMDConfig{Enabled: true, CacheTTL: time.Hour}, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, docJSON(docURL, ""))
	})
	docURL = base + "/client.json"

	// Drive time deterministically.
	current := time.Unix(1_700_000_000, 0)
	svc.now = func() time.Time { return current }

	if _, err := svc.ResolveClient(context.Background(), docURL); err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	if _, err := svc.ResolveClient(context.Background(), docURL); err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if got := atomic.LoadInt32(hits); got != 1 {
		t.Errorf("cache hit expected; got %d fetches, want 1", got)
	}

	// Advance past the TTL → refetch.
	current = current.Add(2 * time.Hour)
	if _, err := svc.ResolveClient(context.Background(), docURL); err != nil {
		t.Fatalf("third resolve: %v", err)
	}
	if got := atomic.LoadInt32(hits); got != 2 {
		t.Errorf("expired entry should refetch; got %d fetches, want 2", got)
	}
}

func TestCIMDResolveClient_NegativeCache(t *testing.T) {
	svc, base, hits := newCIMDTestServer(t, CIMDConfig{Enabled: true}, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	docURL := base + "/broken.json"

	current := time.Unix(1_700_000_000, 0)
	svc.now = func() time.Time { return current }

	for i := 0; i < 3; i++ {
		if _, err := svc.ResolveClient(context.Background(), docURL); !errors.Is(err, ErrCIMDFetch) {
			t.Fatalf("attempt %d: expected ErrCIMDFetch, got %v", i, err)
		}
	}
	if got := atomic.LoadInt32(hits); got != 1 {
		t.Errorf("failure should be negative-cached; got %d fetches, want 1", got)
	}

	// Past the negative TTL the URL is retried.
	current = current.Add(cimdNegativeCacheTTL + time.Second)
	_, _ = svc.ResolveClient(context.Background(), docURL)
	if got := atomic.LoadInt32(hits); got != 2 {
		t.Errorf("expired negative entry should refetch; got %d fetches, want 2", got)
	}
}

func TestCIMDResolveClient_NoRedirectFollow(t *testing.T) {
	var docURL string
	svc, base, _ := newCIMDTestServer(t, CIMDConfig{Enabled: true}, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/moved.json" {
			http.Redirect(w, r, "/real.json", http.StatusMovedPermanently)
			return
		}
		fmt.Fprint(w, docJSON(docURL, ""))
	})
	docURL = base + "/moved.json"
	// The redirect must NOT be followed — a 3xx is a fetch failure.
	if _, err := svc.ResolveClient(context.Background(), docURL); !errors.Is(err, ErrCIMDFetch) {
		t.Errorf("expected ErrCIMDFetch on redirect, got %v", err)
	}
}

func TestCIMDResolveClient_ClientIDLengthCap(t *testing.T) {
	svc := NewCIMDService(CIMDConfig{Enabled: true})
	long := "https://app.example.com/" + strings.Repeat("a", maxCIMDClientIDLength) + ".json"
	if _, err := svc.ResolveClient(context.Background(), long); !errors.Is(err, ErrCIMDInvalidClientID) {
		t.Errorf("expected ErrCIMDInvalidClientID for oversize client_id, got %v", err)
	}
}

func TestCIMDCacheEviction(t *testing.T) {
	var docURL string
	svc, base, _ := newCIMDTestServer(t, CIMDConfig{Enabled: true}, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"client_id":%q,"client_name":"Evict","redirect_uris":["https://x/cb"]}`, docURL)
	})
	svc.maxCacheEntries = 2

	for i := 0; i < 5; i++ {
		docURL = fmt.Sprintf("%s/c%d.json", base, i)
		if _, err := svc.ResolveClient(context.Background(), docURL); err != nil {
			t.Fatalf("resolve %d: %v", i, err)
		}
	}
	svc.mu.Lock()
	size := len(svc.cache)
	svc.mu.Unlock()
	if size > 2 {
		t.Errorf("cache grew past cap: %d entries, cap 2", size)
	}
}

func TestValidateCIMDRedirectURI(t *testing.T) {
	cases := []struct {
		uri string
		ok  bool
	}{
		{"https://app.example.com/callback", true},
		{"http://127.0.0.1:3000/callback", true},
		{"http://localhost:3000/callback", true},
		{"http://[::1]:3000/callback", true},
		{"myapp://oauth/callback", true},           // private-use scheme (native app)
		{"http://app.example.com/callback", false}, // plaintext non-loopback
		{"/relative/callback", false},
		{"://bad", false},
		{"https:/cb", false},                          // rootless — url.Parse accepts, no host
		{"https://", false},                           // no host
		{"https://app.example.com/cb#frag", false},    // fragment not allowed
		{"https://user:pw@app.example.com/cb", false}, // userinfo not allowed
		{"", false}, // empty
	}
	for _, tc := range cases {
		err := validateCIMDRedirectURI(tc.uri)
		if (err == nil) != tc.ok {
			t.Errorf("validateCIMDRedirectURI(%q) = %v, want ok=%v", tc.uri, err, tc.ok)
		}
	}
}

func TestCIMDCacheTTLClamp(t *testing.T) {
	// TTL above the 24h hard cap is clamped.
	svc := NewCIMDService(CIMDConfig{Enabled: true, CacheTTL: 100 * time.Hour})
	if svc.cacheTTL != maxCIMDCacheTTL {
		t.Errorf("cacheTTL = %v, want clamp to %v", svc.cacheTTL, maxCIMDCacheTTL)
	}
	// Zero → default.
	svc2 := NewCIMDService(CIMDConfig{Enabled: true})
	if svc2.cacheTTL != defaultCIMDCacheTTL {
		t.Errorf("cacheTTL = %v, want default %v", svc2.cacheTTL, defaultCIMDCacheTTL)
	}
	if svc2.maxDocumentBytes != defaultCIMDMaxDocumentBytes {
		t.Errorf("maxDocumentBytes = %d, want default %d", svc2.maxDocumentBytes, defaultCIMDMaxDocumentBytes)
	}
}

// TestCIMDCacheReturnsIndependentCopies pins that a cache hit hands back a
// client whose slice fields don't alias the cached entry — mutating a returned
// client must not corrupt what the next resolution sees.
func TestCIMDCacheReturnsIndependentCopies(t *testing.T) {
	var docURL string
	svc, base, hits := newCIMDTestServer(t, CIMDConfig{Enabled: true, CacheTTL: time.Hour}, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, docJSON(docURL, `,"scope":"read write"`))
	})
	docURL = base + "/oauth/client.json"

	ctx := context.Background()
	first, err := svc.ResolveClient(ctx, docURL)
	if err != nil {
		t.Fatalf("first ResolveClient: %v", err)
	}
	// Mutate every slice field on the returned copy.
	first.RedirectURIs[0] = "https://evil.example.com/cb"
	first.Scopes[0] = "admin"
	first.GrantTypes[0] = "implicit"

	second, err := svc.ResolveClient(ctx, docURL) // served from cache (hits stays 1)
	if err != nil {
		t.Fatalf("second ResolveClient: %v", err)
	}
	if atomic.LoadInt32(hits) != 1 {
		t.Fatalf("expected cache hit (1 fetch), got %d", *hits)
	}
	if second.RedirectURIs[0] == "https://evil.example.com/cb" {
		t.Error("RedirectURIs leaked a mutation from a prior returned copy")
	}
	if second.Scopes[0] == "admin" {
		t.Error("Scopes leaked a mutation from a prior returned copy")
	}
	if second.GrantTypes[0] == "implicit" {
		t.Error("GrantTypes leaked a mutation from a prior returned copy")
	}
}

func TestCIMDPositiveCacheTTL(t *testing.T) {
	s := NewCIMDService(CIMDConfig{Enabled: true, CacheTTL: time.Hour})
	cases := []struct {
		header string
		want   time.Duration
	}{
		{"", time.Hour},                              // no header → configured TTL
		{"max-age=600", 10 * time.Minute},            // shorter max-age honored
		{"max-age=86400", time.Hour},                 // longer max-age never extends
		{"max-age=5", cimdPositiveCacheFloor},        // tiny max-age clamped to floor
		{"max-age=0", cimdPositiveCacheFloor},        // zero clamped to floor
		{"no-store", cimdPositiveCacheFloor},         // no-store → floor, not zero
		{"public, no-cache", cimdPositiveCacheFloor}, // no-cache among other directives
		{"MAX-AGE=600", 10 * time.Minute},            // case-insensitive
		{"max-age=bogus", time.Hour},                 // unparseable → configured TTL
		{"max-age=-5", time.Hour},                    // negative → configured TTL
	}
	for _, tc := range cases {
		if got := s.positiveCacheTTL(tc.header); got != tc.want {
			t.Errorf("positiveCacheTTL(%q) = %v, want %v", tc.header, got, tc.want)
		}
	}
}

// TestRedirectHostsAllowed is the check that makes cimd.allowed_domains mean
// what the authorize-handler gate assumes it means.
//
// That gate (API.refusesRedirectTo) reads "an allow-listed publisher is a vetted
// party, so §4.1.2.1 redirects and the interactive-login redirect apply again."
// Allow-listing the client_id host alone does not establish that: on any host
// where more than one party can publish a path — user content, a raw-file CDN, a
// bucket with broad write, a shared internal app host — an attacker publishes a
// document naming redirect_uri https://evil.example/cb and gets an
// unauthenticated 302 to evil.example, plus a victim walked through the real
// login page first. The redirect destination has to be vetted too, or the switch
// re-opens what the carve-out closed.
func TestRedirectHostsAllowed(t *testing.T) {
	svc := NewCIMDService(CIMDConfig{Enabled: true, AllowedDomains: []string{"apps.acme.dev"}})

	const publisher = "apps.acme.dev"

	t.Run("same host as client_id passes unlisted", func(t *testing.T) {
		// The ordinary case: a document names callbacks on the host that
		// published it. Requiring that host to also appear in the allow-list
		// would be redundant — it is already there, since it resolved at all.
		if err := svc.redirectHostsAllowed(publisher, []string{"https://apps.acme.dev/cb"}); err != nil {
			t.Fatalf("same-host redirect must pass: %v", err)
		}
	})

	t.Run("another allow-listed host passes", func(t *testing.T) {
		svc2 := NewCIMDService(CIMDConfig{
			Enabled:        true,
			AllowedDomains: []string{"apps.acme.dev", "cb.acme.dev"},
		})
		if err := svc2.redirectHostsAllowed(publisher, []string{"https://cb.acme.dev/cb"}); err != nil {
			t.Fatalf("a vetted destination host must pass: %v", err)
		}
	})

	t.Run("foreign https host is refused", func(t *testing.T) {
		err := svc.redirectHostsAllowed(publisher, []string{"https://evil.example/cb"})
		if !errors.Is(err, ErrCIMDDomainNotAllowed) {
			t.Fatalf("want ErrCIMDDomainNotAllowed, got %v", err)
		}
	})

	t.Run("one bad entry poisons the document", func(t *testing.T) {
		// Not "drop the bad one and keep going": the client would then hold a
		// redirect_uris list the deployer never approved, and redirectURIAllowed
		// matches against whichever entry the request names.
		err := svc.redirectHostsAllowed(publisher, []string{
			"https://apps.acme.dev/cb",
			"https://evil.example/cb",
		})
		if !errors.Is(err, ErrCIMDDomainNotAllowed) {
			t.Fatalf("want ErrCIMDDomainNotAllowed, got %v", err)
		}
	})

	t.Run("loopback and private-use schemes are exempt", func(t *testing.T) {
		// These deliver to the caller's own machine, not to a host anybody
		// publishes to, so a deployment-wide host allow-list has nothing to say
		// about them — and they are the native/MCP client shape.
		for _, ru := range []string{
			"http://127.0.0.1:9000/cb",
			"http://localhost:9000/cb",
			"myapp:/cb",
		} {
			if err := svc.redirectHostsAllowed(publisher, []string{ru}); err != nil {
				t.Errorf("%s must stay usable: %v", ru, err)
			}
		}
	})

	t.Run("open mode constrains nothing", func(t *testing.T) {
		// domainAllowed admits every host with no allow-list, so this is a
		// no-op there — correctly: open mode refuses these redirects outright,
		// so there is no vetting claim to keep honest.
		open := NewCIMDService(CIMDConfig{Enabled: true})
		if err := open.redirectHostsAllowed(publisher, []string{"https://anywhere.example/cb"}); err != nil {
			t.Fatalf("open mode must not reject: %v", err)
		}
	})

	t.Run("host match is case-insensitive", func(t *testing.T) {
		if err := svc.redirectHostsAllowed("APPS.ACME.DEV", []string{"https://apps.acme.dev/cb"}); err != nil {
			t.Fatalf("host comparison must be case-insensitive: %v", err)
		}
	})
}

// TestRedirectDeliversLocally pins the reachability judgement the authorize
// carve-out delegates to. A false negative costs the native/MCP browser leg; a
// false positive hands an attacker-chosen remote host a redirect from the AS's
// own origin. The look-alike case is the one worth having a test for.
func TestRedirectDeliversLocally(t *testing.T) {
	local := []string{
		"http://127.0.0.1:3000/callback",
		"http://localhost/cb",
		"http://[::1]:8080/cb",
		"myapp:/cb",
		"com.example.app:/oauth",
	}
	remote := []string{
		"https://app.example.com/cb",
		"https://127.0.0.1/cb",         // https is remote-capable regardless of host
		"http://127.0.0.1.evil.com/cb", // look-alike: not loopback
		"http://evil.example/cb",
		"/relative/cb", // no scheme — validateCIMDRedirectURI rejects; fail closed
	}

	for _, u := range local {
		if !RedirectDeliversLocally(u) {
			t.Errorf("%s must count as local delivery — refusing it breaks native clients", u)
		}
	}

	for _, u := range remote {
		if RedirectDeliversLocally(u) {
			t.Errorf("%s must NOT count as local delivery", u)
		}
	}
}
