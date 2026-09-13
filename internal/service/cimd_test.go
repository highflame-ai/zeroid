package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
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
		// NOTE: a document listing a grant outside the allow-list is NO LONGER
		// rejected (zeroid#344) — the extra entry is dropped and the client is
		// synthesized with the intersection. That the DROPPED grant cannot then
		// be obtained is asserted in TestEffectiveCIMDGrantTypes and
		// TestSynthesizeCIMDClient_UnsupportedGrantsAreDroppedNotRejected.
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

// TestCIMDResolveClient_OffListRedirectURIRefused pins the invariant the
// authorize-handler gate depends on but cannot see.
//
// Once cimd.allowed_domains names a host, API.refusesRedirectTo stops refusing
// redirects for self-asserted clients deployment-wide — it does NOT re-check the
// individual client's redirect host. That is only safe if resolution has already
// refused any document declaring an off-list https redirect_uri. Vetting the
// PUBLICATION host is not enough: on any host where more than one party can
// publish a path, an attacker publishes a document on the allow-listed host
// naming redirect_uri https://evil.example/cb and gets an unauthenticated 302.
//
// TestRedirectHostsAllowed covers the predicate in isolation. This covers the
// wiring — that ResolveClient actually calls it — which is the part that can
// silently disappear. It did: rebasing this branch onto the #312 singleflight
// refactor moved the fetch into resolveUncached and severed this call. That
// break happened to be a compile error, so it surfaced; a refactor that left a
// same-named host variable in scope would have kept compiling while vetting the
// wrong host, and no existing test would have noticed.
func TestCIMDResolveClient_OffListRedirectURIRefused(t *testing.T) {
	// The document is served BY the allow-listed host (the httptest server binds
	// 127.0.0.1), so publication-host vetting passes and the redirect host is the
	// only thing left to catch this.
	doc := func(clientID, redirectURI string) string {
		return fmt.Sprintf(
			`{"client_id":%q,"client_name":"Test","redirect_uris":[%q]}`,
			clientID, redirectURI,
		)
	}

	t.Run("off-list https redirect host is refused at resolution", func(t *testing.T) {
		var docURL string
		svc, base, _ := newCIMDTestServer(t,
			CIMDConfig{Enabled: true, AllowedDomains: []string{"127.0.0.1"}},
			func(w http.ResponseWriter, _ *http.Request) {
				fmt.Fprint(w, doc(docURL, "https://evil.example/cb"))
			})
		docURL = base + "/client.json"

		_, err := svc.ResolveClient(context.Background(), docURL)
		if !errors.Is(err, ErrCIMDDomainNotAllowed) {
			t.Fatalf("a document on an allow-listed host declaring an off-list https "+
				"redirect_uri must be refused: got %v", err)
		}
	})

	t.Run("redirect host on the allow-list resolves", func(t *testing.T) {
		// The control. Without it the test above would still pass if resolution
		// rejected every https redirect_uri, which would break real clients.
		var docURL string
		svc, base, _ := newCIMDTestServer(t,
			CIMDConfig{Enabled: true, AllowedDomains: []string{"127.0.0.1"}},
			func(w http.ResponseWriter, _ *http.Request) {
				fmt.Fprint(w, doc(docURL, "https://127.0.0.1/cb"))
			})
		docURL = base + "/client.json"

		if _, err := svc.ResolveClient(context.Background(), docURL); err != nil {
			t.Fatalf("a redirect host that is itself allow-listed must resolve: %v", err)
		}
	})
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

// TestCIMDResolveClient_CoalescesConcurrentFetches pins that N simultaneous
// first-time resolutions of one client_id perform ONE outbound fetch.
//
// The cache alone cannot provide this: it is only populated once a fetch has
// completed, so before that every arriving request is a miss and starts its
// own fetch. N concurrent requests for the same new client_id meant N DNS
// resolutions, N TLS handshakes, and N × up-to-5s of request occupancy for a
// document that is byte-identical every time — reachable without a credential,
// since client resolution runs ahead of the principal chain.
//
// The handler blocks until every caller has arrived, so the test fails if the
// implementation serialises rather than coalesces: without singleflight all
// concurrent callers reach the handler and the barrier releases, and the fetch
// count is N.
func TestCIMDResolveClient_CoalescesConcurrentFetches(t *testing.T) {
	const callers = 8

	var docURL string

	release := make(chan struct{})
	arrived := make(chan struct{}, callers)

	svc, base, hits := newCIMDTestServer(t, CIMDConfig{Enabled: true, CacheTTL: time.Hour},
		func(w http.ResponseWriter, _ *http.Request) {
			// Hold the first fetch open so the other callers are guaranteed to
			// be inside ResolveClient while it is still in flight. Without
			// this the first could complete and populate the cache before the
			// others start, and the test would pass for the wrong reason.
			arrived <- struct{}{}
			<-release
			fmt.Fprint(w, docJSON(docURL, ""))
		})
	docURL = base + "/client.json"

	var wg sync.WaitGroup

	results := make([]*domain.OAuthClient, callers)
	errs := make([]error, callers)

	for i := range callers {
		wg.Add(1)

		go func() {
			defer wg.Done()

			results[i], errs[i] = svc.ResolveClient(context.Background(), docURL)
		}()
	}

	// Exactly one caller should reach the handler; let it finish.
	<-arrived
	close(release)
	wg.Wait()

	if got := atomic.LoadInt32(hits); got != 1 {
		t.Errorf("concurrent resolutions performed %d fetches, want 1 — "+
			"they are not being coalesced, so an unauthenticated caller can "+
			"multiply outbound work by simply issuing requests in parallel", got)
	}

	for i := range callers {
		if errs[i] != nil {
			t.Fatalf("caller %d: %v", i, errs[i])
		}

		if results[i] == nil {
			t.Fatalf("caller %d got a nil client", i)
		}

		if results[i].ClientID != docURL {
			t.Errorf("caller %d: client_id = %q, want %q", i, results[i].ClientID, docURL)
		}
	}

	// Every waiter must hold its OWN client. singleflight hands the same value
	// to all of them, so without a per-caller clone one caller mutating its
	// result would corrupt what the others are holding — the same reason
	// cachedResult returns a copy.
	for i := 1; i < callers; i++ {
		if results[i] == results[0] {
			t.Fatalf("caller %d shares a *domain.OAuthClient with caller 0; "+
				"singleflight results must be cloned per caller", i)
		}
	}

	results[0].RedirectURIs[0] = "https://mutated.example/cb"

	if results[1].RedirectURIs[0] == "https://mutated.example/cb" {
		t.Error("mutating one caller's RedirectURIs changed another's — the " +
			"slice is shared, so the clone is shallow where it must be deep")
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
		// Userinfo confusion: the authority is `evil.com`, and `127.0.0.1` is a
		// username. Anything eyeballing the prefix — or splitting on the wrong
		// delimiter — reads this as loopback and hands an authorization code to
		// evil.com. url.Parse().Hostname() gets it right; this pins that we keep
		// using it rather than string-matching the raw URI.
		"http://127.0.0.1@evil.com/cb",
		// Browsers commonly normalise 0.0.0.0 to loopback, so a client could
		// plausibly listen there. We classify it remote, which fails CLOSED: the
		// redirect is refused rather than wrongly trusted. Pinned so the choice
		// is deliberate — widening it later is a security decision, not a typo fix.
		"http://0.0.0.0/cb",
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

// effectiveCIMDGrantTypes narrows rather than rejects (zeroid#344).
//
// A CIMD document is one declaration published to EVERY authorization server the
// client talks to — there is no registration response and no way to tailor it
// per server. Rejecting the whole document because it mentions a grant this
// server does not implement made such a client unable to log in at all, with an
// error it could not act on and could not fix without breaking its other
// servers.
func TestEffectiveCIMDGrantTypes(t *testing.T) {
	cases := []struct {
		name        string
		declared    []string
		wantKept    []string
		wantDropped []string
	}{
		{
			name:     "absent defaults to authorization_code",
			declared: nil,
			wantKept: []string{"authorization_code"},
		},
		{
			name:     "empty defaults to authorization_code",
			declared: []string{},
			wantKept: []string{"authorization_code"},
		},
		{
			// The exact document from the issue: MCPJam publishes device_code
			// alongside the two grants ZeroID does offer.
			name:        "device_code is dropped, the rest kept",
			declared:    []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"},
			wantKept:    []string{"authorization_code", "refresh_token"},
			wantDropped: []string{"urn:ietf:params:oauth:grant-type:device_code"},
		},
		{
			// The security-relevant case: an M2M grant must not survive into
			// the synthesized client, because the token endpoint reads exactly
			// this list when deciding whether to honour client_credentials.
			name:        "client_credentials is dropped",
			declared:    []string{"authorization_code", "client_credentials"},
			wantKept:    []string{"authorization_code"},
			wantDropped: []string{"client_credentials"},
		},
		{
			name:        "delegation grants are dropped in both spellings",
			declared:    []string{"authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange", "urn:ietf:params:oauth:grant-type:jwt-bearer"},
			wantKept:    []string{"authorization_code"},
			wantDropped: []string{"urn:ietf:params:oauth:grant-type:token-exchange", "urn:ietf:params:oauth:grant-type:jwt-bearer"},
		},
		{
			name:        "duplicates collapse",
			declared:    []string{"authorization_code", "authorization_code", "refresh_token", "client_credentials", "client_credentials"},
			wantKept:    []string{"authorization_code", "refresh_token"},
			wantDropped: []string{"client_credentials"},
		},
		{
			// Order is preserved so the synthesized client (and therefore the
			// resolution cache) is deterministic for a given document.
			name:        "document order is preserved",
			declared:    []string{"refresh_token", "device_code", "authorization_code"},
			wantKept:    []string{"refresh_token", "authorization_code"},
			wantDropped: []string{"device_code"},
		},
		{
			name:        "everything unsupported keeps nothing",
			declared:    []string{"client_credentials", "device_code"},
			wantKept:    nil,
			wantDropped: []string{"client_credentials", "device_code"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kept, dropped := effectiveCIMDGrantTypes(tc.declared)
			if !slices.Equal(kept, tc.wantKept) {
				t.Errorf("kept = %v, want %v", kept, tc.wantKept)
			}
			if !slices.Equal(dropped, tc.wantDropped) {
				t.Errorf("dropped = %v, want %v", dropped, tc.wantDropped)
			}
		})
	}
}

// The issue's reproduction, end to end through the synthesizer.
func TestSynthesizeCIMDClient_UnsupportedGrantsAreDroppedNotRejected(t *testing.T) {
	url := "https://app.example.com/client.json"
	now := time.Now()

	client, err := synthesizeCIMDClient(url, &cimdMetadataDocument{
		ClientID:     url,
		ClientName:   "MCPJam",
		RedirectURIs: []string{"https://app.example.com/cb"},
		GrantTypes:   []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"},
	}, now)
	if err != nil {
		t.Fatalf("a document listing an unimplemented grant must still resolve: %v", err)
	}
	if !slices.Equal(client.GrantTypes, []string{"authorization_code", "refresh_token"}) {
		t.Errorf("GrantTypes = %v, want the supported intersection", client.GrantTypes)
	}
}

// The invariant the old rejection was actually protecting: a zero-registration
// client must not be able to OBTAIN an M2M or delegation grant. That is carried
// by what lands in GrantTypes, which the token endpoint gates on — not by
// refusing to parse a document that merely mentions one.
func TestSynthesizeCIMDClient_M2MGrantsNeverReachTheClient(t *testing.T) {
	url := "https://app.example.com/client.json"
	now := time.Now()

	for _, forbidden := range []string{
		"client_credentials",
		"urn:ietf:params:oauth:grant-type:token-exchange",
		"urn:ietf:params:oauth:grant-type:jwt-bearer",
		"api_key",
	} {
		t.Run(forbidden, func(t *testing.T) {
			client, err := synthesizeCIMDClient(url, &cimdMetadataDocument{
				ClientID:     url,
				ClientName:   "N",
				RedirectURIs: []string{"https://app.example.com/cb"},
				GrantTypes:   []string{"authorization_code", forbidden},
			}, now)
			if err != nil {
				t.Fatalf("document should resolve, not be rejected: %v", err)
			}
			if slices.Contains(client.GrantTypes, forbidden) {
				t.Fatalf("%q reached the synthesized client — the token endpoint reads this "+
					"list to decide whether to honour that grant", forbidden)
			}
			// Also pin the normalized spelling, since the token endpoint's
			// client_credentials gate compares against the short form.
			if slices.Contains(client.GrantTypes, string(domain.NormalizeGrantType(forbidden))) {
				t.Fatalf("normalized form of %q reached the synthesized client", forbidden)
			}
		})
	}
}

// A document whose only grants are unsupported still fails — authorization_code
// is the one flow CIMD exists for, so its absence leaves nothing to synthesize.
func TestSynthesizeCIMDClient_StillRejectsWhenNoSupportedGrantRemains(t *testing.T) {
	url := "https://app.example.com/client.json"
	now := time.Now()

	for _, declared := range [][]string{
		{"client_credentials"},
		{"refresh_token"},
		{"urn:ietf:params:oauth:grant-type:device_code"},
	} {
		_, err := synthesizeCIMDClient(url, &cimdMetadataDocument{
			ClientID:     url,
			ClientName:   "N",
			RedirectURIs: []string{"https://app.example.com/cb"},
			GrantTypes:   declared,
		}, now)
		if !errors.Is(err, ErrCIMDInvalidDocument) {
			t.Errorf("grant_types %v leaves no authorization_code; want ErrCIMDInvalidDocument, got %v", declared, err)
		}
	}
}

// RATCHET: only the interactive legs may yield a CIMD-synthesized client.
//
// zeroid#344 made a CIMD document's grant_types advisory-with-narrowing rather
// than fatal, and the safety of that rests on two things. The first is
// unconditional: effectiveCIMDGrantTypes filters by exact match, so a CIMD
// client's GrantTypes is provably a subset of cimdAllowedGrantTypes.
//
// The second is REACHABILITY, and it is contingent. Most token-endpoint dispatch
// arms do not check client.GrantTypes at all — jwt-bearer, token-exchange,
// api_key, CIBA, ID-JAG and custom grants registered via Server.RegisterGrant
// have no such gate. They are safe today only because a CIMD client cannot reach
// them: resolveClientRegistryOrCIMD is called from exactly three places, all on
// the authorization_code / refresh_token legs.
//
// A future grant that BOTH resolves through resolveClientRegistryOrCIMD AND
// derives authority from the resolved client would bypass every grant-type check
// silently. This test fails when a fourth call site appears, so that assumption
// has to be re-examined deliberately rather than eroding unnoticed.
func TestCIMDClientReachabilityIsBounded(t *testing.T) {
	// Enclosing functions permitted to resolve a client that may be CIMD.
	allowed := map[string]bool{
		// The authorize leg. Gates on client.GrantTypes via
		// checkAuthorizeClientPolicy -> oauth.go:1840.
		"ResolveAuthorizeClient": true,
		// The code->token exchange. Gates at oauth.go:2145.
		"authorizationCode": true,
		// Rotation, which re-resolves the document so a republished one acts as
		// the revocation lever. Gates the CIMD branch at oauth.go:2521.
		"refreshToken": true,
	}

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}

	funcDecl := regexp.MustCompile(`^func (?:\([^)]*\) )?(\w+)`)
	var offenders []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		body, readErr := os.ReadFile(f)
		if readErr != nil {
			t.Fatalf("read %s: %v", f, readErr)
		}
		enclosing := "<file scope>"
		for i, line := range strings.Split(string(body), "\n") {
			if m := funcDecl.FindStringSubmatch(line); m != nil {
				enclosing = m[1]
			}
			if !strings.Contains(line, "resolveClientRegistryOrCIMD(") {
				continue
			}
			if strings.Contains(line, "func (s *OAuthService) resolveClientRegistryOrCIMD") {
				continue // the definition itself
			}
			if !allowed[enclosing] {
				offenders = append(offenders, fmt.Sprintf("%s:%d in %s()", f, i+1, enclosing))
			}
		}
	}

	if len(offenders) > 0 {
		t.Errorf("resolveClientRegistryOrCIMD reached from an unexpected function:\n  %s\n\n"+
			"A CIMD client can now flow there. Most grant paths do NOT check client.GrantTypes, "+
			"so confirm the new caller either gates on it or derives no authority from the client, "+
			"then add the function to `allowed` with a note saying which.",
			strings.Join(offenders, "\n  "))
	}
}

// A CIMD document is unauthenticated, unregistered, attacker-authored input
// bounded only by defaultCIMDMaxDocumentBytes. Logging its rejected grant_types
// verbatim would let one resolution write most of a 5 KiB document into the log,
// and distinct URLs sidestep the resolution cache. Both the entry count and each
// entry's length are capped, and the cap is visible in the output rather than
// silently understating what the document declared.
func TestTruncateGrantTypesForLog(t *testing.T) {
	t.Run("short lists pass through unchanged", func(t *testing.T) {
		in := []string{"client_credentials", "device_code"}
		if got := truncateGrantTypesForLog(in); !slices.Equal(got, in) {
			t.Errorf("got %v, want %v", got, in)
		}
	})

	t.Run("an over-long entry is truncated with a marker", func(t *testing.T) {
		got := truncateGrantTypesForLog([]string{strings.Repeat("x", 500)})
		if len(got) != 1 {
			t.Fatalf("got %d entries, want 1", len(got))
		}
		if len([]rune(got[0])) > maxLoggedGrantTypeLen+1 {
			t.Errorf("entry not truncated: %d runes", len([]rune(got[0])))
		}
		if !strings.HasSuffix(got[0], "…") {
			t.Error("truncation must be visible in the output")
		}
	})

	t.Run("too many entries are capped and counted", func(t *testing.T) {
		in := make([]string, 50)
		for i := range in {
			in[i] = fmt.Sprintf("grant-%d", i)
		}
		got := truncateGrantTypesForLog(in)
		if len(got) != maxLoggedDroppedGrantTypes+1 {
			t.Fatalf("got %d entries, want %d plus the overflow marker", len(got), maxLoggedDroppedGrantTypes)
		}
		if !strings.Contains(got[len(got)-1], "42 more") {
			t.Errorf("overflow marker must say how many were elided, got %q", got[len(got)-1])
		}
	})

	t.Run("the whole line stays bounded for a maximal document", func(t *testing.T) {
		// 5 KiB of distinct 200-char grant types, the worst a document can do.
		in := make([]string, 200)
		for i := range in {
			in[i] = fmt.Sprintf("%0200d", i)
		}
		total := 0
		for _, s := range truncateGrantTypesForLog(in) {
			total += len(s)
		}
		if total > (maxLoggedDroppedGrantTypes+1)*(maxLoggedGrantTypeLen+16) {
			t.Errorf("logged payload is %d bytes — the cap is not bounding it", total)
		}
	})
}
