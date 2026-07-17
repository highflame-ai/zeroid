package attestation

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestSSRFIsBlockedIP exercises the IP classifier directly. This is the
// load-bearing primitive: every fetch-time guard funnels through it, so a
// gap here is a gap in the whole SSRF defence.
func TestSSRFIsBlockedIP(t *testing.T) {
	cases := []struct {
		name    string
		ip      string
		blocked bool
	}{
		// Cloud metadata — the headline target.
		{"aws_gcp_imds_link_local", "169.254.169.254", true},
		{"azure_imds_ula_v6", "fd00:ec2::254", true},
		// RFC 1918 private.
		{"private_10", "10.1.2.3", true},
		{"private_172", "172.16.5.5", true},
		{"private_192", "192.168.1.1", true},
		// Loopback.
		{"loopback_v4", "127.0.0.1", true},
		{"loopback_v6", "::1", true},
		// IPv6 ULA + link-local.
		{"ula_v6", "fc00::1", true},
		{"link_local_v6", "fe80::1", true},
		// Other reserved ranges.
		{"this_network", "0.0.0.0", true},
		{"this_network_8", "0.1.2.3", true},
		{"cgn", "100.64.0.1", true},
		{"test_net_1", "192.0.2.5", true},
		{"test_net_2", "198.51.100.5", true},
		{"test_net_3", "203.0.113.5", true},
		{"benchmarking", "198.18.0.1", true},
		{"reserved_class_e", "240.0.0.1", true},
		{"multicast_v4", "224.0.0.1", true},
		{"multicast_v6", "ff02::1", true},
		// Public addresses must pass.
		{"public_v4", "8.8.8.8", false},
		{"public_v4_github", "140.82.121.4", false},
		{"public_v6", "2606:4700:4700::1111", false},
		// Just outside CGN (100.128/9 is public).
		{"public_just_outside_cgn", "100.128.0.1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("bad test IP %q", tc.ip)
			}
			if got := isBlockedIP(ip); got != tc.blocked {
				t.Errorf("isBlockedIP(%s) = %v, want %v", tc.ip, got, tc.blocked)
			}
		})
	}
}

// withStubbedResolver swaps the package-level lookupIPs for the duration of a
// test, restoring it afterwards. The stub maps every host to fixedIPs, which
// lets the fetch-level tests drive issuer/jwks_uri hosts to chosen addresses
// without real DNS.
func withStubbedResolver(t *testing.T, fixedIPs []net.IP) {
	t.Helper()
	orig := lookupIPs
	t.Cleanup(func() { lookupIPs = orig })
	lookupIPs = func(_ context.Context, _ string) ([]net.IP, error) {
		return fixedIPs, nil
	}
}

// TestSSRFDiscoveryRejectsInternalIssuer proves the issuer host is resolved
// and rejected BEFORE the discovery GET fires — the server must never be
// reachable for an issuer that resolves to an internal address.
func TestSSRFDiscoveryRejectsInternalIssuer(t *testing.T) {
	internalRanges := map[string]string{
		"metadata":    "169.254.169.254",
		"rfc1918":     "10.0.0.5",
		"loopback":    "127.0.0.1",
		"cgn":         "100.64.0.1",
		"unspecified": "0.0.0.0",
	}
	for name, ipStr := range internalRanges {
		t.Run(name, func(t *testing.T) {
			withStubbedResolver(t, []net.IP{net.ParseIP(ipStr)})

			// A transport that records whether any GET reached the network.
			var hits int32
			rt := &recordingTransport{onRoundTrip: func() { atomic.AddInt32(&hits, 1) }}
			client := &http.Client{Transport: rt, Timeout: 5 * time.Second}

			_, err := discoverJWKSURL(context.Background(), client, "https://issuer.example.com", false)
			if err == nil {
				t.Fatalf("expected rejection for internal issuer %s", ipStr)
			}
			if !errors.Is(err, ErrPrivateAttestationEndpoint) {
				t.Fatalf("expected ErrPrivateAttestationEndpoint, got %v", err)
			}
			if got := atomic.LoadInt32(&hits); got != 0 {
				t.Fatalf("discovery GET fired %d times for blocked issuer — must be 0", got)
			}
		})
	}
}

// TestSSRFJWKSRejectsInternalRedirect proves a discovery doc whose jwks_uri
// points at an internal host is rejected before the JWKS GET — the second
// fetch is independently guarded.
func TestSSRFJWKSRejectsInternalRedirect(t *testing.T) {
	withStubbedResolver(t, []net.IP{net.ParseIP("169.254.169.254")})

	var hits int32
	rt := &recordingTransport{onRoundTrip: func() { atomic.AddInt32(&hits, 1) }}
	client := &http.Client{Transport: rt, Timeout: 5 * time.Second}

	_, err := fetchJWKS(context.Background(), client, "https://metadata.internal/jwks.json", false)
	if err == nil {
		t.Fatal("expected rejection for internal jwks_uri")
	}
	if !errors.Is(err, ErrPrivateAttestationEndpoint) {
		t.Fatalf("expected ErrPrivateAttestationEndpoint, got %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("JWKS GET fired %d times for blocked jwks_uri — must be 0", got)
	}
}

// TestSSRFPublicIssuerAllowed proves the guard does NOT block a public issuer:
// the full discovery → jwks_uri resolution succeeds end to end against an
// httptest server when the resolver hands back a public IP and the same
// server answers both GETs.
func TestSSRFPublicIssuerAllowed(t *testing.T) {
	var jwksHits int32
	var issuerURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration"):
			w.Header().Set("Content-Type", "application/json")
			// Echo the issuer URL we fetched with so the RFC 8414 §3.3
			// issuer-match check passes; point jwks_uri at the same server.
			_, _ = w.Write([]byte(`{"issuer":"` + issuerURL + `","jwks_uri":"` + issuerURL + `/jwks"}`))
		case strings.HasSuffix(r.URL.Path, "/jwks"):
			atomic.AddInt32(&jwksHits, 1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	issuerURL = srv.URL

	// Resolve every host to a public IP so the guard permits the fetch, but
	// route the actual HTTP through the httptest server's real client.
	withStubbedResolver(t, []net.IP{net.ParseIP("93.184.216.34")}) // public IP

	jwksURL, err := discoverJWKSURL(context.Background(), srv.Client(), issuerURL, false)
	if err != nil {
		t.Fatalf("public issuer discovery rejected unexpectedly: %v", err)
	}
	if jwksURL == "" {
		t.Fatal("expected a jwks_uri from discovery")
	}
	if _, err := fetchJWKS(context.Background(), srv.Client(), jwksURL, false); err != nil {
		t.Fatalf("public jwks fetch rejected unexpectedly: %v", err)
	}
	if atomic.LoadInt32(&jwksHits) != 1 {
		t.Fatalf("expected exactly one JWKS GET, got %d", jwksHits)
	}
}

// TestSSRFAllowPrivateBypassesGuard proves the dev/test escape hatch: when
// allowPrivate is true, an internal host is NOT pre-checked, so loopback
// fixtures (httptest, http://localhost) keep working.
func TestSSRFAllowPrivateBypassesGuard(t *testing.T) {
	// Resolver would map to loopback, but allowPrivate=true skips resolution
	// entirely — assertURLHostAllowed must return nil without consulting it.
	called := false
	orig := lookupIPs
	t.Cleanup(func() { lookupIPs = orig })
	lookupIPs = func(_ context.Context, _ string) ([]net.IP, error) {
		called = true
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}

	if err := assertURLHostAllowed(context.Background(), "http://localhost:8080/x", true); err != nil {
		t.Fatalf("allowPrivate should bypass the guard, got %v", err)
	}
	if called {
		t.Fatal("resolver must not be consulted when allowPrivate is true")
	}
}

// TestSSRFGuardedTransportDialBlock proves the dial-time half of the defence:
// a connection to an IP-literal address in a blocked range is refused at the
// transport layer, catching DNS-rebind between the pre-flight resolve and the
// actual dial.
func TestSSRFGuardedTransportDialBlock(t *testing.T) {
	allowPrivate := false
	tr := ssrfGuardedTransport(func() bool { return allowPrivate })
	_, err := tr.DialContext(context.Background(), "tcp", "169.254.169.254:80")
	if !errors.Is(err, ErrPrivateAttestationEndpoint) {
		t.Fatalf("dial to metadata IP should be blocked, got %v", err)
	}

	// With allowPrivate flipped on, the dialer no longer blocks the IP — it
	// proceeds to a real dial (which fails to connect, not with our sentinel).
	allowPrivate = true
	_, err = tr.DialContext(context.Background(), "tcp", "127.0.0.1:0")
	if errors.Is(err, ErrPrivateAttestationEndpoint) {
		t.Fatalf("allowPrivate should not block dial with our sentinel, got %v", err)
	}
}

// recordingTransport fails every request after invoking onRoundTrip, so tests
// can assert whether the network was reached. The guard must reject before
// RoundTrip is ever called.
type recordingTransport struct {
	onRoundTrip func()
}

func (rt *recordingTransport) RoundTrip(_ *http.Request) (*http.Response, error) {
	rt.onRoundTrip()
	return nil, errors.New("recordingTransport: network must not be reached")
}

// TestNewSSRFGuardedHTTPClient covers the exported constructor reused by the
// direct-OIDC-federation external-issuer JWKS registry (issue #88): the guard
// blocks a loopback target by default and allows it only when allowPrivate is
// set. A plain-HTTP loopback server is used so the dial-time block is isolated
// from any TLS-verification failure.
func TestNewSSRFGuardedHTTPClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Default (guarded): loopback must be refused at dial time.
	guarded := NewSSRFGuardedHTTPClient(false)
	if _, err := guarded.Get(srv.URL); err == nil {
		t.Fatalf("guarded client must refuse a loopback target; got nil error")
	} else if !errors.Is(err, ErrPrivateAttestationEndpoint) {
		t.Fatalf("expected ErrPrivateAttestationEndpoint, got %v", err)
	}

	// Relaxed (allowPrivate): the same loopback target must connect.
	relaxed := NewSSRFGuardedHTTPClient(true)
	resp, err := relaxed.Get(srv.URL)
	if err != nil {
		t.Fatalf("relaxed client must allow loopback; got %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}
