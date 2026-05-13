package service

import (
	"errors"
	"net"
	"testing"
)

// TestIsBlockedIP exercises the SSRF-guard predicate against every category
// of address it must reject + a handful of public IPs that must pass through.
// GHSA-599q-j34m-33vc — closes the gap where CIBA outbound HTTPS could be
// pointed at internal or cloud-metadata IPs.
func TestIsBlockedIP(t *testing.T) {
	cases := []struct {
		name    string
		ip      string
		blocked bool
		why     string
	}{
		// Public IPv4 — must pass through
		{"public IPv4 — Google DNS", "8.8.8.8", false, ""},
		{"public IPv4 — Cloudflare DNS", "1.1.1.1", false, ""},
		{"public IPv6", "2606:4700::1", false, ""},

		// RFC 1918 private — IsPrivate
		{"RFC 1918 — 10/8", "10.0.0.5", true, "private"},
		{"RFC 1918 — 172.16/12 low", "172.16.0.1", true, "private"},
		{"RFC 1918 — 172.16/12 high", "172.31.255.254", true, "private"},
		{"RFC 1918 — 192.168/16", "192.168.1.1", true, "private"},
		{"non-private inside 172", "172.32.0.1", false, "172.32+ is public"},

		// RFC 4193 IPv6 ULA — IsPrivate
		{"RFC 4193 ULA", "fc00::1", true, "IPv6 ULA"},
		{"Azure IMDS IPv6", "fd00:ec2::254", true, "Azure IMDS is in fc00::/7"},

		// Loopback
		{"loopback IPv4", "127.0.0.1", true, "loopback"},
		{"loopback IPv4 — non-standard", "127.255.255.254", true, "loopback /8"},
		{"loopback IPv6", "::1", true, "IPv6 loopback"},

		// Link-local (includes cloud metadata IPs)
		{"AWS/GCP IMDS", "169.254.169.254", true, "link-local"},
		{"link-local IPv4 — generic", "169.254.0.1", true, "link-local"},
		{"link-local IPv6", "fe80::1", true, "IPv6 link-local"},

		// Multicast
		{"multicast IPv4", "224.0.0.1", true, "multicast"},
		{"multicast IPv6", "ff02::1", true, "IPv6 multicast"},

		// Unspecified
		{"unspecified IPv4", "0.0.0.0", true, "unspecified"},
		{"unspecified IPv6", "::", true, "unspecified"},

		// CGN (RFC 6598) — not exposed by stdlib helpers; manual check
		{"CGN — 100.64/10 low", "100.64.0.1", true, "carrier-grade NAT"},
		{"CGN — 100.64/10 high", "100.127.255.254", true, "carrier-grade NAT"},
		{"just outside CGN", "100.128.0.1", false, "100.128+ is public"},
		{"just before CGN", "100.63.255.254", false, "100.0-63 is public"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("ParseIP(%q) returned nil", tc.ip)
			}
			got := isBlockedIP(ip)
			if got != tc.blocked {
				t.Fatalf("isBlockedIP(%q) = %v; want %v (%s)", tc.ip, got, tc.blocked, tc.why)
			}
		})
	}
}

// TestValidateNotificationEndpoint_HTTPS confirms the pre-existing HTTPS-only
// check still rejects http:// even with allowPrivate=true. Belt-and-suspenders
// against a future change accidentally weakening one check while strengthening
// the other.
func TestValidateNotificationEndpoint_HTTPS(t *testing.T) {
	for _, allowPrivate := range []bool{false, true} {
		t.Run("allowPrivate="+boolStr(allowPrivate), func(t *testing.T) {
			err := validateNotificationEndpoint("http://example.com/cb", allowPrivate)
			if err == nil {
				t.Fatal("expected http:// to be rejected; got nil")
			}
		})
	}
}

// TestValidateNotificationEndpoint_PrivateIP confirms the SSRF guard fires
// on IP-as-host registrations (no DNS involved) for every category.
// Stubs lookupIPs so the test is hermetic (no real DNS).
func TestValidateNotificationEndpoint_PrivateIP(t *testing.T) {
	cases := []struct {
		name string
		url  string
	}{
		{"loopback", "https://127.0.0.1/cb"},
		{"localhost (resolves to loopback)", "https://localhost/cb"},
		{"AWS IMDS", "https://169.254.169.254/latest/meta-data/"},
		{"RFC 1918", "https://10.0.0.5/internal"},
		{"CGN", "https://100.64.0.1/cb"},
	}

	// Stub the resolver: for IP literals, return them directly. For
	// "localhost", return 127.0.0.1.
	prev := lookupIPs
	defer func() { lookupIPs = prev }()
	lookupIPs = func(host string) ([]net.IP, error) {
		if host == "localhost" {
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		}
		if ip := net.ParseIP(host); ip != nil {
			return []net.IP{ip}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: host}
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateNotificationEndpoint(tc.url, false)
			if err == nil {
				t.Fatalf("expected SSRF rejection for %q; got nil", tc.url)
			}
			if !errors.Is(err, ErrPrivateNotificationEndpoint) {
				t.Fatalf("expected ErrPrivateNotificationEndpoint sentinel; got %v", err)
			}
		})
	}
}

// TestValidateNotificationEndpoint_DNSRebinding confirms that ANY resolved IP
// in the blocked set rejects the registration, even when other resolved IPs
// are public. A malicious DNS server can rotate A records between the
// validation lookup and the eventual request — the guard must reject any
// hostname that resolves to a private IP in any of its A records.
func TestValidateNotificationEndpoint_DNSRebinding(t *testing.T) {
	prev := lookupIPs
	defer func() { lookupIPs = prev }()
	lookupIPs = func(host string) ([]net.IP, error) {
		// Simulate a DNS-rebinding attack: hostname resolves to one public
		// IP and one private IP. The guard must reject on the basis of the
		// private one.
		return []net.IP{
			net.ParseIP("8.8.8.8"),
			net.ParseIP("10.0.0.5"),
		}, nil
	}
	err := validateNotificationEndpoint("https://rebound.example.com/cb", false)
	if err == nil {
		t.Fatal("expected DNS-rebinding split-IP host to be rejected; got nil")
	}
	if !errors.Is(err, ErrPrivateNotificationEndpoint) {
		t.Fatalf("expected ErrPrivateNotificationEndpoint sentinel; got %v", err)
	}
}

// TestValidateNotificationEndpoint_AllowPrivate confirms the opt-out flag
// works in test/dev environments. With allowPrivate=true the loopback
// registration must succeed despite resolving to 127.0.0.1.
func TestValidateNotificationEndpoint_AllowPrivate(t *testing.T) {
	prev := lookupIPs
	defer func() { lookupIPs = prev }()
	lookupIPs = func(host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}
	if err := validateNotificationEndpoint("https://localhost:9000/cb", true); err != nil {
		t.Fatalf("expected allowPrivate=true to permit loopback; got %v", err)
	}
}

// TestValidateNotificationEndpoint_PublicHostPasses confirms a normal
// resolved-to-public-IP hostname registers cleanly with the guard enabled.
func TestValidateNotificationEndpoint_PublicHostPasses(t *testing.T) {
	prev := lookupIPs
	defer func() { lookupIPs = prev }()
	lookupIPs = func(host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("203.0.113.10")}, nil // RFC 5737 docs IP
	}
	if err := validateNotificationEndpoint("https://callback.example.com/cb", false); err != nil {
		t.Fatalf("expected public-IP registration to pass; got %v", err)
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
