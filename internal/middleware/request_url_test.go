package middleware

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

// effectiveURL runs one request through RequestURLMiddleware and returns the
// URL it recorded — the value a DPoP proof's htu is compared against.
func effectiveURL(t *testing.T, trust ForwardedTrust, tlsConn bool, headers map[string]string) string {
	t.Helper()

	var got string
	h := RequestURLMiddleware(trust)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = EffectiveRequestURL(r.Context())
	}))

	req := httptest.NewRequest(http.MethodPost, "http://auth.example.com/oauth2/token", nil)
	req.Host = "auth.example.com"
	if tlsConn {
		req.TLS = &tls.ConnectionState{}
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	h.ServeHTTP(httptest.NewRecorder(), req)
	return got
}

var (
	none      = ForwardedTrust{}
	protoOnly = ForwardedTrust{Proto: true}
	protoHost = ForwardedTrust{Proto: true, Host: true}
)

// behindALB is what an AWS ALB delivers: plain http to the target, the real
// Host, X-Forwarded-Proto set from the client connection — and whatever
// X-Forwarded-Host the CLIENT sent, because the ALB never sets that one.
var behindALB = map[string]string{
	"X-Forwarded-Proto": "https",
	"X-Forwarded-Host":  "attacker.example",
}

func TestRequestURLMiddleware(t *testing.T) {
	cases := []struct {
		name    string
		trust   ForwardedTrust
		tls     bool
		headers map[string]string
		want    string
	}{
		// ── the bug this mode exists to fix ─────────────────────────────────
		{"none behind a TLS-terminating edge sees http — every correct proof fails",
			none, false, behindALB, "http://auth.example.com/oauth2/token"},

		// ── the safe fix behind an ALB ──────────────────────────────────────
		{"proto takes the scheme from the edge and the host from Host, ignoring a spoofed X-Forwarded-Host",
			protoOnly, false, behindALB, "https://auth.example.com/oauth2/token"},

		// ── why proto_host is wrong behind an ALB ───────────────────────────
		{"proto_host lets a client-supplied X-Forwarded-Host choose the host",
			protoHost, false, behindALB, "https://attacker.example/oauth2/token"},

		// ── TLS terminated here ─────────────────────────────────────────────
		{"none with TLS at the service is https", none, true, nil, "https://auth.example.com/oauth2/token"},
		{"none ignores forwarded headers entirely", none, true,
			map[string]string{"X-Forwarded-Proto": "http", "X-Forwarded-Host": "attacker.example"},
			"https://auth.example.com/oauth2/token"},

		// ── scheme hardening ────────────────────────────────────────────────
		{"first value of a list wins", protoOnly, false,
			map[string]string{"X-Forwarded-Proto": "https, http"}, "https://auth.example.com/oauth2/token"},
		{"scheme is case-normalised", protoOnly, false,
			map[string]string{"X-Forwarded-Proto": "HTTPS"}, "https://auth.example.com/oauth2/token"},
		{"a non-http(s) scheme is ignored, not written into the URL", protoOnly, false,
			map[string]string{"X-Forwarded-Proto": "javascript"}, "http://auth.example.com/oauth2/token"},
		{"an absent header leaves the connection scheme", protoOnly, false, nil,
			"http://auth.example.com/oauth2/token"},

		// ── host under proto_host ───────────────────────────────────────────
		{"proto_host with no X-Forwarded-Host keeps Host", protoHost, false,
			map[string]string{"X-Forwarded-Proto": "https"}, "https://auth.example.com/oauth2/token"},
		{"proto_host takes the first X-Forwarded-Host", protoHost, false,
			map[string]string{"X-Forwarded-Proto": "https", "X-Forwarded-Host": "edge.example, inner"},
			"https://edge.example/oauth2/token"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := effectiveURL(t, tc.trust, tc.tls, tc.headers); got != tc.want {
				t.Fatalf("effective URL = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestEffectiveRequestURL_EmptyWithoutMiddleware(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if got := EffectiveRequestURL(req.Context()); got != "" {
		t.Fatalf("want empty without the middleware, got %q", got)
	}
}
