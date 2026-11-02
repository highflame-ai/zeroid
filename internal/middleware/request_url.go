package middleware

import (
	"context"
	"net/http"
	"strings"
)

// requestURLKey is the context key for the effective request URL.
type requestURLKey struct{}

// ForwardedTrust says which X-Forwarded-* headers RequestURLMiddleware may
// believe. The two are separate decisions because edge proxies do not treat
// them alike, and trusting a header the edge passes through unmodified means
// trusting the client.
type ForwardedTrust struct {
	// Proto trusts X-Forwarded-Proto for the scheme. Safe behind any edge that
	// SETS the header from the client connection — every TLS-terminating
	// proxy does, including AWS ALB.
	Proto bool

	// Host trusts X-Forwarded-Host for the authority. Safe only behind an edge
	// that sets AND OVERWRITES it. AWS ALB does not set it at all, so a
	// client-supplied value reaches the service untouched: trusting it there
	// lets the client choose the host a DPoP proof's htu is compared against,
	// and a proof signed for another server validates here.
	Host bool
}

// RequestURLMiddleware stores the effective external URL of each request on
// context.Context. Used by DPoP proof validation (RFC 9449 §4.3 htu claim) so
// the htu comparison runs against what the client actually hit, not against a
// static config value that could drift from reality under reverse-proxying.
//
// With no trust, the scheme comes from the connection (https only when TLS
// terminates here) and the host from the request's Host header. Each
// forwarded header is consulted only when its half of `trust` is set.
//
// Why the host defaults to Host rather than anything forwarded: Host is also
// client-supplied, but an edge ROUTES on it — a request whose Host names some
// other server never reaches this one. X-Forwarded-Host carries no such
// constraint; it is just a header.
func RequestURLMiddleware(trust ForwardedTrust) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}
			if trust.Proto {
				// Some proxies send "https, http" — first value wins. Only
				// http/https are honoured: anything else is not a scheme this
				// server could have been reached on, so it is ignored rather
				// than written into the URL a proof is checked against.
				if v := strings.ToLower(firstForwarded(r.Header.Get("X-Forwarded-Proto"))); v == "http" || v == "https" {
					scheme = v
				}
			}

			host := r.Host
			if trust.Host {
				if v := firstForwarded(r.Header.Get("X-Forwarded-Host")); v != "" {
					host = v
				}
			}

			full := scheme + "://" + host + r.URL.Path
			ctx := context.WithValue(r.Context(), requestURLKey{}, full)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// firstForwarded returns the first comma-separated element of a forwarded
// header, trimmed.
func firstForwarded(v string) string {
	return strings.TrimSpace(strings.SplitN(v, ",", 2)[0])
}

// EffectiveRequestURL returns the URL the client used to reach the server,
// as recorded by RequestURLMiddleware. Returns empty string if the
// middleware was not installed (caller falls back to a configured value).
func EffectiveRequestURL(ctx context.Context) string {
	v, _ := ctx.Value(requestURLKey{}).(string)
	return v
}
