package middleware

import (
	"context"
	"net/http"
	"strings"
)

// requestURLKey is the context key for the effective request URL.
type requestURLKey struct{}

// RequestURLMiddleware stores the effective external URL of each request
// on context.Context. Used by DPoP proof validation (RFC 9449 §4.3 htu
// claim) so the htu comparison runs against what the client actually
// hit, not against a static config value that could drift from reality
// under reverse-proxying.
//
// X-Forwarded-Proto / X-Forwarded-Host are consulted only when the
// `trustForwardedHeaders` flag is set — production deployers behind a
// trusted edge proxy (nginx, AWS ALB, GCP LB) flip it on; deployers who
// terminate TLS at the service itself leave it off so spoofed proxy
// headers can't move the goalposts.
func RequestURLMiddleware(trustForwardedHeaders bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}
			host := r.Host
			if trustForwardedHeaders {
				if v := r.Header.Get("X-Forwarded-Proto"); v != "" {
					// Some proxies send "https, http" — first value wins.
					scheme = strings.TrimSpace(strings.SplitN(v, ",", 2)[0])
				}
				if v := r.Header.Get("X-Forwarded-Host"); v != "" {
					host = strings.TrimSpace(strings.SplitN(v, ",", 2)[0])
				}
			}
			path := r.URL.Path
			full := scheme + "://" + host + path
			ctx := context.WithValue(r.Context(), requestURLKey{}, full)
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}

// EffectiveRequestURL returns the URL the client used to reach the server,
// as recorded by RequestURLMiddleware. Returns empty string if the
// middleware was not installed (caller falls back to a configured value).
func EffectiveRequestURL(ctx context.Context) string {
	v, _ := ctx.Value(requestURLKey{}).(string)
	return v
}
