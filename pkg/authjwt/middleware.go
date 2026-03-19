package authjwt

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/rs/zerolog"
)

type contextKey struct{ name string }

var claimsContextKey = &contextKey{"authjwt-claims"}

// ClaimsFromContext retrieves verified claims from the request context.
// Returns nil if no claims are present (request was not authenticated).
func ClaimsFromContext(ctx context.Context) *Claims {
	v, _ := ctx.Value(claimsContextKey).(*Claims)
	return v
}

// MiddlewareConfig configures the authentication middleware.
type MiddlewareConfig struct {
	// Verifier is the token verifier (created via NewVerifier). Required.
	Verifier *Verifier

	// Logger for middleware events.
	Logger zerolog.Logger

	// AllowUnauthenticated, when true, passes requests without a Bearer token
	// through to the next handler with no claims in context. Requests with an
	// invalid Bearer token are still rejected with 401.
	// Default false — missing Bearer token returns 401.
	AllowUnauthenticated bool

	// ExemptPaths are path prefixes that bypass authentication entirely.
	// Common examples: "/health", "/ready", "/.well-known/".
	ExemptPaths []string
}

// Middleware returns an http.Handler middleware that verifies Bearer JWTs
// and injects Claims into the request context.
//
// This middleware handles external API authentication only.
// Internal service-to-service auth should be handled by a separate
// middleware layer before or after this one.
func Middleware(cfg MiddlewareConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip exempt paths.
			for _, prefix := range cfg.ExemptPaths {
				if strings.HasPrefix(r.URL.Path, prefix) {
					next.ServeHTTP(w, r)
					return
				}
			}

			// Extract Bearer token.
			tokenString := extractBearerToken(r)

			if tokenString == "" {
				if cfg.AllowUnauthenticated {
					next.ServeHTTP(w, r)
					return
				}
				http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
				return
			}

			// Verify token.
			claims, err := cfg.Verifier.Verify(r.Context(), tokenString)
			if err != nil {
				cfg.Logger.Warn().
					Err(err).
					Str("path", r.URL.Path).
					Str("method", r.Method).
					Msg("JWT verification failed")

				status := http.StatusUnauthorized
				msg := `{"error":"invalid token"}`
				switch {
				case isExpired(err):
					msg = `{"error":"token expired"}`
				case isInvalidIssuer(err):
					msg = `{"error":"invalid issuer"}`
				case isUnsupportedAlg(err):
					msg = `{"error":"unsupported signing algorithm"}`
				}
				http.Error(w, msg, status)
				return
			}

			// Inject claims into context.
			ctx := context.WithValue(r.Context(), claimsContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func isExpired(err error) bool        { return errors.Is(err, ErrExpiredToken) }
func isInvalidIssuer(err error) bool   { return errors.Is(err, ErrInvalidIssuer) }
func isUnsupportedAlg(err error) bool  { return errors.Is(err, ErrUnsupportedAlg) }
