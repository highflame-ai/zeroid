package middleware

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"slices"
	"strings"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/jwtalg"
)

// BootstrapClaims holds the developer identity claims extracted from a
// validated zeroid:bootstrap-scoped token. It is populated by
// BootstrapAuthMiddleware and available via GetBootstrapClaims.
type BootstrapClaims struct {
	// UserID is the developer the bootstrap token was issued to (the token's
	// sub claim) — becomes OwnerUserID on every code agent it registers.
	UserID    string
	AccountID string
	ProjectID string
	JTI       string
	Scopes    []string
}

type bootstrapClaimsKey struct{}

// BootstrapAuthConfig configures the BootstrapAuthMiddleware.
type BootstrapAuthConfig struct {
	// ECPublicKey is the ECDSA P-256 public key used to verify ES256 tokens
	// (e.g. a client_credentials-minted bootstrap token).
	ECPublicKey *ecdsa.PublicKey
	// RSAPublicKey optionally verifies RS256 tokens — the developer bootstrap
	// token from the PKCE authorization_code flow is RS256. Nil disables the
	// RS256 fallback (deployments without RSA keys).
	RSAPublicKey *rsa.PublicKey
	// Issuer is the expected iss claim value.
	Issuer string
	// ResourceMetadataURL is the absolute URL of this server's RFC 9728
	// Protected Resource Metadata document, emitted in WWW-Authenticate
	// challenges (RFC 9728 §5.1). Empty disables the breadcrumb.
	ResourceMetadataURL string
}

// BootstrapAuthMiddleware validates a ZeroID-issued Bearer token carrying the
// zeroid:bootstrap scope and injects BootstrapClaims into the request context.
// Modeled on AgentAuthMiddleware, with two deltas:
//
//   - It accepts both ES256 and RS256 signatures — the developer bootstrap
//     token from the PKCE flow is RS256 (authorization_code sets UseRS256),
//     while a client_credentials bootstrap token is ES256.
//   - It REQUIRES the single-purpose zeroid:bootstrap scope; a valid ZeroID
//     token without it is rejected with 403 insufficient_scope (RFC 6750 §3.1)
//     so ordinary access tokens can never register code agents.
//
// It also sets the TenantContext so downstream handlers can call GetTenant().
func BootstrapAuthMiddleware(cfg BootstrapAuthConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				// RFC 6750 §3: no auth info → bare Bearer challenge (no error
				// code in the header); the JSON body still carries a human-
				// readable message. Same convention as AgentAuthMiddleware.
				writeBootstrapAuthError(w, http.StatusUnauthorized, "", "", "Authorization header is required", cfg.ResourceMetadataURL)
				return
			}
			if !strings.HasPrefix(authHeader, "Bearer ") {
				writeBootstrapAuthError(w, http.StatusUnauthorized, "invalid_request", "Authorization header must use the Bearer scheme", "Authorization header must use the Bearer scheme", cfg.ResourceMetadataURL)
				return
			}
			tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
			if tokenStr == "" {
				writeBootstrapAuthError(w, http.StatusUnauthorized, "invalid_request", "Authorization header carries an empty Bearer token", "Authorization header carries an empty Bearer token", cfg.ResourceMetadataURL)
				return
			}

			// Reject alg=none / HS* before any signature work — JWT-SVID §3.
			if err := jwtalg.Validate(tokenStr); err != nil {
				log.Warn().Err(err).Str("path", r.URL.Path).Msg("Bootstrap JWT rejected: bad alg")
				writeBootstrapAuthError(w, http.StatusUnauthorized, "invalid_token", "invalid or expired token", "invalid or expired token", cfg.ResourceMetadataURL)
				return
			}

			// Try ES256 first (the NHI default), then RS256 when RSA keys are
			// configured — the PKCE developer bootstrap token is RS256.
			parsed, err := jwt.Parse([]byte(tokenStr),
				jwt.WithKey(jwa.ES256(), cfg.ECPublicKey),
				jwt.WithValidate(true),
				jwt.WithIssuer(cfg.Issuer),
			)
			if err != nil && cfg.RSAPublicKey != nil {
				parsed, err = jwt.Parse([]byte(tokenStr),
					jwt.WithKey(jwa.RS256(), cfg.RSAPublicKey),
					jwt.WithValidate(true),
					jwt.WithIssuer(cfg.Issuer),
				)
			}
			if err != nil {
				log.Warn().Err(err).Str("path", r.URL.Path).Msg("Bootstrap JWT validation failed")
				writeBootstrapAuthError(w, http.StatusUnauthorized, "invalid_token", "invalid or expired token", "invalid or expired token", cfg.ResourceMetadataURL)
				return
			}

			claims := extractBootstrapClaims(parsed)

			if claims.UserID == "" {
				writeBootstrapAuthError(w, http.StatusUnauthorized, "invalid_token", "token missing required sub claim", "token missing required sub claim", cfg.ResourceMetadataURL)
				return
			}
			if claims.AccountID == "" || claims.ProjectID == "" {
				writeBootstrapAuthError(w, http.StatusUnauthorized, "invalid_token", "token missing required tenant claims", "token missing required tenant claims", cfg.ResourceMetadataURL)
				return
			}

			// The single-purpose scope gate: a valid ZeroID token that was not
			// minted for bootstrap must not register code agents. RFC 6750
			// §3.1: insufficient_scope → 403.
			if !slices.Contains(claims.Scopes, domain.ScopeZeroIDBootstrap) {
				writeBootstrapAuthError(w, http.StatusForbidden, "insufficient_scope",
					"token lacks the required "+domain.ScopeZeroIDBootstrap+" scope",
					"token lacks the required "+domain.ScopeZeroIDBootstrap+" scope",
					cfg.ResourceMetadataURL)
				return
			}

			ctx := r.Context()
			ctx = SetTenant(ctx, claims.AccountID, claims.ProjectID)
			ctx = context.WithValue(ctx, bootstrapClaimsKey{}, claims)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetBootstrapClaims retrieves the bootstrap claims from the request context.
// Handlers behind BootstrapAuthMiddleware call this to read the developer's
// identity + tenant without re-parsing the JWT.
func GetBootstrapClaims(ctx context.Context) (BootstrapClaims, bool) {
	claims, ok := ctx.Value(bootstrapClaimsKey{}).(BootstrapClaims)
	return claims, ok
}

func extractBootstrapClaims(token jwt.Token) BootstrapClaims {
	sub, _ := token.Subject()
	jti, _ := token.JwtID()
	claims := BootstrapClaims{
		UserID: sub,
		JTI:    jti,
	}

	if v, err := jwt.Get[string](token, "account_id"); err == nil {
		claims.AccountID = v
	}
	if v, err := jwt.Get[string](token, "project_id"); err == nil {
		claims.ProjectID = v
	}
	// ZeroID-issued tokens carry granted scopes in the "scopes" claim; the
	// "scp" spelling is accepted as well for interop with auth-code shaped
	// tokens. Each can decode as []string or []any depending on the JSON
	// round-trip — same fallback dance as AgentAuthMiddleware / authcode.go.
	for _, name := range []string{"scopes", "scp"} {
		if v, err := jwt.Get[[]string](token, name); err == nil {
			claims.Scopes = append(claims.Scopes, v...)
		} else if v, err := jwt.Get[[]any](token, name); err == nil {
			for _, item := range v {
				if str, ok := item.(string); ok {
					claims.Scopes = append(claims.Scopes, str)
				}
			}
		}
	}

	return claims
}

// writeBootstrapAuthError emits an RFC 6750 §3 challenge. Unlike
// writeAgentAuthError it takes the status explicitly because the scope gate
// responds 403 insufficient_scope (RFC 6750 §3.1) while credential failures
// respond 401. Same header/body conventions as writeAgentAuthError: the
// WWW-Authenticate header carries the RFC 6750 error info (empty when the
// request had no auth info at all), the JSON body always carries a
// human-readable message.
func writeBootstrapAuthError(w http.ResponseWriter, status int, errorCode, headerMessage, bodyMessage, resourceMetadataURL string) {
	w.Header().Set("WWW-Authenticate", WWWAuthenticate(errorCode, headerMessage, resourceMetadataURL))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"code":    status,
			"message": bodyMessage,
		},
	})
}
