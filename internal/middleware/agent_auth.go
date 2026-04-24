package middleware

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/rs/zerolog/log"
)

// AgentClaims holds the agent identity claims extracted from a validated ES256 JWT.
// It is populated by AgentAuthMiddleware and available via GetAgentClaims.
type AgentClaims struct {
	Subject    string // WIMSE URI
	AccountID  string
	ProjectID  string
	AgentID    string
	TrustLevel string
	Scopes     []string
	JTI        string
	IdentityID string
}

type agentClaimsKey struct{}

// AgentAuthConfig configures the AgentAuthMiddleware.
type AgentAuthConfig struct {
	// PublicKey is the ECDSA P-256 public key used to verify ES256 tokens.
	PublicKey *ecdsa.PublicKey
	// Issuer is the expected iss claim value.
	Issuer string
}

// AgentAuthMiddleware validates ES256 Bearer tokens issued by ZeroID and injects agent claims into context.
// It also sets the TenantContext so downstream handlers can call GetTenant() as usual.
func AgentAuthMiddleware(cfg AgentAuthConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				writeAgentAuthError(w, http.StatusUnauthorized, "missing or invalid Authorization header")
				return
			}
			tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

			parsed, err := jwt.Parse([]byte(tokenStr),
				jwt.WithKey(jwa.ES256, cfg.PublicKey),
				jwt.WithValidate(true),
				jwt.WithIssuer(cfg.Issuer),
			)
			if err != nil {
				log.Warn().Err(err).Str("path", r.URL.Path).Msg("Agent JWT validation failed")
				writeAgentAuthError(w, http.StatusUnauthorized, "invalid or expired token")
				return
			}

			claims := extractAgentClaims(parsed)

			if claims.AccountID == "" || claims.ProjectID == "" {
				writeAgentAuthError(w, http.StatusUnauthorized, "token missing required tenant claims")
				return
			}

			ctx := r.Context()
			ctx = SetTenant(ctx, claims.AccountID, claims.ProjectID)
			ctx = context.WithValue(ctx, agentClaimsKey{}, claims)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetAgentClaims retrieves the agent identity claims from the request context.
// This is part of the public middleware API — relying services and agent-scoped
// endpoints that sit behind AgentAuthMiddleware call this to access per-request
// identity claims without re-parsing the JWT.
func GetAgentClaims(ctx context.Context) (AgentClaims, bool) {
	claims, ok := ctx.Value(agentClaimsKey{}).(AgentClaims)
	return claims, ok
}

func extractAgentClaims(token jwt.Token) AgentClaims {
	claims := AgentClaims{
		Subject: token.Subject(),
		JTI:     token.JwtID(),
	}

	if v, ok := token.Get("account_id"); ok {
		claims.AccountID, _ = v.(string)
	}
	if v, ok := token.Get("project_id"); ok {
		claims.ProjectID, _ = v.(string)
	}
	if v, ok := token.Get("agent_id"); ok {
		claims.AgentID, _ = v.(string)
	}
	if v, ok := token.Get("trust_level"); ok {
		claims.TrustLevel, _ = v.(string)
	}
	if v, ok := token.Get("identity_id"); ok {
		claims.IdentityID, _ = v.(string)
	}
	if v, ok := token.Get("scopes"); ok {
		switch s := v.(type) {
		case []string:
			claims.Scopes = s
		case []any:
			for _, item := range s {
				if str, ok := item.(string); ok {
					claims.Scopes = append(claims.Scopes, str)
				}
			}
		}
	}

	return claims
}

func writeAgentAuthError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"code":    status,
			"message": message,
		},
	})
}
