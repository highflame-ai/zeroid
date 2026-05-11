package middleware

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/internal/jwtalg"
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

			// Reject alg=none / HS* before any further work — JWT-SVID §3.
			if err := jwtalg.Validate(tokenStr); err != nil {
				log.Warn().Err(err).Str("path", r.URL.Path).Msg("Agent JWT rejected: bad alg")
				writeAgentAuthError(w, http.StatusUnauthorized, "invalid or expired token")
				return
			}

			parsed, err := jwt.Parse([]byte(tokenStr),
				jwt.WithKey(jwa.ES256(), cfg.PublicKey),
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
	// jwx v4: Subject() / JwtID() return (value, present).
	sub, _ := token.Subject()
	jti, _ := token.JwtID()
	claims := AgentClaims{
		Subject: sub,
		JTI:     jti,
	}

	// jwx v4: jwt.Get[T](token, name) replaces token.Get(name); errors when
	// the claim is absent or wrong-typed, so a returned err is the safe miss.
	if v, err := jwt.Get[string](token, "account_id"); err == nil {
		claims.AccountID = v
	}
	if v, err := jwt.Get[string](token, "project_id"); err == nil {
		claims.ProjectID = v
	}
	if v, err := jwt.Get[string](token, "agent_id"); err == nil {
		claims.AgentID = v
	}
	if v, err := jwt.Get[string](token, "trust_level"); err == nil {
		claims.TrustLevel = v
	}
	if v, err := jwt.Get[string](token, "identity_id"); err == nil {
		claims.IdentityID = v
	}
	// scopes can be []string or []any depending on issuance shape; try both.
	if v, err := jwt.Get[[]string](token, "scopes"); err == nil {
		claims.Scopes = v
	} else if v, err := jwt.Get[[]any](token, "scopes"); err == nil {
		for _, item := range v {
			if str, ok := item.(string); ok {
				claims.Scopes = append(claims.Scopes, str)
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
