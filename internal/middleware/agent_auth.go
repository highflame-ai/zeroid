package middleware

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/lestrrat-go/jwx/v4/jwk"
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
	// KeySet is the server's JWKS — every public key the issuer signs with,
	// each carrying its own kid and alg.
	//
	// This must be the key SET, not a single key. Every OAuth grant path
	// asks IssueCredential for RS256 (UseRS256: true), and credential.go
	// honours that whenever RSA keys are loaded, which `make setup-keys`
	// always produces. Pinning one algorithm and one key here therefore
	// rejected every token the grants issued — see #357. Selecting by kid
	// also keeps verification correct across a key rotation, where two keys
	// of the same algorithm are live at once.
	//
	// Widening the algorithm set does NOT widen key trust: jwx resolves the
	// header's kid against this set only, so a token signed by any other key
	// is still refused. jwtalg.Validate runs first and rejects alg=none and
	// HS* before the key lookup, so the asymmetric-only guard stands.
	KeySet jwk.Set
	// Issuer is the expected iss claim value.
	Issuer string
	// ResourceMetadataURL is the absolute URL of this server's RFC 9728
	// Protected Resource Metadata document. Emitted in the WWW-Authenticate
	// header on every 401 so cold-start clients can chain resource → PRM →
	// AS metadata per RFC 9728 §5.1. Empty disables the breadcrumb (e.g.
	// for legacy deployments that haven't migrated to issuer-anchored
	// discovery).
	ResourceMetadataURL string
}

// AgentAuthMiddleware validates ES256 Bearer tokens issued by ZeroID and injects agent claims into context.
// It also sets the TenantContext so downstream handlers can call GetTenant() as usual.
func AgentAuthMiddleware(cfg AgentAuthConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				// RFC 6750 §3: "If the request lacks any authentication
				// information, the resource server SHOULD NOT include an
				// error code or other error information." Emit a bare
				// Bearer challenge — the RFC 9728 §5.1 resource_metadata
				// breadcrumb still gets attached (the SHOULD-NOT clause
				// scopes to error info, not discovery hints), so a
				// cold-start client can still find PRM.
				//
				// The JSON body still carries a human-readable message
				// (`bodyMessage`) so a developer reading the response gets
				// actionable signal — the SHOULD-NOT-include-error-info
				// guidance is about the WWW-Authenticate header, not the
				// response body which is a ZeroID-internal convention.
				writeAgentAuthError(w, "", "", "Authorization header is required", cfg.ResourceMetadataURL)
				return
			}
			// RFC 9110 §11.1: the scheme is case-insensitive. RFC 9449
			// §7.1: a DPoP-bound access token is presented under the DPoP
			// scheme, not Bearer — ZeroID issues such tokens, so refusing
			// the scheme locks out its own spec-compliant clients.
			tokenStr, scheme, ok := ExtractAuthToken(authHeader, SchemeBearer, SchemeDPoP)
			if !ok {
				// Credentials WERE sent, just not in a recognized scheme —
				// RFC 6750 §3.1 error_code applies here.
				writeAgentAuthError(w, "invalid_request", "Authorization header must use the Bearer or DPoP scheme", "Authorization header must use the Bearer or DPoP scheme", cfg.ResourceMetadataURL)
				return
			}

			// A scheme with no token after it is a malformed request, not a
			// token-validation failure — there is no token to validate. RFC
			// 6750 §3.1 invalid_request applies; short-circuiting before
			// jwtalg.Validate also avoids an unnecessary JWS parse on input
			// that can never succeed.
			if tokenStr == "" {
				writeAgentAuthError(w, "invalid_request", "Authorization header carries an empty "+scheme+" token", "Authorization header carries an empty "+scheme+" token", cfg.ResourceMetadataURL)
				return
			}

			// RFC 9449 §7.1: the DPoP scheme asserts a proof accompanies the
			// token. Refuse the request when it does not, so the scheme can
			// never be used to present a token under weaker terms than
			// Bearer. This is a syntactic check only — the proof is verified
			// against cnf.jkt further down, once the claims are parsed.
			if scheme == SchemeDPoP && r.Header.Get("DPoP") == "" {
				writeAgentAuthError(w, "invalid_request", "DPoP scheme requires a DPoP proof header", "DPoP scheme requires a DPoP proof header", cfg.ResourceMetadataURL)
				return
			}

			// Reject alg=none / HS* before any further work — JWT-SVID §3.
			if err := jwtalg.Validate(tokenStr); err != nil {
				log.Warn().Err(err).Str("path", r.URL.Path).Msg("Agent JWT rejected: bad alg")
				writeAgentAuthError(w, "invalid_token", "invalid or expired token", "invalid or expired token", cfg.ResourceMetadataURL)
				return
			}

			parsed, err := jwt.Parse([]byte(tokenStr),
				jwt.WithKeySet(cfg.KeySet),
				jwt.WithValidate(true),
				jwt.WithIssuer(cfg.Issuer),
			)
			if err != nil {
				log.Warn().Err(err).Str("path", r.URL.Path).Msg("Agent JWT validation failed")
				writeAgentAuthError(w, "invalid_token", "invalid or expired token", "invalid or expired token", cfg.ResourceMetadataURL)
				return
			}

			claims := extractAgentClaims(parsed)

			if claims.AccountID == "" || claims.ProjectID == "" {
				writeAgentAuthError(w, "invalid_token", "token missing required tenant claims", "token missing required tenant claims", cfg.ResourceMetadataURL)
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

// writeAgentAuthError emits a 401 response with an RFC 6750 §3 challenge in
// the WWW-Authenticate header.
//
//   - errorCode      — RFC 6750 §3.1 value ("invalid_request", "invalid_token",
//     "insufficient_scope"). Empty when the request lacks any auth info, per
//     RFC 6750 §3 SHOULD-NOT-emit-error-info.
//   - headerMessage  — error_description value in the header. Same RFC 6750 §3
//     constraint as errorCode: empty when the request lacked auth info.
//   - bodyMessage    — human-readable message for the JSON response body.
//     This is ZeroID's internal convention, NOT subject to the RFC 6750 §3
//     SHOULD-NOT clause (which scopes to the header). Always populate this so
//     a developer reading the response gets actionable signal even when the
//     header is intentionally bare.
//
// When resourceMetadataURL is non-empty, RFC 9728 §5.1's resource_metadata
// parameter is appended so cold-start clients can discover the PRM document.
func writeAgentAuthError(w http.ResponseWriter, errorCode, headerMessage, bodyMessage, resourceMetadataURL string) {
	w.Header().Set("WWW-Authenticate", WWWAuthenticate(errorCode, headerMessage, resourceMetadataURL))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"code":    http.StatusUnauthorized,
			"message": bodyMessage,
		},
	})
}
