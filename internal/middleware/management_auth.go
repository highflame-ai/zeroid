package middleware

import (
	"context"
	"net/http"
	"strings"
)

type adminContextKey string

const (
	HeaderProjectID = "X-Project-ID"
	HeaderAccountID = "X-Account-ID"
	HeaderUserID    = "X-User-ID"

	callerNameKey adminContextKey = "caller_name"

	// SystemCallerPrefix is reserved for server-internal actors that need
	// to stamp audit records (e.g. the cleanup worker's expired-identity
	// sweep). Caller-supplied X-User-ID values with this prefix are
	// silently dropped so an admin can't forge attribution to a worker.
	SystemCallerPrefix = "system:"
)

// TenantContextMiddleware extracts tenant context (X-Account-ID, X-Project-ID)
// and optional caller identity (X-User-ID) from request headers into the context.
//
// This middleware performs NO authentication — the admin API is protected at the
// network layer (separate port, not exposed externally). Authentication is the
// operator's responsibility (VPN, service mesh, reverse proxy, or the optional
// AdminAuthMiddleware hook).
func TenantContextMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		accountID := r.Header.Get(HeaderAccountID)
		projectID := r.Header.Get(HeaderProjectID)

		if accountID != "" && projectID != "" {
			ctx = SetTenant(ctx, accountID, projectID)
		}

		// X-User-ID is informational and flows into audit modified_by stamps.
		// Reserved system:* prefix is silently dropped so an authenticated
		// admin caller can't impersonate the cleanup worker or any other
		// server-internal actor in the audit trail. Case-insensitive match
		// so "System:" / "SYSTEM:" can't sneak past a downstream log query
		// that filters with ILIKE 'system:%'. SetCallerName from server-
		// side code (via context, not headers) bypasses this filter.
		userID := r.Header.Get(HeaderUserID)
		if userID != "" && !strings.HasPrefix(strings.ToLower(userID), SystemCallerPrefix) {
			ctx = SetCallerName(ctx, userID)
		}

		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

// SetCallerName records who is making the admin API call (for audit trails).
func SetCallerName(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, callerNameKey, name)
}

// GetCallerName returns the caller identity from context, or empty string.
func GetCallerName(ctx context.Context) string {
	name, _ := ctx.Value(callerNameKey).(string)
	return name
}
