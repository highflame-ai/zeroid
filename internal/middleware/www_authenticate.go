package middleware

import (
	"fmt"
	"strings"
)

// WWWAuthenticate builds a Bearer WWW-Authenticate challenge value combining
// RFC 6750 §3 (Bearer error codes) with the RFC 9728 §5.1 resource_metadata
// breadcrumb.
//
// errorCode and errorDesc are RFC 6750 §3.1 error semantics. errorCode SHOULD
// be one of "invalid_request", "invalid_token", or "insufficient_scope". An
// empty errorCode emits a bare "Bearer" challenge — appropriate when no
// authentication has been attempted yet (initial 401 to an unauthenticated
// client).
//
// resourceMetadataURL is the absolute URL of the protected resource metadata
// document (typically "{issuer}/.well-known/oauth-protected-resource"). When
// non-empty, it is appended as the RFC 9728 §5.1 `resource_metadata`
// parameter so cold-start clients can chain resource → PRM → AS metadata
// without prior knowledge.
//
// All parameter values are double-quoted per RFC 7235 §2.1 (quoted-string).
// Callers are responsible for ensuring values are well-formed; this function
// does not URL-encode or escape.
func WWWAuthenticate(errorCode, errorDesc, resourceMetadataURL string) string {
	var params []string
	if errorCode != "" {
		params = append(params, fmt.Sprintf(`error=%q`, errorCode))
	}
	if errorDesc != "" {
		params = append(params, fmt.Sprintf(`error_description=%q`, errorDesc))
	}
	if resourceMetadataURL != "" {
		params = append(params, fmt.Sprintf(`resource_metadata=%q`, resourceMetadataURL))
	}
	if len(params) == 0 {
		return "Bearer"
	}
	return "Bearer " + strings.Join(params, ", ")
}
