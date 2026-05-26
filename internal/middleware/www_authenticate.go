package middleware

import (
	"strings"
)

// WWWAuthenticate builds a Bearer WWW-Authenticate challenge value combining
// RFC 6750 §3 (Bearer error codes) with the RFC 9728 §5.1 resource_metadata
// breadcrumb.
//
// errorCode and errorDesc are RFC 6750 §3.1 error semantics. errorCode SHOULD
// be one of "invalid_request", "invalid_token", or "insufficient_scope". An
// empty errorCode emits a bare "Bearer" challenge — appropriate when no
// authentication has been attempted yet (RFC 6750 §3: "If the request lacks
// any authentication information, the resource server SHOULD NOT include an
// error code or other error information"). When errorCode is empty, errorDesc
// is dropped as well — error_description without error_code is meaningless and
// also violates the SHOULD-NOT-include-error-information guidance.
//
// resourceMetadataURL is the absolute URL of the protected resource metadata
// document (typically "{issuer}/.well-known/oauth-protected-resource"). When
// non-empty, it is appended as the RFC 9728 §5.1 `resource_metadata`
// parameter so cold-start clients can chain resource → PRM → AS metadata
// without prior knowledge. The breadcrumb is independent of error info, so
// it appears in both bare challenges (missing credentials) and decorated
// challenges (invalid credentials).
//
// All parameter values are double-quoted per RFC 7235 §2.1 quoted-string
// rules — only " and \ are escaped. We do NOT use fmt's %q verb here because
// %q applies Go-specific escaping (e.g. \uXXXX for non-ASCII, \n for
// newlines) which produces strings that are not valid HTTP quoted-string per
// RFC 7230 §3.2.6. For ASCII-only inputs the two are identical, but the
// custom quote() helper stays correct if a future caller passes a
// URL containing non-ASCII (punycode, IDN, etc.) or a description with a
// literal newline that the caller forgot to strip.
func WWWAuthenticate(errorCode, errorDesc, resourceMetadataURL string) string {
	var params []string
	if errorCode != "" {
		params = append(params, "error="+httpQuotedString(errorCode))
		if errorDesc != "" {
			params = append(params, "error_description="+httpQuotedString(errorDesc))
		}
	}
	if resourceMetadataURL != "" {
		params = append(params, "resource_metadata="+httpQuotedString(resourceMetadataURL))
	}
	if len(params) == 0 {
		return "Bearer"
	}
	return "Bearer " + strings.Join(params, ", ")
}

// httpQuotedString wraps s in double quotes and escapes only the two
// characters that RFC 7230 §3.2.6 quoted-string requires escaping (backslash
// and double-quote). All other octets — including UTF-8 — pass through
// unchanged, matching the RFC's allowed character set (obs-text covers any
// %x80-FF byte).
func httpQuotedString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}
