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
// rules — only " and \ are escaped, and all CTL characters except HTAB are
// stripped (HTAB is preserved as RFC 7230 §3.2.6 obs-text permits it). We do
// NOT use fmt's %q verb here because %q applies Go-specific escaping (e.g.
// \uXXXX for non-ASCII) which produces strings that are not valid HTTP
// quoted-string per RFC 7230 §3.2.6. For ASCII-only inputs the two are
// nearly identical, but the custom helper stays correct if a future caller
// passes a URL containing non-ASCII (punycode, IDN, etc.).
//
// httpQuotedString defensively strips CTL characters (0x00-0x1F, 0x7F)
// other than HTAB before quoting. CTLs in a header value would be rejected
// by Go's net/http at write time, and CR/LF specifically would enable
// response-splitting attacks if any caller fed user-controlled input
// without sanitizing first. Callers SHOULD still pre-validate; the strip
// is defense-in-depth.
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
// and double-quote). CTL characters (0x00-0x1F and 0x7F) other than HTAB are
// stripped — they're disallowed in HTTP header field values, Go's net/http
// rejects them at write time, and CR/LF specifically would enable response-
// splitting attacks if user-controlled input ever reached this helper. All
// other octets — including UTF-8 — pass through unchanged, matching the RFC's
// allowed character set (obs-text covers any %x80-FF byte).
func httpQuotedString(s string) string {
	s = stripCTL(s)
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

// stripCTL removes CTL characters per RFC 7230 §3.2.6's exclusion: control
// characters (%x00-1F / %x7F) are forbidden in quoted-string values, except
// for HTAB (%x09) which is explicitly permitted in obs-text. The strip is
// intentionally lossy — a header value with a stray newline is broken
// whether we strip it or emit it; stripping is the safer of the two
// failure modes.
func stripCTL(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\t' || (c >= 0x20 && c != 0x7F) {
			b.WriteByte(c)
		}
	}
	return b.String()
}
