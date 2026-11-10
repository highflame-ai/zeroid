package service

import "testing"

// cimdDisplayURI guards an href and an img src on a consent screen, so its job
// is narrower than "is this a URL": only an absolute https URL may reach a
// human. draft-ietf-oauth-client-id-metadata-document §8.5 puts these fields in
// front of users precisely to help them spot phishing, which makes the field
// itself a phishing surface.
func TestCIMDDisplayURIAdmitsOnlyAbsoluteHTTPS(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{"absolute https is kept", "https://example.com/app", "https://example.com/app"},
		{"https root is kept", "https://example.com", "https://example.com"},
		{"empty stays empty", "", ""},
		{"whitespace only", "   ", ""},

		// Each of these would be script execution on the authorization
		// server's own origin if a consent screen put it in an href.
		{"javascript scheme", "javascript:alert(1)", ""},
		{"javascript with padding", "  javascript:alert(1)  ", ""},
		{"data scheme", "data:text/html;base64,PHNjcmlwdD4=", ""},
		{"vbscript scheme", "vbscript:msgbox(1)", ""},

		// http is refused too: the document itself must be https (draft §3), a
		// mixed-content logo is blocked by the browser anyway, and a
		// mixed-content client_uri downgrades the one link a suspicious user
		// might click to check who is asking.
		{"http is refused", "http://example.com/app", ""},

		{"scheme-relative has no scheme", "//example.com/app", ""},
		{"relative path", "/app", ""},
		{"no host", "https:///app", ""},
		{"not a url at all", "not a url", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := cimdDisplayURI(tc.in); got != tc.want {
				t.Errorf("cimdDisplayURI(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
