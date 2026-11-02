package zeroid

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestLogSafePath_DropsTheQueryString — the request loggers used to record
// r.RequestURI, which carries the query string.
//
// /oauth2/authorize reads its protocol parameters from the query on a GET, so a
// client author who mirrors the documented POST form into a GET puts their
// api_key in the URL. The resolver ignores it (Form is bound to the POST body),
// but a logger reading RequestURI had already written the secret to disk and
// shipped it to the deployer's log sink — twice per request, since both
// request.start and request.complete log the path.
func TestLogSafePath_DropsTheQueryString(t *testing.T) {
	const secret = "zid_sk_livesecretvalue"

	r := httptest.NewRequest("GET", "/oauth2/authorize?client_id=abc&api_key="+secret, nil)

	got := logSafePath(r)

	if strings.Contains(got, secret) {
		t.Fatalf("logged path %q carries the credential — this is what lands in the access log", got)
	}

	if strings.Contains(got, "?") {
		t.Fatalf("logged path %q still carries a query string", got)
	}

	// Still useful to an operator: the endpoint is what a log line is read for.
	if got != "/oauth2/authorize" {
		t.Fatalf("logSafePath = %q, want the bare path", got)
	}
}
