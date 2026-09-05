package zeroid

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Tests for the RFC 8707 §2 repeatable-`resource` carve-out in
// oauthFormCompatMiddleware (CAP-IDN-026).
//
// RFC 6749 §3.1 says a request parameter MUST NOT appear more than once, and
// the middleware enforces that. RFC 8707 §2 overrides it for `resource`
// specifically — "the parameter can be included multiple times to indicate
// multiple resources". Without the carve-out a conformant multi-resource
// request is rejected with `duplicate OAuth parameter: resource`, which reads
// to an interop tester as "resource unsupported".

// postForm runs a form-encoded body through the middleware and returns the
// rewritten JSON body the downstream handler would see, plus the response
// recorder (non-200 means the middleware rejected it).
func postForm(t *testing.T, body string) (map[string]any, *httptest.ResponseRecorder) {
	t.Helper()

	var seen []byte
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("reading rewritten body: %v", err)
		}
		seen = b
	})

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	oauthFormCompatMiddleware(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || len(seen) == 0 {
		return nil, rec
	}
	var out map[string]any
	if err := json.Unmarshal(seen, &out); err != nil {
		t.Fatalf("middleware emitted invalid JSON %q: %v", seen, err)
	}
	return out, rec
}

func TestFormCompat_RepeatedResourceBecomesArray(t *testing.T) {
	got, rec := postForm(t,
		"grant_type=client_credentials&resource=https%3A%2F%2Fa.example%2Fmcp&resource=https%3A%2F%2Fb.example%2Fmcp")
	if got == nil {
		t.Fatalf("middleware rejected a conformant RFC 8707 request: %d %s", rec.Code, rec.Body.String())
	}

	arr, ok := got["resource"].([]any)
	if !ok {
		t.Fatalf("resource did not become an array: %#v", got["resource"])
	}
	if len(arr) != 2 || arr[0] != "https://a.example/mcp" || arr[1] != "https://b.example/mcp" {
		t.Fatalf("values or order wrong: %#v", arr)
	}
}

func TestFormCompat_SingleResourceStaysAString(t *testing.T) {
	// One occurrence must keep the plain-string shape — this is the common case
	// and the handler's resourceParam binder accepts both.
	got, rec := postForm(t, "grant_type=client_credentials&resource=https%3A%2F%2Fa.example%2Fmcp")
	if got == nil {
		t.Fatalf("rejected: %d %s", rec.Code, rec.Body.String())
	}
	if s, ok := got["resource"].(string); !ok || s != "https://a.example/mcp" {
		t.Fatalf("single resource did not stay a string: %#v", got["resource"])
	}
}

func TestFormCompat_OtherDuplicatesStillRejected(t *testing.T) {
	// The carve-out must be surgical: RFC 6749 §3.1 still applies to every
	// other parameter. A repeated client_id is an attack shape (parameter
	// smuggling), not a spec feature.
	_, rec := postForm(t, "grant_type=client_credentials&client_id=a&client_id=b")
	if rec.Code == http.StatusOK {
		t.Fatal("duplicate client_id was accepted — the carve-out is too broad")
	}
	if !strings.Contains(rec.Body.String(), "duplicate OAuth parameter") {
		t.Fatalf("unexpected rejection reason: %s", rec.Body.String())
	}
}

func TestFormCompat_ValuelessRepeatsDropped(t *testing.T) {
	// RFC 6749 §3.2: a parameter sent without a value is treated as omitted.
	// That rule has to survive the repeat path too, or `resource=https://a&resource=`
	// would bind a token to the empty string alongside the real resource.
	got, rec := postForm(t,
		"grant_type=client_credentials&resource=https%3A%2F%2Fa.example%2Fmcp&resource=")
	if got == nil {
		t.Fatalf("rejected: %d %s", rec.Code, rec.Body.String())
	}
	arr, ok := got["resource"].([]any)
	if !ok {
		t.Fatalf("expected an array, got %#v", got["resource"])
	}
	if len(arr) != 1 || arr[0] != "https://a.example/mcp" {
		t.Fatalf("valueless occurrence was not dropped: %#v", arr)
	}
}

func TestFormCompat_AllValuelessResourceOmitted(t *testing.T) {
	// Every occurrence valueless ⇒ the parameter is absent entirely, not an
	// empty array (which the service would otherwise have to special-case).
	got, rec := postForm(t, "grant_type=client_credentials&resource=&resource=")
	if got == nil {
		t.Fatalf("rejected: %d %s", rec.Code, rec.Body.String())
	}
	if _, present := got["resource"]; present {
		t.Fatalf("expected resource to be omitted, got %#v", got["resource"])
	}
}
