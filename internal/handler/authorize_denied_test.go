package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/oautherror"
)

// A resolver reporting ErrPrincipalAccessDenied: the resource owner was
// authenticated and declined. denyAuthorize delivers the RFC 6749 §4.1.2.1
// access_denied redirect regardless of method (the method gate lives in the
// handler's dispatch and is covered end to end by the integration suite), and
// falls back to JSON exactly where failAuthorize would.

func TestDenyAuthorize_RedirectsWithErrorStateAndIss(t *testing.T) {
	const issuer = "https://as.example.test"

	api := &API{issuer: issuer}
	rec := httptest.NewRecorder()
	api.denyAuthorize(rec, saRequest(), registeredClient())

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}

	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}

	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("Location did not parse: %v", err)
	}

	if got := loc.Scheme + "://" + loc.Host + loc.Path; got != saRedirectURI {
		t.Errorf("redirected to %q, want the validated redirect_uri %q", got, saRedirectURI)
	}

	q := loc.Query()
	if q.Get("error") != oautherror.AccessDenied {
		t.Errorf("error = %q, want access_denied", q.Get("error"))
	}

	if q.Get("error_description") != accessDeniedDescription {
		t.Errorf("error_description = %q, want the fixed text", q.Get("error_description"))
	}

	if q.Get("state") != "sa-state" {
		t.Errorf("state = %q, want it echoed", q.Get("state"))
	}

	if got := q["iss"]; len(got) != 1 || got[0] != issuer {
		t.Errorf("iss = %v, want exactly [%q]", got, issuer)
	}

	if q.Get("code") != "" {
		t.Errorf("a denial must never carry a code: %q", loc.RawQuery)
	}
}

func TestDenyAuthorize_NoStateWhenNoneSent(t *testing.T) {
	api := &API{issuer: "https://as.example.test"}
	req := saRequest()
	req.State = ""

	rec := httptest.NewRecorder()
	api.denyAuthorize(rec, req, registeredClient())

	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("Location did not parse: %v", err)
	}

	if _, present := loc.Query()["state"]; present {
		t.Errorf("state must be absent when the request carried none: %q", loc.RawQuery)
	}
}

// Where refusesRedirectTo refuses the destination, the denial is a JSON
// access_denied, never a Location.
func TestDenyAuthorize_RefusedDestinationGetsJSON(t *testing.T) {
	api := &API{issuer: "https://as.example.test"}

	// The only refused destination left after #412: no client to reason about.
	for name, client := range map[string]func() *domain.OAuthClient{
		"nil client": func() *domain.OAuthClient { return nil },
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			api.denyAuthorize(rec, saRequest(), client())

			if loc := rec.Header().Get("Location"); loc != "" {
				t.Fatalf("refused destination must not be redirected to, got %q", loc)
			}

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", rec.Code)
			}

			var body map[string]string
			if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
				t.Fatalf("decode: %v", err)
			}

			if body["error"] != oautherror.AccessDenied {
				t.Errorf("error = %q, want access_denied", body["error"])
			}
		})
	}
}

// A self-asserted client whose redirect_uri delivers locally is not refused,
// so a native/CLI client learns of the denial from its callback.
func TestDenyAuthorize_SelfAssertedLoopbackIsRedirected(t *testing.T) {
	api := &API{issuer: "https://as.example.test"}
	req := saRequest()
	req.RedirectURI = "http://127.0.0.1:9000/cb"
	client := cimdClient()
	client.RedirectURIs = []string{req.RedirectURI}

	rec := httptest.NewRecorder()
	api.denyAuthorize(rec, req, client)

	if rec.Code != http.StatusFound {
		t.Fatalf("loopback destination must be redirected to, got %d", rec.Code)
	}
}

// Extracting redirectAuthorizeError must not have changed failAuthorize's
// method policy: a POST failure stays JSON for a client that would be
// redirected on GET.
func TestFailAuthorize_POSTStillJSON(t *testing.T) {
	api := &API{issuer: "https://as.example.test"}
	rec := httptest.NewRecorder()
	api.failAuthorize(rec, httptest.NewRequest(http.MethodPost, "/oauth2/authorize", nil),
		saRequest(), registeredClient(),
		http.StatusUnauthorized, oautherror.InvalidClient, oautherror.AccessDenied, "credential rejected")

	if loc := rec.Header().Get("Location"); loc != "" {
		t.Fatalf("POST failure must stay JSON, got Location %q", loc)
	}

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// A self-asserted client's remote redirect_uri is redirected to: the publisher
// was admitted at document resolution (cimd.allowed_domains), so the denial
// travels to the client like any other §4.1.2.1 error.
func TestDenyAuthorize_SelfAssertedRemoteIsRedirected(t *testing.T) {
	api := &API{issuer: "https://as.example.test"}
	req := saRequest()
	client := cimdClient()
	client.RedirectURIs = []string{req.RedirectURI}

	rec := httptest.NewRecorder()
	api.denyAuthorize(rec, req, client)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}

	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("Location did not parse: %v", err)
	}

	if got := loc.Query().Get("error"); got != oautherror.AccessDenied {
		t.Errorf("error = %q, want access_denied", got)
	}

	if got := loc.Query().Get("iss"); got != "https://as.example.test" {
		t.Errorf("iss = %q", got)
	}
}
