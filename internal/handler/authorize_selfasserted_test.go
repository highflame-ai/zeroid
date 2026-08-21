package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/oautherror"
	"github.com/highflame-ai/zeroid/internal/service"
)

// The self-asserted-client carve-out.
//
// RFC 6749 §4.1.2.1 says report most authorize failures by redirecting to the
// client's registered redirect_uri. That rule assumes "registered" means somebody
// vetted the party. CIMD removes registration by design — the redirect_uris come
// from a document the requester published, CIMD is on by default, and
// allowed_domains ships empty — so for those clients the destination is
// attacker-CHOSEN, and honouring the rule makes this endpoint an unauthenticated
// redirector (the failure being reported is "you have no credential", so no
// credential is needed to reach it) with the AS's own origin as the first hop.
//
// So: registered clients get the conformant redirect, self-asserted ones get JSON.
// These tests drive failAuthorize and redirectToInteractiveLogin directly — they
// touch no service, and the branch under test is the provenance check.

const (
	saRedirectURI = "https://app.example.test/callback"
	saLoginURL    = "https://studio.example.test/login"
)

func registeredClient() *domain.OAuthClient {
	return &domain.OAuthClient{
		ClientID:           "registered-client",
		ClientType:         "public",
		IsActive:           true,
		RedirectURIs:       []string{saRedirectURI},
		RegistrationSource: "internal",
	}
}

func cimdClient() *domain.OAuthClient {
	c := registeredClient()
	c.ClientID = "https://attacker.example/cimd.json"
	c.RegistrationSource = domain.RegistrationSourceCIMD

	return c
}

func saRequest() *service.AuthorizeRequest {
	return &service.AuthorizeRequest{
		ClientID:            "c",
		RedirectURI:         saRedirectURI,
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		State:               "sa-state",
	}
}

// TestSelfAsserted_ErrorIsNotRedirected is the carve-out: the same failure that
// redirects for a registered client must answer JSON for a self-asserted one.
func TestSelfAsserted_ErrorIsNotRedirected(t *testing.T) {
	api := &API{issuer: "https://as.example.test"}
	get := httptest.NewRequest(http.MethodGet, "/oauth2/authorize", nil)

	t.Run("registered client is redirected", func(t *testing.T) {
		rec := httptest.NewRecorder()
		api.failAuthorize(rec, get, saRequest(), registeredClient(),
			http.StatusUnauthorized, oautherror.InvalidClient, oautherror.AccessDenied, "no credential")

		if rec.Code != http.StatusFound {
			t.Fatalf("a vetted redirect_uri must still get the §4.1.2.1 redirect, got %d", rec.Code)
		}

		loc, err := url.Parse(rec.Header().Get("Location"))
		if err != nil {
			t.Fatalf("Location did not parse: %v", err)
		}

		if loc.Query().Get("error") != oautherror.AccessDenied {
			t.Errorf("error = %q, want access_denied", loc.Query().Get("error"))
		}
	})

	t.Run("self-asserted client gets JSON, no Location", func(t *testing.T) {
		rec := httptest.NewRecorder()
		api.failAuthorize(rec, get, saRequest(), cimdClient(),
			http.StatusUnauthorized, oautherror.InvalidClient, oautherror.AccessDenied, "no credential")

		if loc := rec.Header().Get("Location"); loc != "" {
			t.Fatalf("a self-asserted client must NOT be redirected — the endpoint would be an "+
				"unauthenticated redirector to %q", loc)
		}

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected the JSON refusal status, got %d", rec.Code)
		}

		var body map[string]string
		if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}

		// The JSON channel keeps its own vocabulary: invalid_client, not the
		// access_denied the redirect would have carried.
		if body["error"] != oautherror.InvalidClient {
			t.Errorf("error = %q, want invalid_client", body["error"])
		}
	})

	// Fail closed: failAuthorize's premise is that a validated redirect_uri exists,
	// and a nil client means it does not.
	t.Run("nil client gets JSON", func(t *testing.T) {
		rec := httptest.NewRecorder()
		api.failAuthorize(rec, get, saRequest(), nil,
			http.StatusUnauthorized, oautherror.InvalidClient, oautherror.AccessDenied, "no credential")

		if loc := rec.Header().Get("Location"); loc != "" {
			t.Fatalf("a nil client must not be redirected, got %q", loc)
		}
	})
}

// TestSelfAsserted_InteractiveLoginIsRefused covers the more damaging half. Sending
// a user through the deployment's real login page for a client nobody vetted means
// the victim authenticates for real and the flow resumes toward an
// attacker-published redirect_uri — an unvetted client borrowing the login
// surface's credibility.
func TestSelfAsserted_InteractiveLoginIsRefused(t *testing.T) {
	api := &API{issuer: "https://as.example.test"}
	api.SetInteractiveLoginURL(func(*service.AuthorizeRequest) string { return saLoginURL })

	get := httptest.NewRequest(http.MethodGet, "/oauth2/authorize", nil)

	t.Run("registered client is sent to login", func(t *testing.T) {
		rec := httptest.NewRecorder()

		if !api.redirectToInteractiveLogin(rec, get, saRequest(), registeredClient(), "session") {
			t.Fatal("a vetted client must still reach the login surface")
		}

		if got := rec.Header().Get("Location"); got == "" {
			t.Fatal("expected a Location to the login surface")
		}
	})

	t.Run("self-asserted client is refused", func(t *testing.T) {
		rec := httptest.NewRecorder()

		if api.redirectToInteractiveLogin(rec, get, saRequest(), cimdClient(), "session") {
			t.Fatal("a self-asserted client must NOT borrow the login surface")
		}

		if loc := rec.Header().Get("Location"); loc != "" {
			t.Fatalf("nothing should have been written, got Location %q", loc)
		}
	})
}

// TestVettedPublishers_RestoresRedirects is the other side of the carve-out, and
// the reason it is a carve-out rather than a ban.
//
// The refusal above is not about CIMD the feature — it is about a destination
// nobody vetted. cimd.allowed_domains is the deployer naming which hosts may
// publish a metadata document, which restores exactly the assumption §4.1.2.1's
// redirect rule is built on. So with an allow-list in force a CIMD client is a
// redirect destination like any other, and both refusals lift together.
//
// This test exists because the behaviour was documented in three places —
// failAuthorize's godoc, redirectToInteractiveLogin's, and docs/cimd.md — before
// it was implemented, and a promise nobody executes is the kind that rots.
func TestVettedPublishers_RestoresRedirects(t *testing.T) {
	get := httptest.NewRequest(http.MethodGet, "/oauth2/authorize", nil)

	vetted := func() *API {
		api := &API{issuer: "https://as.example.test"}
		api.SetCIMDPublishersVetted(true)
		api.SetInteractiveLoginURL(func(*service.AuthorizeRequest) string { return saLoginURL })

		return api
	}

	t.Run("error redirects to the CIMD client", func(t *testing.T) {
		rec := httptest.NewRecorder()
		vetted().failAuthorize(rec, get, saRequest(), cimdClient(),
			http.StatusUnauthorized, oautherror.InvalidClient, oautherror.AccessDenied, "no credential")

		if rec.Code != http.StatusFound {
			t.Fatalf("an allow-list vets the publisher, so §4.1.2.1 applies again; got %d", rec.Code)
		}

		loc, err := url.Parse(rec.Header().Get("Location"))
		if err != nil {
			t.Fatalf("Location did not parse: %v", err)
		}

		if got := loc.Query().Get("error"); got != oautherror.AccessDenied {
			t.Errorf("error = %q, want access_denied", got)
		}

		if got := loc.Query().Get("state"); got != "sa-state" {
			t.Errorf("state = %q, want it echoed back", got)
		}
	})

	t.Run("interactive login is reachable", func(t *testing.T) {
		rec := httptest.NewRecorder()

		if !vetted().redirectToInteractiveLogin(rec, get, saRequest(), cimdClient(), "session") {
			t.Fatal("with vetted publishers a CIMD client must reach the login surface — " +
				"this is what makes the MCP browser leg completable")
		}

		if rec.Header().Get("Location") == "" {
			t.Fatal("expected a Location to the login surface")
		}
	})

	// The gate is the allow-list, not the client: a nil client is still refused,
	// and a non-GET still gets JSON. Pinned so "vetted" never becomes a blanket
	// bypass of the other two conditions.
	t.Run("vetting does not bypass the other refusals", func(t *testing.T) {
		rec := httptest.NewRecorder()
		vetted().failAuthorize(rec, get, saRequest(), nil,
			http.StatusUnauthorized, oautherror.InvalidClient, oautherror.AccessDenied, "no credential")

		if loc := rec.Header().Get("Location"); loc != "" {
			t.Fatalf("a nil client must not be redirected, got %q", loc)
		}

		post := httptest.NewRequest(http.MethodPost, "/oauth2/authorize", nil)
		if vetted().redirectToInteractiveLogin(httptest.NewRecorder(), post, saRequest(), cimdClient(), "session") {
			t.Fatal("POST has no user agent to redirect, allow-list or not")
		}
	})
}
