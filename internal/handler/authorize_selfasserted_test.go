package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/oautherror"
	"github.com/highflame-ai/zeroid/internal/service"
)

// Self-asserted clients are redirected like any other.
//
// RFC 6749 §4.1.2.1 says report most authorize failures by redirecting to the
// client's registered redirect_uri. There used to be a carve-out here: a
// self-asserted client with a remote https redirect_uri was refused unless
// cimd.allowed_domains named its publisher.
//
// That carve-out inverted the meaning of an empty allow-list. Everywhere else
// empty is the OPEN-ecosystem default — any public https host may publish, and
// an operator sets a list to CLOSE the ecosystem. Here alone, empty was the most
// restrictive setting and adding a list was what unlocked the flow. The effect
// was a deployment where a desktop client worked and a hosted one could not
// reach the consent screen at all.
//
// cimd.allowed_domains is now enforced in one place, document resolution. A
// client that reached this code has already been admitted by whatever policy the
// deployer set, so asking again here asked the same question twice and answered
// it differently.
//
// These tests drive failAuthorize and redirectToInteractiveLogin directly — they
// touch no service.

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

// TestSelfAsserted_ErrorIsRedirectedLikeAnyClient pins the rule that replaced the
// carve-out: provenance does not change the §4.1.2.1 response.
func TestSelfAsserted_ErrorIsRedirectedLikeAnyClient(t *testing.T) {
	api := &API{issuer: "https://as.example.test"}
	get := httptest.NewRequest(http.MethodGet, "/oauth2/authorize", nil)

	for name, client := range map[string]*domain.OAuthClient{
		"registered":    registeredClient(),
		"self-asserted": cimdClient(),
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			api.failAuthorize(rec, get, saRequest(), client,
				http.StatusUnauthorized, oautherror.InvalidClient, oautherror.AccessDenied, "no credential")

			if rec.Code != http.StatusFound {
				t.Fatalf("want the §4.1.2.1 redirect, got %d", rec.Code)
			}

			loc, err := url.Parse(rec.Header().Get("Location"))
			if err != nil {
				t.Fatalf("Location did not parse: %v", err)
			}

			if loc.Query().Get("error") != oautherror.AccessDenied {
				t.Errorf("error = %q, want access_denied", loc.Query().Get("error"))
			}
		})
	}
}

// TestSelfAsserted_InteractiveLoginIsOffered is the half that mattered in
// practice. Refusing the login hop meant a hosted client never reached the
// consent screen, and failed with "interactive authentication required but
// unavailable" — an error naming the login surface rather than the allow-list
// that actually refused it.
func TestSelfAsserted_InteractiveLoginIsOffered(t *testing.T) {
	api := &API{
		issuer:              "https://as.example.test",
		interactiveLoginURL: func(*service.AuthorizeRequest) string { return saLoginURL },
	}
	get := httptest.NewRequest(http.MethodGet, "/oauth2/authorize", nil)

	for name, client := range map[string]*domain.OAuthClient{
		"registered":    registeredClient(),
		"self-asserted": cimdClient(),
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			if !api.redirectToInteractiveLogin(rec, get, saRequest(), client, "test") {
				t.Fatal("the login hop must be offered regardless of provenance")
			}

			loc := rec.Header().Get("Location")
			if loc == "" || !strings.HasPrefix(loc, saLoginURL) {
				t.Fatalf("Location = %q, want the configured login URL", loc)
			}
		})
	}
}

// TestRefusesRedirectTo_NilClient keeps the one refusal that survives. Both
// callers check it themselves, but a security predicate that answers "go ahead"
// where there is no client to reason about is the wrong default to leave for a
// third caller.
func TestRefusesRedirectTo_NilClient(t *testing.T) {
	api := &API{issuer: "https://as.example.test"}

	if !api.refusesRedirectTo(nil, saRedirectURI) {
		t.Fatal("a nil client must refuse")
	}

	if api.refusesRedirectTo(cimdClient(), saRedirectURI) {
		t.Fatal("a self-asserted client with a remote https redirect must not refuse any more")
	}
}
