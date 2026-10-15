package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/highflame-ai/zeroid/internal/service"
)

// loginRedirect drives redirectToInteractiveLogin for a GET carrying query and
// returns the return_to it emitted, parsed.
func loginRedirect(t *testing.T, passthrough []string, query url.Values) url.Values {
	t.Helper()

	api := &API{
		issuer:              "https://as.example.test",
		interactiveLoginURL: func(*service.AuthorizeRequest) string { return saLoginURL },
	}
	if passthrough != nil {
		api.interactiveLoginPassthrough = func() []string { return passthrough }
	}

	get := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+query.Encode(), nil)
	rec := httptest.NewRecorder()

	if !api.redirectToInteractiveLogin(rec, get, saRequest(), registeredClient(), "test") {
		t.Fatal("expected the interactive-login redirect")
	}

	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("Location did not parse: %v", err)
	}

	rt, err := url.Parse(loc.Query().Get("return_to"))
	if err != nil {
		t.Fatalf("return_to did not parse: %v", err)
	}

	return rt.Query()
}

func TestInteractivePassthrough_AllowlistedParamPreservedVerbatim(t *testing.T) {
	const project = "proj_7f3a-9c/É x"

	rt := loginRedirect(t, []string{"project_id"}, url.Values{
		"project_id": {project},
		"utm_source": {"not-listed"},
	})

	if got := rt.Get("project_id"); got != project {
		t.Errorf("project_id = %q, want %q verbatim", got, project)
	}

	if rt.Has("utm_source") {
		t.Error("a parameter that was not allowlisted must still be dropped")
	}

	// The validated protocol parameters are untouched.
	if rt.Get("client_id") != "c" || rt.Get("state") != "sa-state" || rt.Get("redirect_uri") != saRedirectURI {
		t.Errorf("protocol parameters changed: %v", rt)
	}
}

// Without an allowlist the behaviour is exactly the old one.
func TestInteractivePassthrough_NoAllowlistDropsEverything(t *testing.T) {
	for name, list := range map[string][]string{"nil": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			rt := loginRedirect(t, list, url.Values{"project_id": {"p1"}})
			if rt.Has("project_id") {
				t.Error("project_id must not be forwarded without an allowlist")
			}
		})
	}
}

// Ambiguous or oversized values are dropped, never truncated or guessed at,
// and the redirect still happens.
func TestInteractivePassthrough_RefusedValuesDropped(t *testing.T) {
	for name, values := range map[string][]string{
		"repeated":          {"a", "b"},
		"empty":             {""},
		"too long":          {strings.Repeat("x", MaxInteractiveLoginPassthroughValueLen+1)},
		"control character": {"p1\r\nSet-Cookie: x=y"},
		"nul":               {"p1\x00"},
	} {
		t.Run(name, func(t *testing.T) {
			rt := loginRedirect(t, []string{"project_id"}, url.Values{"project_id": values})
			if rt.Has("project_id") {
				t.Errorf("project_id = %q, want it dropped", rt["project_id"])
			}
		})
	}

	rt := loginRedirect(t, []string{"project_id"}, url.Values{
		"project_id": {strings.Repeat("x", MaxInteractiveLoginPassthroughValueLen)},
	})
	if len(rt.Get("project_id")) != MaxInteractiveLoginPassthroughValueLen {
		t.Error("a value exactly at the limit must be preserved")
	}
}

// The second lock: even if a protocol name reached the allowlist, it could not
// override the validated value.
func TestInteractivePassthrough_NeverOverridesProtocolParams(t *testing.T) {
	rt := loginRedirect(t, []string{"client_id", "state", "redirect_uri"}, url.Values{
		"client_id":    {"evil"},
		"state":        {"evil"},
		"redirect_uri": {"https://evil.example/cb"},
	})

	if rt.Get("client_id") != "c" || rt.Get("state") != "sa-state" || rt.Get("redirect_uri") != saRedirectURI {
		t.Errorf("a passthrough parameter overrode a validated one: %v", rt)
	}

	if len(rt["client_id"]) != 1 || len(rt["state"]) != 1 || len(rt["redirect_uri"]) != 1 {
		t.Errorf("a passthrough parameter was appended to a validated one: %v", rt)
	}
}

func TestValidateInteractiveLoginPassthroughParams(t *testing.T) {
	got, err := ValidateInteractiveLoginPassthroughParams([]string{"project_id", "tenant.hint", "project_id", "x-y"})
	if err != nil {
		t.Fatalf("valid list refused: %v", err)
	}

	if strings.Join(got, ",") != "project_id,tenant.hint,x-y" {
		t.Errorf("got %v, want de-duplicated in order", got)
	}

	if got, err := ValidateInteractiveLoginPassthroughParams(nil); err != nil || len(got) != 0 {
		t.Errorf("empty list = %v, %v; want empty, nil", got, err)
	}

	for _, bad := range []string{
		"", "1abc", "_x", "a b", "a=b", "a&b", "a%20", "ä", strings.Repeat("a", 65),
		"client_id", "Client_ID", "REDIRECT_URI", "scope", "state", "resource", "return_to",
		"code_verifier", "client_secret", "api_key", "request_uri", "nonce", "prompt", "code",
	} {
		if _, err := ValidateInteractiveLoginPassthroughParams([]string{"project_id", bad}); err == nil {
			t.Errorf("%q accepted, want refused", bad)
		}
	}

	tooMany := make([]string, 0, MaxInteractiveLoginPassthroughParams+1)
	for i := range MaxInteractiveLoginPassthroughParams + 1 {
		tooMany = append(tooMany, "p"+strings.Repeat("a", i))
	}

	if _, err := ValidateInteractiveLoginPassthroughParams(tooMany); err == nil {
		t.Error("more than the maximum number of names accepted")
	}
}
