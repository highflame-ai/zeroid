package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/highflame-ai/zeroid/internal/oautherror"
)

// TestFailAuthorize_CarriesIss pins RFC 9207 §2 on the error redirect at the
// unit level, with an issuer that carries a path and a redirect_uri that
// carries its own query: iss must be the issuer verbatim and the registered
// query must survive (RFC 6749 §3.1.2).
func TestFailAuthorize_CarriesIss(t *testing.T) {
	const issuer = "https://as.example.test/tenant-a"

	api := &API{issuer: issuer}
	req := saRequest()
	req.RedirectURI = "https://app.example.test/callback?keep=me"
	client := registeredClient()
	client.RedirectURIs = []string{req.RedirectURI}

	rec := httptest.NewRecorder()
	api.failAuthorize(rec, httptest.NewRequest(http.MethodGet, "/oauth2/authorize", nil), req, client,
		http.StatusBadRequest, oautherror.InvalidRequest, oautherror.InvalidRequest, "bad")

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}

	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("Location did not parse: %v", err)
	}

	q := loc.Query()
	if got := q["iss"]; len(got) != 1 || got[0] != issuer {
		t.Errorf("iss = %v, want exactly [%q]", got, issuer)
	}

	if q.Get("keep") != "me" {
		t.Errorf("registered redirect_uri query lost: %q", loc.RawQuery)
	}

	if q.Get("error") != oautherror.InvalidRequest || q.Get("state") != "sa-state" {
		t.Errorf("error/state not preserved: %q", loc.RawQuery)
	}
}

// TestOAuthMetadata_RegistrationEndpointOverride — the override replaces the
// advertised member and empty restores the default. Checked on the RFC 8414
// document and on buildASMetadata, the base the OIDC document is built from
// (serving that one needs a keyset; the integration suite fetches both).
func TestOAuthMetadata_RegistrationEndpointOverride(t *testing.T) {
	api := &API{issuer: "https://as.example.test"}

	docs := func() []map[string]any {
		as, err := api.oauthMetadataOp(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}

		return []map[string]any{as.Body, api.buildASMetadata()}
	}

	for _, d := range docs() {
		if got := d["registration_endpoint"]; got != "https://as.example.test/oauth2/register" {
			t.Errorf("default registration_endpoint = %v", got)
		}
	}

	api.SetRegistrationEndpoint("https://app.example.test/register")

	for _, d := range docs() {
		if got := d["registration_endpoint"]; got != "https://app.example.test/register" {
			t.Errorf("overridden registration_endpoint = %v", got)
		}
	}

	api.SetRegistrationEndpoint("")

	for _, d := range docs() {
		if got := d["registration_endpoint"]; got != "https://as.example.test/oauth2/register" {
			t.Errorf("cleared registration_endpoint = %v", got)
		}
	}
}

// TestOAuthMetadata_DeviceAuthorizationEndpoint — unset advertises neither the
// endpoint nor the device_code grant; set advertises both, in the RFC 8414
// document and in buildASMetadata (the OIDC document's base); clearing removes
// both again.
func TestOAuthMetadata_DeviceAuthorizationEndpoint(t *testing.T) {
	const endpoint = "https://login.example.test/oauth2/device_authorization"

	api := &API{issuer: "https://as.example.test"}

	docs := func() []map[string]any {
		as, err := api.oauthMetadataOp(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}

		return []map[string]any{as.Body, api.buildASMetadata()}
	}

	hasDeviceGrant := func(d map[string]any) bool {
		grants, _ := d["grant_types_supported"].([]string)
		for _, g := range grants {
			if g == deviceCodeGrantType {
				return true
			}
		}

		return false
	}

	assertUnset := func(when string) {
		t.Helper()

		for _, d := range docs() {
			if _, ok := d["device_authorization_endpoint"]; ok {
				t.Errorf("%s: device_authorization_endpoint must be absent", when)
			}

			if hasDeviceGrant(d) {
				t.Errorf("%s: device_code grant must not be advertised", when)
			}
		}
	}

	assertUnset("default")

	api.SetDeviceAuthorizationEndpoint(endpoint)

	for _, d := range docs() {
		if got := d["device_authorization_endpoint"]; got != endpoint {
			t.Errorf("device_authorization_endpoint = %v, want %q", got, endpoint)
		}

		if !hasDeviceGrant(d) {
			t.Errorf("grant_types_supported must list %s while the endpoint is set: %v",
				deviceCodeGrantType, d["grant_types_supported"])
		}
	}

	api.SetDeviceAuthorizationEndpoint("")
	assertUnset("cleared")
}
