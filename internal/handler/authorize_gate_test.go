package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestAuthorize_UnavailableIsRefusedAtTheEndpoint — SetAuthorizationCodeAvailable
// is documented as the way to say "this deployment does not serve the
// authorization_code flow", and docs/cimd.md points a deployer at it. It used to
// suppress only the discovery metadata, leaving /oauth2/authorize live: an
// advertisement switch wearing the name of an off switch.
//
// That gap matters most for the deployment the hatch exists for. A cookie-based
// PrincipalResolver is safe while POST is the only route (SameSite=Lax withholds
// the cookie on a cross-site POST) and becomes CSRF-reachable once a top-level
// navigation can drive the endpoint. A deployer who turns the flow off must
// actually get it turned off, on both methods.
func TestAuthorize_UnavailableIsRefusedAtTheEndpoint(t *testing.T) {
	api := &API{authorizationCodeAvailable: func() bool { return false }}

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			rec := httptest.NewRecorder()
			api.authorizeHandler(rec, httptest.NewRequest(method, "/oauth2/authorize", nil))

			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("%s /oauth2/authorize with the flow disabled = %d, want 503 — "+
					"the documented off switch left the endpoint serving", method, rec.Code)
			}

			var body map[string]string
			if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
				t.Fatalf("decode error body: %v", err)
			}

			if body["error"] == "" {
				t.Fatal("503 must carry an RFC 6749 §5.2 error body")
			}
		})
	}
}

// TestAuthorize_AvailableReachesTheHandler pins the other half: the gate must
// refuse a disabled deployment WITHOUT refusing an enabled one. A blanket 503
// would pass the test above and break every real deployment.
//
// The request carries no parameters, so an enabled deployment fails the
// required-field gate with 400 — which is proof it got past step 0, and stops
// short of principal resolution (nil on this bare API).
func TestAuthorize_AvailableReachesTheHandler(t *testing.T) {
	api := &API{authorizationCodeAvailable: func() bool { return true }}

	rec := httptest.NewRecorder()
	api.authorizeHandler(rec, httptest.NewRequest(http.MethodGet, "/oauth2/authorize", nil))

	if rec.Code == http.StatusServiceUnavailable {
		t.Fatal("an available deployment must not be refused at the gate")
	}

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected the required-field gate to answer 400, got %d", rec.Code)
	}
}

// TestAuthorize_DefaultIsUnchanged — the predicate is nil until a deployer sets
// one, and canServeAuthorizationCode treats nil as "yes". Step 0 must not turn
// an unconfigured embedder's endpoint off; that case is still owned by
// ErrNoResolversRegistered further down, which says which knob to reach for.
func TestAuthorize_DefaultIsUnchanged(t *testing.T) {
	api := &API{}

	rec := httptest.NewRecorder()
	api.authorizeHandler(rec, httptest.NewRequest(http.MethodGet, "/oauth2/authorize", nil))

	if rec.Code == http.StatusServiceUnavailable {
		t.Fatal("a nil predicate must mean available: step 0 changed the default")
	}
}
