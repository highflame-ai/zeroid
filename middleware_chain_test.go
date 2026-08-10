package zeroid

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Tests for Server.Use's chaining contract (#276).
//
// Use replaced instead of appending, so a second call silently discarded the
// first — no error, no log, just a middleware that never runs. That is worse
// than it sounds because the slot is normally already occupied: AuthN registers
// a trusted-service annotator at startup, paired with SetTrustedServiceValidator,
// so a deployer adding any second concern would have dropped the annotator and
// broken external-principal exchange instead of the thing they just added.
//
// These exercise middlewareHolder directly rather than standing up a Server,
// because the composition order is the property under test and it needs no DB.

func recordingMW(log *[]string, name string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*log = append(*log, name+":in")
			next.ServeHTTP(w, r)
			*log = append(*log, name+":out")
		})
	}
}

// runChain drives one request through the holder's chain, appending to the same
// log the recording middlewares write to so the result is a single ordered trace.
func runChain(t *testing.T, h *middlewareHolder, log *[]string) []string {
	t.Helper()

	terminal := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		*log = append(*log, "handler")
	})

	var final http.Handler = terminal
	if chained := h.chain(); chained != nil {
		final = chained(terminal)
	}

	final.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	return *log
}

// TestUse_AppendsRatherThanReplacing is the regression this issue is about: both
// registrations must run. Under the old single-slot behaviour `first` never ran.
func TestUse_AppendsRatherThanReplacing(t *testing.T) {
	var log []string

	s := &Server{globalMWState: &middlewareHolder{}}
	s.Use(recordingMW(&log, "first"))
	s.Use(recordingMW(&log, "second"))

	order := runChain(t, s.globalMWState, &log)

	joined := strings.Join(order, ",")
	if !strings.Contains(joined, "first:in") {
		t.Fatalf("the first-registered middleware did not run — Use still replaces: %v", order)
	}

	if !strings.Contains(joined, "second:in") {
		t.Fatalf("the second-registered middleware did not run: %v", order)
	}
}

// TestUse_RunsInRegistrationOrder pins first-registered-outermost, matching chi
// and net/http. Order is observable to deployers — a middleware that annotates
// context must run before one that reads it — so it is contract, not detail.
func TestUse_RunsInRegistrationOrder(t *testing.T) {
	var log []string

	s := &Server{globalMWState: &middlewareHolder{}}
	s.Use(recordingMW(&log, "outer"))
	s.Use(recordingMW(&log, "inner"))

	order := runChain(t, s.globalMWState, &log)

	want := "outer:in,inner:in,handler,inner:out,outer:out"
	if got := strings.Join(order, ","); got != want {
		t.Fatalf("chain order = %q, want %q", got, want)
	}
}

// TestUse_NoMiddlewareIsPassThrough — chain() must report nil rather than an
// identity wrapper when nothing is registered, so the router closure can skip a
// pointless allocation per request.
func TestUse_NoMiddlewareIsPassThrough(t *testing.T) {
	var log []string

	s := &Server{globalMWState: &middlewareHolder{}}

	if s.globalMWState.chain() != nil {
		t.Fatal("chain() must be nil with no middleware registered")
	}

	if order := runChain(t, s.globalMWState, &log); strings.Join(order, ",") != "handler" {
		t.Fatalf("expected the bare handler, got %v", order)
	}
}

// TestUse_NilIsIgnored — a nil middleware would panic when composed. Dropping it
// is friendlier than a nil-deref at the first request, and matches
// RegisterPrincipalResolver, which also no-ops on nil.
func TestUse_NilIsIgnored(t *testing.T) {
	var log []string

	s := &Server{globalMWState: &middlewareHolder{}}
	s.Use(nil)
	s.Use(recordingMW(&log, "real"))
	s.Use(nil)

	order := runChain(t, s.globalMWState, &log)

	if got := strings.Join(order, ","); got != "real:in,handler,real:out" {
		t.Fatalf("nil middleware was not ignored: %v", order)
	}
}

// TestAdminAuth_StillReplaces — admin auth is one decision, not a stack, so it
// keeps replace semantics even though it shares middlewareHolder. Pinning it
// because the holder is now a slice and appending here would silently stack two
// auth gates.
func TestAdminAuth_StillReplaces(t *testing.T) {
	var log []string

	s := &Server{adminAuthState: &middlewareHolder{}}
	s.AdminAuth(recordingMW(&log, "old"))
	s.AdminAuth(recordingMW(&log, "new"))

	order := runChain(t, s.adminAuthState, &log)

	if got := strings.Join(order, ","); got != "new:in,handler,new:out" {
		t.Fatalf("AdminAuth must replace, not append: %v", order)
	}

	s.AdminAuth(nil)

	if s.adminAuthState.fn() != nil {
		t.Fatal("AdminAuth(nil) must clear the middleware")
	}
}
