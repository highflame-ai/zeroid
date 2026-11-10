package handler

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"

	"github.com/highflame-ai/zeroid/internal/service"
)

// TestMapErr_InvalidIdentityFieldIs400 guards PATCH /agents/registry/{id}: a
// rejected public_key_pem used to fall through mapErr's substring cases into a
// logged 500. The "not found" variant pins the ordering — the sentinel must win
// over the substring fallback that would otherwise call it a 404.
func TestMapErr_InvalidIdentityFieldIs400(t *testing.T) {
	for _, err := range []error{
		fmt.Errorf("%w: invalid public_key_pem: must be a PEM-encoded P-256 (ES256) public key: curve is P-384, want P-256", service.ErrInvalidIdentityField),
		fmt.Errorf("%w: something not found in the key", service.ErrInvalidIdentityField),
	} {
		var se huma.StatusError
		if !errors.As(mapErr(err), &se) {
			t.Fatalf("mapErr(%v) is not a huma.StatusError", err)
		}
		if se.GetStatus() != http.StatusBadRequest {
			t.Errorf("mapErr(%v) = %d, want 400", err, se.GetStatus())
		}
		if se.Error() != err.Error() {
			t.Errorf("mapErr must surface the specific reason: got %q, want %q", se.Error(), err.Error())
		}
	}
}

// TestExtractOAuthError_PersonGrant pins the token endpoint's answer to a
// person-grant refusal (invalid_scope) and to a failed resolver (server_error,
// without the resolver's message).
func TestExtractOAuthError_PersonGrant(t *testing.T) {
	code, desc, status := extractOAuthError(service.ErrPersonScopeDenied)
	if code != "invalid_scope" || status != http.StatusBadRequest {
		t.Errorf("denied: got %s/%d, want invalid_scope/400", code, status)
	}
	if desc == "" {
		t.Error("denied: want a description")
	}
	code, desc, status = extractOAuthError(fmt.Errorf("%w: %w", service.ErrPersonGrantUnavailable, errors.New("db at 10.0.0.5 refused")))
	if code != "server_error" || status != http.StatusInternalServerError {
		t.Errorf("unavailable: got %s/%d, want server_error/500", code, status)
	}
	if strings.Contains(desc, "10.0.0.5") {
		t.Errorf("the resolver's error must not reach the client: %q", desc)
	}
}
