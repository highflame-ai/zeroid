package handler

import (
	"errors"
	"fmt"
	"net/http"
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
