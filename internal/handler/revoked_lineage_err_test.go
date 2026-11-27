package handler

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// TestExtractOAuthError_RevokedLineage pins the token endpoint's answer when
// issuance finds, under lock, that the token it is delegating from was
// revoked after the grant checked it: invalid_grant, as the exchange's own
// check answers, not a 500.
func TestExtractOAuthError_RevokedLineage(t *testing.T) {
	err := fmt.Errorf("%w: %w", domain.ErrCredentialAlreadyRevoked, postgres.ErrRevokedLineage)
	code, desc, status := extractOAuthError(err)
	if code != "invalid_grant" || status != http.StatusBadRequest {
		t.Errorf("got %s/%d, want invalid_grant/400", code, status)
	}
	if desc != "subject_token is inactive or has been revoked" {
		t.Errorf("description %q", desc)
	}
}
