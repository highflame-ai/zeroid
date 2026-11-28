package handler

import (
	"fmt"
	"strings"
	"testing"

	"github.com/highflame-ai/zeroid/internal/service"
)

// A refused policy delete names what still references the policy: an issuer
// row's first-contact mapping is cleared on the issuer, not on a key.
func TestPolicyInUseDetail(t *testing.T) {
	byMapping := policyInUseDetail(fmt.Errorf("%w: %w", service.ErrPolicyInUse, service.ErrPolicyInUseByFirstContact))
	if !strings.Contains(byMapping, "first-contact mapping") || !strings.Contains(byMapping, "first_contact_credential_policy_id") {
		t.Fatalf("detail = %q, want it to name the first-contact mapping", byMapping)
	}
	byKeys := policyInUseDetail(fmt.Errorf("%w: referenced by 1 service key(s)", service.ErrPolicyInUse))
	if byKeys != "credential policy is still in use by one or more service keys" {
		t.Fatalf("detail = %q, want the service-key detail unchanged", byKeys)
	}
}
