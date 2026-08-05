package service

import (
	"testing"

	"github.com/highflame-ai/zeroid/domain"
)

// TestBuildIDJAGCustomClaims_StampsResourceBinding pins the claim that
// INV-IDN-006 enforcement depends on. Shield gates entirely on the presence of
// `resource`, so if this stops being stamped the invariant silently stops
// enforcing — an un-enforced security control, which fails quiet.
func TestBuildIDJAGCustomClaims_StampsResourceBinding(t *testing.T) {
	t.Parallel()

	cfg := domain.ExternalIssuerConfig{ClaimMapping: map[string]string{"user_id": "sub"}}
	resources := []string{"https://gw.example.com/mcp/github"}

	got := buildIDJAGCustomClaims(map[string]any{}, cfg, "https://corp-idp.example", resources)

	res, ok := got["resource"].([]string)
	if !ok {
		t.Fatalf("resource claim missing or not []string: %#v", got["resource"])
	}
	if len(res) != 1 || res[0] != resources[0] {
		t.Errorf("resource = %#v, want %#v", res, resources)
	}

	// The provenance marker stays — it is what distinguishes an ID-JAG mint in
	// audit, even though enforcement no longer keys on it.
	if got["token_exchange"] != "id_jag" {
		t.Errorf("token_exchange = %v, want id_jag", got["token_exchange"])
	}
}

// TestBuildIDJAGCustomClaims_PropagateClaimsCannotClobberResource is the reason
// the resource stamp is written LAST.
//
// PropagateClaims is deployer config. If a deployer lists "resource" there, the
// propagation loop copies the RAW ID-JAG value straight through — bypassing
// extractResourceClaim, which is what normalizes the RFC 8707 shapes and fails
// closed on an absent/empty binding. Ordering is the whole defense: written
// first, the loop would overwrite the validated value with an unvalidated one.
func TestBuildIDJAGCustomClaims_PropagateClaimsCannotClobberResource(t *testing.T) {
	t.Parallel()

	cfg := domain.ExternalIssuerConfig{
		ClaimMapping:    map[string]string{"user_id": "sub"},
		PropagateClaims: []string{"resource", "acr"},
	}

	// The raw assertion carries a WIDER resource set than the one the caller
	// validated and passed in. If propagation won.
	raw := map[string]any{
		"resource": []any{"https://gw.example.com/mcp/github", "https://gw.example.com/mcp/slack"},
		"acr":      "phr",
	}
	validated := []string{"https://gw.example.com/mcp/github"}

	got := buildIDJAGCustomClaims(raw, cfg, "https://corp-idp.example", validated)

	res, ok := got["resource"].([]string)
	if !ok {
		t.Fatalf("resource claim must be the validated []string, got %#v", got["resource"])
	}
	if len(res) != 1 || res[0] != validated[0] {
		t.Errorf("resource = %#v, want %#v — propagate_claims must NOT be able to "+
			"widen or replace the validated RFC 8707 binding", res, validated)
	}

	// Propagation still works for claims that are not the binding.
	if got["acr"] != "phr" {
		t.Errorf("acr = %v, want phr (unrelated propagation must be unaffected)", got["acr"])
	}
}

// TestBuildIDJAGCustomClaims_RoleAndPrivilegeScope guards the claims that were
// already there, so the extraction refactor is provably behavior-preserving.
func TestBuildIDJAGCustomClaims_RoleAndPrivilegeScope(t *testing.T) {
	t.Parallel()

	cfg := domain.ExternalIssuerConfig{
		ClaimMapping: map[string]string{
			"user_id":         "sub",
			"role":            "groups_role",
			"privilege_scope": "groups_ps",
		},
	}
	raw := map[string]any{
		"groups_role": "admin",
		"groups_ps":   []any{"tenant:read", "tenant:write"},
	}

	got := buildIDJAGCustomClaims(raw, cfg, "https://corp-idp.example", []string{"https://gw/mcp/github"})

	if got["role"] != "admin" {
		t.Errorf("role = %v, want admin", got["role"])
	}
	ps, ok := got["privilege_scope"].([]string)
	if !ok || len(ps) != 2 {
		t.Errorf("privilege_scope = %#v, want two entries", got["privilege_scope"])
	}

	// Absent mappings must not default-fill.
	bare := buildIDJAGCustomClaims(map[string]any{}, cfg, "https://corp-idp.example", []string{"x"})
	if _, present := bare["role"]; present {
		t.Error("role must be absent when the IdP did not supply it (never default-fill)")
	}
	if _, present := bare["privilege_scope"]; present {
		t.Error("privilege_scope must be absent when the IdP did not supply it")
	}
}
