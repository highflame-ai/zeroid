package service

import "testing"

// TestApprovalAndProvenanceClaimsAreReserved is a tripwire, in the same
// spirit as TestResourceIsReserved.
//
// Shield trusts these claims for authorization: `authorization_details` (and
// the `approval_id` inside each entry) decide whether a step-up approval
// covers a call, and `origin` / `agent_idp_iss` / `agent_idp_parent` reach
// Cedar as context.principal / context.actor. Both additional_claims paths
// (ExternalPrincipalExchange and the external id_token exchange) merge caller
// input subject only to reservedClaims, so dropping any of these entries lets
// a caller forge an approval or claim to be a native agent.
func TestApprovalAndProvenanceClaimsAreReserved(t *testing.T) {
	for _, claim := range []string{
		"authorization_details", "approval_id",
		"origin", "agent_idp_iss", "agent_idp_parent",
	} {
		if !reservedClaims[claim] {
			t.Errorf("claim %q MUST be reserved — Shield trusts it for authorization", claim)
		}
	}
}
