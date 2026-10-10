package service

import "testing"

// TestReservedClaims_PrincipalTypeAndMissionID is the tripwire for D1 of the
// human-rooted delegation design.
//
// Each of these claims carries authority a downstream decision trusts, and each
// is set only by ZeroID's own resolution:
//
//   - mission_id groups a token into a delegation tree for audit and
//     revocation. If additional_claims could set it, a caller on the broker,
//     id_token or ID-JAG path could graft its token onto someone else's tree.
//   - principal_type says whether `sub` is a person or a workload. A forged
//     `user` would launder a workload chain into one a `required_principal_type`
//     policy accepts as human-rooted.
//   - may_act (RFC 8693 §4.4) names who may act for the subject. Only the
//     issuer may assert it.
//   - scope is the RFC 9068 string form emitted beside `scopes`, and must carry
//     the same authority.
//   - identity_id is what agent self-service acts on, and agent_id is reported
//     by introspection. ZeroID sets neither, so a caller could otherwise name
//     any agent.
func TestReservedClaims_PrincipalTypeAndMissionID(t *testing.T) {
	for _, claim := range []string{"mission_id", "principal_type", "may_act", "scope", "identity_id", "agent_id"} {
		if !reservedClaims[claim] {
			t.Errorf("%q must be in reservedClaims: additional_claims would otherwise be able to forge it", claim)
		}
	}
}
