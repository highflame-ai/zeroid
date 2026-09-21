package service

import "testing"

// TestClientIDIsReserved is a tripwire, in the same spirit as
// TestResourceIsReserved.
//
// `client_id` (RFC 9068 §2.2) is set from the OAuth client the grant actually
// authenticated or resolved, via IssueRequest.ClientID. It exists so a resource
// server can attribute a call to a client — which makes a forgeable one worse
// than no claim at all, because a consumer that trusts it has no way to tell.
//
// The ordering is what makes the reservation load-bearing rather than
// belt-and-braces: IssueCredential applies req.CustomClaims AFTER the dedicated
// `client_id` set, and ExternalPrincipalExchange merges caller-supplied
// `additional_claims` into CustomClaims subject only to this map. Drop the
// entry and an `additional_claims: {"client_id": "..."}` silently wins.
//
// For a CIMD client that is total impersonation: the metadata-document URL is
// the entire identity, since there is no registration row behind it.
func TestClientIDIsReserved(t *testing.T) {
	if !reservedClaims["client_id"] {
		t.Fatal(
			"client_id must stay in reservedClaims — CustomClaims are applied after " +
				"the dedicated set, so without it additional_claims can impersonate " +
				"any OAuth client",
		)
	}
}

// TestReservedClaimsCoversTheAttributionClaims documents, in an executable
// place, which attribution claims are reserved and which are knowingly not.
//
// `application_id` is NOT reserved. It has carried the client_id on the
// authorization_code path since long before `client_id` existed, and reserving
// it now could break a trusted-service caller that legitimately sets it. That
// is a real pre-existing gap and it is deliberately out of scope here rather
// than silently bundled in — this test exists so the omission is a recorded
// decision instead of something a future reader has to guess about.
func TestReservedClaimsCoversTheAttributionClaims(t *testing.T) {
	if !reservedClaims["client_id"] {
		t.Error("client_id must be reserved")
	}
	if reservedClaims["application_id"] {
		t.Error(
			"application_id is now reserved — that is a behaviour change this test " +
				"deliberately did not make. If it was intended, update this test and " +
				"say why in the commit; a trusted-service caller may have been setting it",
		)
	}
}
