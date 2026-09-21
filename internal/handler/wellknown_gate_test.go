package handler

import (
	"context"
	"testing"
)

// TestOAuthMetadata_GateEvaluatedOncePerRequest — the servability predicate is
// deliberately dynamic (a deployer may register resolvers after NewServer), so
// reading it more than once while building a single document can emit an
// incoherent pair: client_id_metadata_document_supported advertised without the
// authorization_code grant it applies to, or the reverse.
//
// A predicate that flips on every call reproduces exactly that. This lives as a
// unit test rather than an integration test because the shared integration
// server has CIMD disabled, which makes the CIMD gate — the second of the two
// read sites — dead code there, so the same assertion passes vacuously.
func TestOAuthMetadata_GateEvaluatedOncePerRequest(t *testing.T) {
	var calls int

	api := &API{
		issuer:      "https://as.example.test",
		cimdEnabled: true,
		authorizationCodeAvailable: func() bool {
			calls++

			return calls%2 == 1 // true, false, true, ... — one flip per call
		},
	}

	for i := range 4 {
		out, err := api.oauthMetadataOp(context.Background(), nil)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}

		grants, _ := out.Body["grant_types_supported"].([]string)
		advertisesGrant := false

		for _, g := range grants {
			if g == "authorization_code" {
				advertisesGrant = true
			}
		}

		responseTypes, _ := out.Body["response_types_supported"].([]string)
		_, hasPKCE := out.Body["code_challenge_methods_supported"]
		cimd, _ := out.Body["client_id_metadata_document_supported"].(bool)

		// Whatever the predicate answered for THIS document, every gated field
		// must agree with it.
		if (len(responseTypes) > 0) != advertisesGrant {
			t.Errorf("request %d: response_types_supported=%v disagrees with grant=%v — "+
				"the gate was evaluated more than once per document",
				i, responseTypes, advertisesGrant)
		}

		if hasPKCE != advertisesGrant {
			t.Errorf("request %d: PKCE metadata present=%v disagrees with grant=%v",
				i, hasPKCE, advertisesGrant)
		}

		if cimd && !advertisesGrant {
			t.Errorf("request %d: CIMD advertised without the authorization_code "+
				"grant it applies to", i)
		}

		// The member is PRESENT exactly when it has a value, and absent
		// otherwise — RFC 8414 §2 requires it, but its "claims with zero
		// elements MUST be omitted" wins when the flow is unservable and the
		// list would be empty (zeroid#316). This assertion used to demand the
		// member unconditionally; it now pins the omission, because an empty
		// array reappearing here is precisely the regression.
		_, present := out.Body["response_types_supported"]
		if present != advertisesGrant {
			t.Errorf("request %d: response_types_supported present=%v but grant "+
				"advertised=%v — the member must appear exactly when it is non-empty",
				i, present, advertisesGrant)
		}
	}
}
