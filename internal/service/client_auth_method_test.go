package service

import (
	"testing"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/oautherror"
)

// Tests for rejectUnimplementedClientAuth — the guard that stops a client
// registered for an unenforceable authentication method from being treated as a
// public client (zeroid#206 scope item 2).
//
// The property under test is narrow and worth stating precisely: it is NOT
// "private_key_jwt is unsupported". Registration accepts private_key_jwt and
// stores key material, but derives client_type from the separate `confidential`
// flag — so such a client lands as client_type=public with an empty secret hash,
// which is exactly the shape the public-client pass-through allows. Without this
// guard, choosing key-based authentication yields WEAKER authentication than
// choosing a shared secret, silently.
func TestRejectUnimplementedClientAuth(t *testing.T) {
	t.Parallel()

	allowed := []string{"", "none", "client_secret_post", "client_secret_basic", "private_key_jwt"}
	for _, method := range allowed {
		t.Run("allows "+orUnset(method), func(t *testing.T) {
			err := rejectUnimplementedClientAuth(&domain.OAuthClient{TokenEndpointAuthMethod: method})
			if err != nil {
				t.Fatalf("method %q must be allowed — this server enforces it: %v", method, err)
			}
		})
	}

	// The empty string deserves its own statement of intent: it means "unset",
	// which is what a row predating the column carries. Registration never
	// writes it, so treating it as allowed preserves legacy data rather than
	// creating a bypass — an unset method with a stored secret still goes
	// through secret verification, and without one it is a genuine public
	// client.
	t.Run("an unset method is legacy data, not a bypass", func(t *testing.T) {
		if err := rejectUnimplementedClientAuth(&domain.OAuthClient{}); err != nil {
			t.Fatalf("an unset method must keep behaving as before: %v", err)
		}
	})

	// private_key_jwt moved from `refused` to `allowed` above when
	// verifyClientAssertion landed (zeroid#206 scope item 1). The guard's job
	// never changed: refuse what this server cannot ENFORCE. The set of
	// enforceable methods grew, so the answer for this one method flipped.
	// Enforcement of private_key_jwt is covered by the client-assertion tests;
	// what matters here is only that the guard no longer blocks it.
	refused := map[string]string{
		"client_secret_jwt":           "dropped in OAuth 2.1, will not be implemented",
		"tls_client_auth":             "deferred pending an mTLS termination story",
		"self_signed_tls_client_auth": "same family as tls_client_auth",
		"totally_made_up":             "registration stores the method verbatim, so unknown values are reachable",
	}
	for method, why := range refused {
		t.Run("refuses "+method, func(t *testing.T) {
			err := rejectUnimplementedClientAuth(&domain.OAuthClient{
				// The shape registration actually produces for these: public
				// type, no secret. That is the combination that would otherwise
				// be waved through.
				ClientType:              "public",
				ClientSecret:            "",
				TokenEndpointAuthMethod: method,
			})
			oe := wantOAuthError(t, err, oautherror.InvalidClient)
			// invalid_client, not invalid_request: the client is well-formed and
			// known, it simply cannot be authenticated as registered
			// (RFC 6749 §5.2).
			if oe.HTTPStatus != 401 {
				t.Fatalf("expected 401 for %s (%s), got %d", method, why, oe.HTTPStatus)
			}
		})
	}

	t.Run("a nil client is not this guard's business", func(t *testing.T) {
		// Callers already handle "no client resolved" separately; returning an
		// auth error here would convert an unrelated state into a 401.
		if err := rejectUnimplementedClientAuth(nil); err != nil {
			t.Fatalf("nil client must pass through: %v", err)
		}
	})
}

func orUnset(s string) string {
	if s == "" {
		return "(unset)"
	}
	return s
}
