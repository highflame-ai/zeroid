package service

import (
	"context"
	"testing"

	"github.com/highflame-ai/zeroid/internal/oautherror"
)

// These exercise the Token() gate and the jwt-bearer split without a DB. Every
// case here is rejected before any credential, store, or signature work, which
// is the point: a malformed or unsupported `resource` must never reach issuance
// machinery, and proving that needs no fixtures.

func TestTokenGate_ResourceOnUnsupportedGrant(t *testing.T) {
	svc := &OAuthService{}

	for _, grant := range []string{
		// A refresh continues an existing grant; re-targeting a token already
		// held is a fresh authorization decision that belongs at the original
		// grant. Permanently excluded, not pending.
		"refresh_token",
		// CIBA redeems through BackchannelService, which takes no resource —
		// binding would have to be plumbed there deliberately rather than
		// inherited.
		"urn:openid:params:grant-type:ciba",
		// Unknown / custom grants registered via RegisterGrant: fail closed.
		"no_such_grant",
	} {
		t.Run(grant, func(t *testing.T) {
			_, err := svc.Token(context.Background(), TokenRequest{
				GrantType: grant,
				Resource:  []string{"https://gw.example/mcp/github"},
			})
			wantOAuthError(t, err, oautherror.InvalidTarget)
		})
	}
}

// TestTokenGate_SupportedGrantsPassTheGate proves the enabled grants are not
// intercepted: each must fail on its OWN missing-parameter validation, not on
// the resource gate. Without this the suite would still pass if a grant were
// accidentally left out of resourceSupportedGrants.
func TestTokenGate_SupportedGrantsPassTheGate(t *testing.T) {
	svc := &OAuthService{}

	for _, grant := range []string{
		"client_credentials",
		"urn:ietf:params:oauth:grant-type:token-exchange",
		"authorization_code",
	} {
		t.Run(grant, func(t *testing.T) {
			_, err := svc.Token(context.Background(), TokenRequest{
				GrantType: grant,
				Resource:  []string{"https://gw.example/mcp/github"},
			})
			// invalid_request = reached the grant's own validation.
			wantOAuthError(t, err, oautherror.InvalidRequest)
		})
	}
}

func TestTokenGate_AudienceAndResourceRejectedBeforeAnythingElse(t *testing.T) {
	svc := &OAuthService{}

	// Both parameters AND an unsupported grant AND a malformed resource. The
	// structural conflict is reported first, so a caller that made several
	// mistakes is told about the one that makes the request incoherent.
	_, err := svc.Token(context.Background(), TokenRequest{
		GrantType: "client_credentials",
		Audience:  "codeoid",
		Resource:  []string{"not-a-uri"},
	})
	wantOAuthError(t, err, oautherror.InvalidRequest)
}

func TestTokenGate_MalformedResourceRejectedBeforeGrantDispatch(t *testing.T) {
	svc := &OAuthService{}

	// client_credentials would normally fail with invalid_request for a missing
	// account_id/project_id. Getting invalid_target instead proves validation
	// ran before dispatch.
	_, err := svc.Token(context.Background(), TokenRequest{
		GrantType: "client_credentials",
		Resource:  []string{"https://gw.example/mcp#frag"},
	})
	wantOAuthError(t, err, oautherror.InvalidTarget)
}

func TestTokenGate_NoResourceLeavesGrantsUntouched(t *testing.T) {
	svc := &OAuthService{}

	// Without `resource`, client_credentials must reach its own validation and
	// fail on the missing tenant — proving the gate is inert when the parameter
	// is absent rather than intercepting every request.
	_, err := svc.Token(context.Background(), TokenRequest{GrantType: "client_credentials"})
	wantOAuthError(t, err, oautherror.InvalidRequest)
}

func TestTokenGate_UnknownGrantStillUnsupportedGrantType(t *testing.T) {
	svc := &OAuthService{}

	// No resource: the normal unsupported_grant_type path is unchanged.
	_, err := svc.Token(context.Background(), TokenRequest{GrantType: "no_such_grant"})
	wantOAuthError(t, err, oautherror.UnsupportedGrantType)

	// With a resource: the resource gate fires first. Either error is defensible;
	// pinning it means a future reorder is a deliberate choice, not a surprise.
	_, err = svc.Token(context.Background(), TokenRequest{
		GrantType: "no_such_grant",
		Resource:  []string{"https://gw.example/mcp/github"},
	})
	wantOAuthError(t, err, oautherror.InvalidTarget)
}

// TestJWTBearer_SelfSignedRejectsResource pins the split inside the jwt-bearer
// grant: the grant type is marked as supporting `resource` for the ID-JAG
// profile, so the NHI self-signed path has to refuse it explicitly or the
// parameter would be silently dropped — the exact accepted-and-ignored outcome
// the design forbids.
func TestJWTBearer_SelfSignedRejectsResource(t *testing.T) {
	svc := &OAuthService{}

	// Not an ID-JAG (no oauth-id-jag+jwt typ header), so this takes the NHI
	// branch. The rejection lands before any algorithm or signature work.
	_, err := svc.Token(context.Background(), TokenRequest{
		GrantType: "urn:ietf:params:oauth:grant-type:jwt-bearer",
		Subject:   "not.a.real.assertion",
		Resource:  []string{"https://gw.example/mcp/github"},
	})
	oe := wantOAuthError(t, err, oautherror.InvalidTarget)
	if oe.Description == "" {
		t.Fatal("rejection should explain which path refused the parameter")
	}
}

func TestJWTBearer_SelfSignedUnaffectedWithoutResource(t *testing.T) {
	svc := &OAuthService{}

	// Same assertion, no resource: must fail on the assertion itself
	// (invalid_grant), not on the resource gate.
	_, err := svc.Token(context.Background(), TokenRequest{
		GrantType: "urn:ietf:params:oauth:grant-type:jwt-bearer",
		Subject:   "not.a.real.assertion",
	})
	wantOAuthError(t, err, oautherror.InvalidGrant)
}

func TestJWTBearer_MissingSubjectStillInvalidRequest(t *testing.T) {
	svc := &OAuthService{}

	_, err := svc.Token(context.Background(), TokenRequest{
		GrantType: "urn:ietf:params:oauth:grant-type:jwt-bearer",
	})
	wantOAuthError(t, err, oautherror.InvalidRequest)
}
