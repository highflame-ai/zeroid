package service

import (
	"context"

	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
)

// RevocationRequest is an RFC 7009 §2.1 revocation request as received at
// /oauth2/token/revoke: the token to revoke, the optional token_type_hint, and
// whatever client authentication the caller presented (all of it optional).
type RevocationRequest struct {
	Token               string
	TokenTypeHint       string
	ClientID            string
	ClientSecret        string
	ClientAssertion     string
	ClientAssertionType string
}

// revocationFailedDescription is the error_description of the 500 answered
// when a revocation fails server-side. The cause stays in the server log.
const revocationFailedDescription = "the token could not be revoked; retry the request"

// RevokeForClient authorizes and performs an RFC 7009 revocation of an access
// token or a refresh token (see RevokeToken for both).
//
// It returns an error in two cases only, and the handler maps each through
// extractOAuthError:
//
//   - the presented client authentication is refused: invalid_client / 401
//     (or invalid_request / 400 for a malformed one);
//   - the server failed to look up or revoke the token: server_error / 500.
//     Answering 200 would tell the client its token is dead when it may not be
//     (RFC 7009 §2.1: the client must not use the token after a 200).
//
// On every other outcome — token unknown, already revoked, malformed, or not
// issued to the presenting client — it returns nil and the endpoint answers
// 200, per RFC 7009 §2.2, alike for all of them.
//
// Two authorization paths, and the split is the point:
//
//   - A public CIMD client identifying itself by client_id alone (RFC 7009
//     §2.1 lets a public client do exactly that). It has no registry row, so
//     VerifyPresentedClientAuth — which is shared with introspection and stays
//     registry-only there — refuses it. Here it is accepted, but the
//     revocation is then CONSTRAINED to tokens issued to that same client_id,
//     for both token types: an access token only if its verified `client_id`
//     claim names the client, a refresh token only if its row was issued to
//     the client (and then with its whole family and the access tokens issued
//     from it, as for any client). That constraint is what makes accepting a
//     self-published identity safe on this endpoint: anyone can name a CIMD
//     URL, so naming one may only ever reach tokens that URL's client already
//     holds. Introspection has no equivalent constraint to apply — it answers
//     a question about the token rather than acting on the caller's own
//     grant — which is why it keeps refusing unauthenticated CIMD client_ids.
//
//   - Everything else: VerifyPresentedClientAuth, then RevokeToken with the
//     client the request identified. Refresh tokens are confined to that
//     client; access tokens are not (possession authorizes their revocation,
//     the rule this endpoint has always had).
func (s *OAuthService) RevokeForClient(ctx context.Context, req RevocationRequest) error {
	cimdClientID, err := s.authorizeCIMDRevoker(ctx, req)
	if err != nil {
		return err
	}
	if cimdClientID != "" {
		return revocationFailure(s.revokeToken(ctx, req.Token, req.TokenTypeHint,
			revocationScope{clientID: cimdClientID, ownAccessTokensOnly: true}))
	}

	if err := s.VerifyPresentedClientAuth(ctx, req.ClientID, req.ClientSecret, req.ClientAssertion, req.ClientAssertionType); err != nil {
		return err
	}
	// req.ClientID is the client just verified (or "" for a caller that
	// identified none); it confines refresh-token revocation to that client's
	// own tokens.
	return revocationFailure(s.RevokeToken(ctx, req.Token, req.TokenTypeHint, req.ClientID))
}

// revocationFailure logs a server-side revocation failure and turns it into
// the server_error the endpoint answers. nil stays nil.
func revocationFailure(err error) error {
	if err == nil {
		return nil
	}
	log.Error().Err(err).Msg("oauth2 revocation failed")
	return oauthServerError(revocationFailedDescription, err)
}

// authorizeCIMDRevoker decides whether a revocation request is a public CIMD
// client identifying itself by client_id alone.
//
// Returns:
//   - ("", nil) when the request is not that shape — credentials presented,
//     no client_id, CIMD disabled, the client_id is not CIMD-shaped, or the
//     registry holds a row for it (a registry row always wins, see
//     resolveClientRegistryOrCIMD). The caller falls through to the existing
//     VerifyPresentedClientAuth path, which handles all of those as before.
//   - (clientID, nil) when the client_id resolves through CIMD to a PUBLIC
//     client. The caller must constrain revocation to tokens issued to it.
//   - an invalid_client error when the client_id is CIMD-shaped but does not
//     resolve (disallowed domain, fetch failure, invalid document) or resolves
//     to a client that must authenticate (private_key_jwt). Both were refused
//     before this path existed and still are.
//
// Resolution goes through resolveClientRegistryOrCIMD, so allowed_domains,
// the SSRF-guarded fetch, the document validation and the resolution cache
// are exactly the ones the authorization_code and refresh_token flows use.
// Nothing about the resolved client is used except its public-ness and its
// client_id: in particular its grant_types grant nothing here, because the
// only action available is revoking a token this client already holds.
func (s *OAuthService) authorizeCIMDRevoker(ctx context.Context, req RevocationRequest) (string, error) {
	if req.ClientID == "" || req.ClientSecret != "" ||
		clientAssertionPresented(req.ClientAssertion, req.ClientAssertionType) {
		return "", nil
	}
	if !s.cimdSvc.Enabled() || !IsCIMDClientID(req.ClientID) {
		return "", nil
	}

	client, viaCIMD, err := s.resolveClientRegistryOrCIMD(ctx, req.ClientID)
	if !viaCIMD {
		// Registry row, registry miss, or a registry error: all of these are
		// VerifyPresentedClientAuth's to decide, as they were before.
		return "", nil
	}
	if err != nil {
		// Same refusal, and the same response, as before this path existed.
		// The cause (which may describe our fetch) stays server-side.
		return "", oauthUnauthorized("client authentication required", err)
	}
	if err := cimdRevokerMustBePublic(client); err != nil {
		return "", err
	}
	return client.ClientID, nil
}

// cimdRevokerMustBePublic refuses a resolved CIMD client that is required to
// authenticate. A document declaring private_key_jwt describes a confidential
// client (zeroid#348): presenting its client_id alone proves nothing, so it is
// refused exactly as a registered private_key_jwt client without an assertion
// is. Only a document declaring "none" — a public client — gets the RFC 7009
// §2.1 client_id-only identification.
func cimdRevokerMustBePublic(client *domain.OAuthClient) error {
	if client == nil {
		return oauthUnauthorized("client authentication required", nil)
	}
	if err := rejectUnimplementedClientAuth(client); err != nil {
		return err
	}
	if client.RequiresClientAuthentication() {
		return oauthUnauthorized(
			"client metadata document declares token_endpoint_auth_method \""+
				client.TokenEndpointAuthMethod+"\"; the client must authenticate", nil)
	}
	return nil
}

// tokenIssuedToClient reports whether a verified token's `client_id` claim
// names clientID. An empty clientID never matches, so an absent claim cannot
// be satisfied by an absent caller identity.
func tokenIssuedToClient(parsed jwt.Token, clientID string) bool {
	if parsed == nil || clientID == "" {
		return false
	}
	cid, err := jwt.Get[string](parsed, "client_id")
	return err == nil && cid == clientID
}
