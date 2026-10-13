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
//   - A CIMD client. It has no registry row, so VerifyPresentedClientAuth —
//     which is shared with introspection and stays registry-only there —
//     refuses it. Here it is resolved through its metadata document and
//     authenticated as its document declares: a public client ("none") by its
//     client_id alone (RFC 7009 §2.1), a confidential one (private_key_jwt) by
//     an RFC 7523 §2.2 assertion against the document's keys. Either way the
//     revocation is then CONSTRAINED to tokens issued to that same client_id,
//     for both token types: an access token only if its verified `client_id`
//     claim names the client, a refresh token only if its row was issued to
//     the client (and then with its whole family and the access tokens issued
//     from it, as for any client). That constraint is what makes accepting a
//     self-published identity safe on this endpoint: anyone can publish a
//     document (with keys of their choosing) at a URL they control, so being
//     that URL may only ever reach tokens that URL's client already holds.
//     Introspection has no equivalent constraint — it answers questions about
//     any token presented — which is why it keeps refusing CIMD clients,
//     authenticated or not.
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

// authorizeCIMDRevoker decides whether a revocation request comes from a CIMD
// client, and if so authenticates it.
//
// Returns:
//   - ("", nil) when the request is not a CIMD client's — a client_secret
//     presented, no client identifier at all, CIMD disabled, the identifier is
//     not CIMD-shaped, or the registry holds a row for it (a registry row
//     always wins, see resolveClientRegistryOrCIMD). The caller falls through
//     to the existing VerifyPresentedClientAuth path, which handles all of
//     those exactly as before.
//   - (clientID, nil) when the identifier resolves through CIMD and the client
//     authenticates as its document declares. The caller must constrain
//     revocation to tokens issued to it.
//   - an invalid_client error when the identifier is CIMD-shaped but does not
//     resolve (disallowed domain, fetch failure, invalid document), or the
//     client does not authenticate as declared (a private_key_jwt client with
//     no or a bad assertion; a public client presenting an assertion).
//
// The client is identified by client_id, or — when that is omitted and an
// assertion is presented — by the assertion's iss, the same RFC 7523 §3
// fallback the token endpoint and VerifyPresentedClientAuth apply. The
// unverified iss only selects which document's keys the assertion is checked
// against; verifyClientAssertion then requires iss == that client_id.
//
// Resolution goes through resolveClientRegistryOrCIMD and authentication
// through verifyConfidentialClientAuth: the same allowed_domains policy, fetch,
// document validation and cache, and the same assertion rules (accepted aud
// values, alg allow-list, exp bounds, jti single-use, key discovery from the
// document's jwks / jwks_uri), that the authorization_code and refresh_token
// grants apply to a CIMD client. Nothing is forked. In particular the accepted
// aud set is acceptedClientAssertionAudiences — the issuer identifier and the
// token endpoint URL — exactly as for a registered private_key_jwt client at
// this endpoint; the revocation endpoint URL is not added, because RFC 7523 §3
// asks aud to identify the authorization server and widening that set only
// here would make one endpoint disagree with the rest.
//
// Nothing about the resolved client is used beyond its client_id and how it
// authenticates: its grant_types grant nothing here, because the only action
// available is revoking a token this client already holds.
func (s *OAuthService) authorizeCIMDRevoker(ctx context.Context, req RevocationRequest) (string, error) {
	if req.ClientSecret != "" || !s.cimdSvc.Enabled() {
		return "", nil
	}
	clientID := req.ClientID
	assertionPresented := clientAssertionPresented(req.ClientAssertion, req.ClientAssertionType)
	if clientID == "" && assertionPresented {
		clientID, _ = ClientIDFromAssertion(req.ClientAssertion)
	}
	if clientID == "" || !IsCIMDClientID(clientID) {
		return "", nil
	}

	client, viaCIMD, err := s.resolveClientRegistryOrCIMD(ctx, clientID)
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
	if err := s.authenticateCIMDRevoker(ctx, client, clientID, req.ClientAssertion, req.ClientAssertionType); err != nil {
		return "", err
	}
	return client.ClientID, nil
}

// authenticateCIMDRevoker authenticates a resolved CIMD client as its document
// declares, with the function the authorization_code and refresh_token grants
// use for the same client (verifyConfidentialClientAuth):
//
//   - private_key_jwt: a valid RFC 7523 §2.2 assertion signed by a key the
//     document publishes is required; none, or a bad one, is refused. This is
//     a confidential client (zeroid#348) and its client_id alone proves
//     nothing.
//   - none: a public client, identified by its client_id alone (RFC 7009
//     §2.1). An assertion is refused — nothing vetted a key for it.
//
// No secret is passed: a CIMD client cannot have one, and a request carrying
// one never reaches here (authorizeCIMDRevoker sends it to the registry path).
func (s *OAuthService) authenticateCIMDRevoker(
	ctx context.Context, client *domain.OAuthClient, clientID, assertion, assertionType string,
) error {
	if client == nil {
		return oauthUnauthorized("client authentication required", nil)
	}
	return s.verifyConfidentialClientAuth(ctx, client, clientID, "", assertion, assertionType)
}

// tokenIssuedToClient reports whether a verified token's `client_id` claim
// names clientID. An empty clientID never matches, so an absent claim cannot
// be satisfied by an absent caller identity.
//
// parsed must come from parseToken, which has verified the signature against
// our own keys. The claim is set at issuance from the client the grant
// authenticated or resolved and is reserved against additional_claims, so the
// caller cannot influence it; for a CIMD client it is the document URL itself.
// A token without the claim is not attributable to any client and is never
// revoked on a CIMD client's behalf.
func tokenIssuedToClient(parsed jwt.Token, clientID string) bool {
	if parsed == nil || clientID == "" {
		return false
	}
	cid, err := jwt.Get[string](parsed, "client_id")
	return err == nil && cid == clientID
}
