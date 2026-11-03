package service

import (
	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
)

// authCodeRedemption is what the success line of an authorization_code
// redemption records: identifiers and facts, never the code, the
// code_verifier, a client secret or a client assertion.
type authCodeRedemption struct {
	requestID string
	clientID  string
	// cimd is true when the client was resolved from its Client ID Metadata
	// Document rather than from the registry.
	cimd bool
	// clientAuth is the client authentication the grant required and verified
	// (clientAuthRequired).
	clientAuth string
	// What the request carried, whatever the grant then did with it: a public
	// client's secret, for example, is never checked.
	sentAuthorizationHeader bool
	sentClientSecret        bool
	sentClientAssertion     bool
	accountID               string
	projectID               string
	userID                  string
	// jti names the access token issued, as the "Credential issued" line does.
	jti string
}

// logAuthorizationCodeRedeemed writes the success line of an authorization_code
// redemption. For one token request it records how the client authenticated
// and that PKCE held: the client authentication the grant required, what the
// request carried, and that its code_verifier matched the S256 challenge the
// code was issued for. An operator can then show both for a given request
// without the request body, which is never logged.
//
// It is written only after the token is issued, so every field is a fact of a
// redemption that succeeded. code_verifier records the result of the check,
// never the value. request_id is omitted when the request carried none.
func logAuthorizationCodeRedeemed(r authCodeRedemption) {
	ev := log.Info()
	if r.requestID != "" {
		ev = ev.Str("request_id", r.requestID)
	}
	ev.Str("client_id", r.clientID).
		Bool("cimd", r.cimd).
		Str("client_auth", r.clientAuth).
		Bool("sent_authorization_header", r.sentAuthorizationHeader).
		Bool("sent_client_secret", r.sentClientSecret).
		Bool("sent_client_assertion", r.sentClientAssertion).
		// The only method: IssueAuthCode refuses any other, and
		// verifyCodeChallenge computes S256.
		Str("code_challenge_method", "S256").
		Str("code_verifier", "verified").
		Str("account_id", r.accountID).
		Str("project_id", r.projectID).
		Str("user_id", r.userID).
		Str("jti", r.jti).
		Msg("authorization code redeemed")
}

// clientAuthRequired names the client authentication verifyConfidentialClientAuth
// requires of a client: "private_key_jwt" for a key-based client, "none" for a
// client that carries no credential and proves possession with PKCE alone, and
// otherwise "client_secret". The two secret methods are one class here, as
// they are in enforceRegisteredClientAuthMethod, so the value names what was
// enforced rather than the registered spelling.
func clientAuthRequired(c *domain.OAuthClient) string {
	switch {
	case c.TokenEndpointAuthMethod == clientAuthMethodPrivateKeyJWT:
		return clientAuthMethodPrivateKeyJWT
	case !c.RequiresClientAuthentication():
		return "none"
	default:
		return "client_secret"
	}
}
