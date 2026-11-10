package service

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"

	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
)

// Issuer ownership proof (ADR 0042 open question 8, for person issuers): the
// deployer has the account's owner sign in through a person issuer and asks
// ZeroID to verify the resulting ID token under the row. These two routes
// are the ZeroID half; the deployer decides what a verified sign-in proves.
// The contract is docs/external-issuers.md.

// Caps on the VerifyIDToken body. An ID token is a few kilobytes; nonce and
// client_id are short identifiers.
const (
	maxVerifyIDTokenBytes  = 16 << 10
	maxVerifyClientIDBytes = 512
	maxVerifyNonceBytes    = 512
)

var (
	errIssuerWrongKind = issuerErr(http.StatusUnprocessableEntity, "wrong_kind",
		"this route is for person issuers; the issuer is a workload issuer")
	errIssuerRowDisabled = issuerErr(http.StatusUnprocessableEntity, "issuer_disabled",
		"the issuer is disabled")
)

// IssuerDiscovery is the sign-in endpoints a person issuer's discovery
// document names, for a deployer starting an authorization-code sign-in.
type IssuerDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

// Discovery re-reads a person issuer's discovery document with the fetch
// issuer creation uses and returns its authorization and token endpoints,
// each an https URL (http only with allow_private_endpoints).
func (s *ExternalIssuerService) Discovery(ctx context.Context, accountID, id string) (*IssuerDiscovery, error) {
	row, err := s.Get(ctx, accountID, id)
	if err != nil {
		return nil, err
	}
	return s.discoveryForRow(ctx, row)
}

func (s *ExternalIssuerService) discoveryForRow(ctx context.Context, row *domain.ExternalIssuer) (*IssuerDiscovery, error) {
	if row.Kind != domain.IssuerKindPerson {
		return nil, errIssuerWrongKind
	}
	doc, err := s.discover(ctx, row.Issuer)
	if err != nil {
		return nil, err
	}
	for _, ep := range []string{doc.AuthorizationEndpoint, doc.TokenEndpoint} {
		if err := domain.ValidateIssuerURL(ep, s.cfg.AllowPrivateEndpoints); err != nil {
			return nil, issuerErr(http.StatusUnprocessableEntity, "discovery_invalid",
				"the issuer's discovery document names no usable authorization_endpoint and token_endpoint")
		}
	}
	return &IssuerDiscovery{Issuer: row.Issuer, AuthorizationEndpoint: doc.AuthorizationEndpoint, TokenEndpoint: doc.TokenEndpoint}, nil
}

// VerifyIDTokenInput is a VerifyIDToken request. ClientID is the app the
// token was issued to; Nonce is the value the deployer sent on the
// authorization request.
type VerifyIDTokenInput struct {
	IDToken  string
	ClientID string
	Nonce    string
}

// IDTokenVerification is a verified ID token's person, read through the
// row's claim mapping exactly as the ID-token exchange reads it.
type IDTokenVerification struct {
	IssuerID      string `json:"issuer_id"`
	Issuer        string `json:"issuer"`
	Subject       string `json:"subject"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	// Groups is what the row's claim_mapping.groups reads from the token,
	// with the limits and filtering the grants apply before stamping the
	// `groups` claim. Omitted when the mapping is unset or yields none.
	Groups []string `json:"groups,omitempty"`
}

// VerifyIDToken verifies an ID token under one of accountID's person issuer
// rows the way the ID-token exchange (P1c) verifies a person's token, with
// the same routine (verifyPersonIDToken), and also requires its nonce claim
// to equal in.Nonce. It needs no binding, mints nothing and records no jti:
// the token is only read. Every refusal is a 422 with a code; a token or its
// claims never appear in a refusal or a log line.
func (s *ExternalIssuerService) VerifyIDToken(ctx context.Context, accountID, id string, in VerifyIDTokenInput) (*IDTokenVerification, error) {
	if err := validateVerifyIDTokenInput(in); err != nil {
		return nil, err
	}
	row, err := s.Get(ctx, accountID, id)
	if err != nil {
		return nil, err
	}
	out, err := s.verifyIDTokenForRow(ctx, row, in)
	code := "ok"
	if err != nil {
		var apiErr *IssuerAPIError
		code = "error"
		if errors.As(err, &apiErr) {
			code = apiErr.Code
		}
	}
	log.Info().Str("account_id", accountID).Str("issuer_id", row.ID).Str("result", code).Msg("issuer id_token verification")
	return out, err
}

func validateVerifyIDTokenInput(in VerifyIDTokenInput) error {
	switch {
	case in.IDToken == "" || len(in.IDToken) > maxVerifyIDTokenBytes:
		return issuerErr(http.StatusBadRequest, "invalid_request", fmt.Sprintf("id_token is required (at most %d bytes)", maxVerifyIDTokenBytes))
	case in.ClientID == "" || len(in.ClientID) > maxVerifyClientIDBytes:
		return issuerErr(http.StatusBadRequest, "invalid_request", fmt.Sprintf("client_id is required (at most %d bytes)", maxVerifyClientIDBytes))
	case in.Nonce == "" || len(in.Nonce) > maxVerifyNonceBytes:
		return issuerErr(http.StatusBadRequest, "invalid_request", fmt.Sprintf("nonce is required (at most %d bytes)", maxVerifyNonceBytes))
	}
	return nil
}

// verifyIDTokenForRow is VerifyIDToken after the row is read. The row's kind
// and state are checked before the token is looked at.
func (s *ExternalIssuerService) verifyIDTokenForRow(ctx context.Context, row *domain.ExternalIssuer, in VerifyIDTokenInput) (*IDTokenVerification, error) {
	if row.Kind != domain.IssuerKindPerson {
		return nil, errIssuerWrongKind
	}
	if !row.Enabled {
		return nil, errIssuerRowDisabled
	}
	entry, err := s.cfg.Registry.EntryForRow(row)
	if err != nil {
		return nil, err
	}
	tok, err := verifyPersonIDToken(ctx, in.IDToken, entry, in.ClientID)
	if err != nil {
		return nil, idTokenRefusal(err)
	}
	if nonce, _ := tok.claims["nonce"].(string); !nonceMatches(nonce, in.Nonce) {
		return nil, issuerErr(http.StatusUnprocessableEntity, "nonce_mismatch",
			"the ID token's nonce is missing or is not the one sent on the sign-in")
	}
	return &IDTokenVerification{
		IssuerID: row.ID, Issuer: row.Issuer, Subject: tok.userID,
		Email: tok.email, EmailVerified: tok.emailVerified, Groups: tok.groups,
	}, nil
}

// idTokenRefusal turns verifyPersonIDToken's *OAuthError into a stable code.
// The OAuth description is not returned: the code is the contract.
func idTokenRefusal(err error) error {
	switch {
	case errors.Is(err, errAssertionAudience):
		return issuerErr(http.StatusUnprocessableEntity, "audience_mismatch",
			"the ID token was not issued to client_id (aud, or azp when present)")
	case errors.Is(err, errAssertionConstraints):
		return issuerErr(http.StatusUnprocessableEntity, "constraint_mismatch",
			"the ID token does not satisfy the issuer's claim constraints")
	}
	var oauthErr *OAuthError
	if errors.As(err, &oauthErr) && oauthErr.HTTPStatus >= http.StatusInternalServerError {
		// The issuer's key set could not be loaded: not the token's fault.
		log.Warn().Str("reason", oauthErr.Description).Msg("issuer id_token verification could not load keys")
		return issuerErr(http.StatusUnprocessableEntity, "jwks_unreachable", "the issuer's JWKS could not be fetched")
	}
	return issuerErr(http.StatusUnprocessableEntity, "token_invalid",
		"the ID token is not a valid ID token from this issuer (malformed, signature, iss, expiry, age, or not a person's ID token)")
}

// nonceMatches compares in constant time. Both sides are hashed first so
// the comparison does not even leak the expected nonce's length.
func nonceMatches(got, want string) bool {
	if got == "" {
		return false
	}
	g, w := sha256.Sum256([]byte(got)), sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(g[:], w[:]) == 1
}
