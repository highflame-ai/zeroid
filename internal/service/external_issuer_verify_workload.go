package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
)

// Workload issuer proof of control (ADR 0042 open question 8, for workload
// issuers): the deployer hands the account a one-time challenge, the account
// obtains a token from its issuer with the challenge as the audience
// (`aws sts get-web-identity-token --audience`, `kubectl create token
// --audience`, a JWT-SVID for that audience) and the deployer asks ZeroID to
// verify it under the row. A row is written disabled until then. This route
// is the ZeroID half; the deployer records the result and enables the row.
// The contract is docs/external-issuers.md.

// maxVerifyWorkloadTokenBytes caps the token; an STS, Kubernetes or SPIFFE
// JWT is a few kilobytes. maxVerifyAudienceBytes caps the challenge.
const (
	maxVerifyWorkloadTokenBytes = 16 << 10
	maxVerifyAudienceBytes      = 512
)

var errIssuerNotWorkloadRow = issuerErr(http.StatusUnprocessableEntity, "wrong_kind",
	"this route is for workload issuers; the issuer is a person issuer")

// VerifyWorkloadTokenInput is a VerifyWorkloadToken request. Audience is the
// challenge the deployer issued; the token must be minted for it alone.
type VerifyWorkloadTokenInput struct {
	Token    string
	Audience string
}

// WorkloadTokenVerification is a verified challenge token's issuer and
// subject.
type WorkloadTokenVerification struct {
	IssuerID string `json:"issuer_id"`
	Issuer   string `json:"issuer"`
	Subject  string `json:"subject"`
}

// VerifyWorkloadToken verifies a token under one of accountID's workload
// issuer rows the way a federated client assertion (P2) is verified, with the
// same routine (validateExternalAssertion): signature against the row's JWKS,
// iss, the row's claim constraints or shared-issuer pin, sub, exp, iat, the
// row's token-age cap on age and on lifetime. Its aud must be exactly
// in.Audience, a value no P2 assertion carries, so a captured assertion is
// not a proof. Unlike P2 it accepts a disabled row, since a row waits
// disabled for this proof. It needs no binding, mints nothing and records no
// jti. Every refusal is a 422 with a code; the token never appears in a
// refusal or a log line.
func (s *ExternalIssuerService) VerifyWorkloadToken(ctx context.Context, accountID, id string, in VerifyWorkloadTokenInput) (*WorkloadTokenVerification, error) {
	if err := validateVerifyWorkloadTokenInput(in); err != nil {
		return nil, err
	}
	row, err := s.Get(ctx, accountID, id)
	if err != nil {
		return nil, err
	}
	out, err := s.verifyWorkloadTokenForRow(ctx, row, in)
	code := "ok"
	if err != nil {
		var apiErr *IssuerAPIError
		code = "error"
		if errors.As(err, &apiErr) {
			code = apiErr.Code
		}
	}
	log.Info().Str("account_id", accountID).Str("issuer_id", row.ID).Str("result", code).Msg("issuer workload token verification")
	return out, err
}

func validateVerifyWorkloadTokenInput(in VerifyWorkloadTokenInput) error {
	switch {
	case in.Token == "" || len(in.Token) > maxVerifyWorkloadTokenBytes:
		return issuerErr(http.StatusBadRequest, "invalid_request", fmt.Sprintf("token is required (at most %d bytes)", maxVerifyWorkloadTokenBytes))
	case in.Audience == "" || len(in.Audience) > maxVerifyAudienceBytes:
		return issuerErr(http.StatusBadRequest, "invalid_request", fmt.Sprintf("audience is required (at most %d bytes)", maxVerifyAudienceBytes))
	}
	return nil
}

func (s *ExternalIssuerService) verifyWorkloadTokenForRow(ctx context.Context, row *domain.ExternalIssuer, in VerifyWorkloadTokenInput) (*WorkloadTokenVerification, error) {
	if row.Kind != domain.IssuerKindWorkload {
		return nil, errIssuerNotWorkloadRow
	}
	// A challenge equal to an audience the row or this server accepts would
	// let an ordinary P2 assertion, captured in transit, stand in for proof.
	if slices.Contains(row.Audiences, in.Audience) ||
		(s.cfg.SelfIssuer != "" && domain.CanonicalIssuer(in.Audience) == domain.CanonicalIssuer(s.cfg.SelfIssuer)) {
		return nil, issuerErr(http.StatusUnprocessableEntity, "audience_not_a_challenge",
			"audience must be a one-time challenge, not an audience the issuer or this server accepts")
	}
	// A shared issuer's row may pin several values (up to the constraint
	// cap), and a token carries one. A proof with one value must not stand
	// for a row that also pins another customer's, so such a row is proven
	// only when it pins exactly one.
	if pin := s.sharedPin(row.Issuer); pin != "" && len(row.ClaimConstraints[pin]) != 1 {
		return nil, issuerErr(http.StatusUnprocessableEntity, "pin_not_single",
			fmt.Sprintf("a shared issuer's workload row is proven only when it pins exactly one %s value", pin))
	}
	entry, err := s.cfg.Registry.EntryForRow(row)
	if err != nil {
		return nil, err
	}
	tok, err := validateExternalAssertion(ctx, in.Token, entry, "token", requirePlainSub, in.Audience)
	if err != nil {
		return nil, workloadTokenRefusal(err)
	}
	// validateExternalAssertion accepts the row's audiences too; the proof is
	// a token minted for the challenge and nothing else.
	if aud, _ := tok.Audience(); len(aud) != 1 || aud[0] != in.Audience {
		return nil, issuerErr(http.StatusUnprocessableEntity, "audience_mismatch",
			"the token's aud must be exactly the challenge")
	}
	exp, _ := tok.Expiration()
	iat, _ := tok.IssuedAt()
	if maxLifetime := time.Duration(row.MaxTokenAgeSeconds) * time.Second; exp.Sub(iat) > maxLifetime {
		return nil, issuerErr(http.StatusUnprocessableEntity, "token_invalid",
			fmt.Sprintf("the token's lifetime exceeds the issuer's max_token_age (%s)", maxLifetime))
	}
	sub, _ := tok.Subject()
	return &WorkloadTokenVerification{IssuerID: row.ID, Issuer: row.Issuer, Subject: sub}, nil
}

// workloadTokenRefusal is idTokenRefusal for a workload token: the same
// stable codes, with this route's wording.
func workloadTokenRefusal(err error) error {
	switch {
	case errors.Is(err, errAssertionAudience):
		return issuerErr(http.StatusUnprocessableEntity, "audience_mismatch",
			"the token's aud must be exactly the challenge")
	case errors.Is(err, errAssertionConstraints):
		return issuerErr(http.StatusUnprocessableEntity, "constraint_mismatch",
			"the token does not satisfy the issuer's claim constraints")
	}
	var oauthErr *OAuthError
	if errors.As(err, &oauthErr) && oauthErr.HTTPStatus >= http.StatusInternalServerError {
		log.Warn().Str("reason", oauthErr.Description).Msg("issuer workload token verification could not load keys")
		return issuerErr(http.StatusUnprocessableEntity, "jwks_unreachable", "the issuer's JWKS could not be fetched")
	}
	return issuerErr(http.StatusUnprocessableEntity, "token_invalid",
		"the token is not a valid token from this issuer (malformed, signature, iss, sub, expiry or age)")
}
