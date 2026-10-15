package handler

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	"github.com/rs/zerolog/log"
)

// Interactive-login passthrough parameters.
//
// redirectToInteractiveLogin rebuilds return_to from the protocol parameters
// ZeroID validated and drops everything else on the inbound query, so a
// credential a caller put in the wrong channel is never forwarded to the login
// surface. Some embedders also need one or two parameters of their OWN to
// survive the login round trip — a CLI that pre-selects which project the
// sign-in is for, say — and rebuilding gave them no way to say so.
//
// The allowlist is that way. It is deployer configuration, not caller input:
// only names the embedder listed are copied, each verbatim, and only when the
// value is unambiguous and small. A name ZeroID gives meaning to can never be
// listed, so passthrough cannot smuggle a second client_id, redirect_uri,
// scope or credential into the resumed request.
const (
	// MaxInteractiveLoginPassthroughParams bounds the allowlist. Passthrough is
	// for a handful of embedder hints, not a general query forwarder.
	MaxInteractiveLoginPassthroughParams = 8
	// MaxInteractiveLoginPassthroughValueLen bounds each copied value, in bytes.
	// A longer value is dropped, not truncated: a truncated identifier is a
	// different identifier.
	MaxInteractiveLoginPassthroughValueLen = 256
)

// passthroughNameSyntax is a conservative parameter-name shape: what an
// embedder hint looks like, and nothing a URL needs escaping for.
var passthroughNameSyntax = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,63}$`)

// reservedPassthroughNames can never be passed through. Compared
// case-insensitively, so Client_ID is as reserved as client_id.
//
// The set is every parameter that has a meaning at an OAuth authorization
// endpoint or that carries a credential, whether or not ZeroID implements it
// today: the protocol parameters return_to is rebuilt from (an allowlisted
// copy would override the validated value), return_to itself, the OAuth 2.0 /
// OIDC / PKCE / RFC 8707 / RFC 9101 / RFC 9126 / RFC 9396 / RFC 9449
// authorization request parameters (listing one would let a caller add it to
// a request ZeroID already validated without it), and token-endpoint and
// credential parameters (forwarding one is exactly the leak rebuilding exists
// to prevent).
var reservedPassthroughNames = map[string]bool{
	// Rebuilt by redirectToInteractiveLogin, and its own parameter.
	"client_id": true, "redirect_uri": true, "response_type": true,
	"code_challenge": true, "code_challenge_method": true, "state": true,
	"scope": true, "resource": true, "return_to": true,
	// Other authorization request parameters.
	"response_mode": true, "nonce": true, "prompt": true, "max_age": true,
	"display": true, "ui_locales": true, "claims_locales": true,
	"login_hint": true, "id_token_hint": true, "acr_values": true,
	"claims": true, "request": true, "request_uri": true,
	"authorization_details": true, "dpop_jkt": true, "registration": true,
	"audience": true, "iss": true,
	// Response parameters.
	"code": true, "error": true, "error_description": true, "error_uri": true,
	"id_token": true, "access_token": true, "token_type": true, "expires_in": true,
	// Token-endpoint and credential parameters.
	"grant_type": true, "code_verifier": true, "refresh_token": true,
	"client_secret": true, "client_assertion": true, "client_assertion_type": true,
	"assertion": true, "subject_token": true, "subject_token_type": true,
	"actor_token": true, "actor_token_type": true, "requested_token_type": true,
	"api_key": true, "password": true, "username": true, "device_code": true,
	"user_code": true, "auth_req_id": true,
}

// ValidateInteractiveLoginPassthroughParams checks an embedder's allowlist
// and returns it de-duplicated, in the order given. An error names the first
// offending entry; nothing is returned with it.
func ValidateInteractiveLoginPassthroughParams(names []string) ([]string, error) {
	seen := make(map[string]bool, len(names))
	out := make([]string, 0, len(names))

	for _, name := range names {
		if !passthroughNameSyntax.MatchString(name) {
			return nil, fmt.Errorf("interactive login passthrough parameter %q: "+
				"must be 1-64 characters of letters, digits, '_', '.' or '-', starting with a letter", name)
		}

		if reservedPassthroughNames[strings.ToLower(name)] {
			return nil, fmt.Errorf("interactive login passthrough parameter %q: "+
				"reserved — it has protocol or credential meaning at the authorization endpoint", name)
		}

		if seen[name] {
			continue
		}

		seen[name] = true
		out = append(out, name)
	}

	if len(out) > MaxInteractiveLoginPassthroughParams {
		return nil, errors.New("interactive login passthrough: at most " +
			fmt.Sprint(MaxInteractiveLoginPassthroughParams) + " parameters may be listed")
	}

	return out, nil
}

// addPassthroughParams copies each allowlisted parameter from inbound into
// returnTo, verbatim. A parameter is copied only when it appears exactly once
// with a non-empty value of at most MaxInteractiveLoginPassthroughValueLen
// bytes and no control characters; otherwise it is dropped, never truncated or
// guessed at. Dropping is not an error: the parameter is the embedder's hint,
// not part of the authorization request, and refusing the sign-in over it
// would let a malformed hint block a login.
//
// A name already present in returnTo is never overwritten. The validator keeps
// protocol names off the allowlist; this is the second lock on the same door.
func addPassthroughParams(returnTo, inbound url.Values, names []string, clientID string) {
	for _, name := range names {
		if _, taken := returnTo[name]; taken {
			continue
		}

		values, present := inbound[name]
		if !present {
			continue
		}

		if reason := passthroughRefusal(values); reason != "" {
			// The value is not logged: it is caller-controlled, and the
			// point of rebuilding return_to is that stray input does not
			// travel anywhere it was not meant to — logs included.
			log.Warn().
				Str("param", name).
				Str("client_id", clientID).
				Str("reason", reason).
				Msg("interactive login passthrough parameter dropped")

			continue
		}

		returnTo.Set(name, values[0])
	}
}

// passthroughRefusal says why values cannot be passed through, or "" when the
// single value can be.
func passthroughRefusal(values []string) string {
	switch {
	case len(values) != 1:
		return "repeated"
	case values[0] == "":
		return "empty"
	case len(values[0]) > MaxInteractiveLoginPassthroughValueLen:
		return "too long"
	case strings.ContainsFunc(values[0], unicode.IsControl):
		return "control character"
	default:
		return ""
	}
}
