package handler

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/highflame-ai/zeroid/internal/oautherror"
)

// basicHeader builds an RFC 6749 §2.3.1 Basic header: each half is
// form-urlencoded BEFORE base64, exactly as a conformant client does.
func basicHeader(id, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString(
		[]byte(url.QueryEscape(id)+":"+url.QueryEscape(secret)))
}

const (
	testBasicID     = "mcp-partner:client one" // ':' and ' ' force real form-encoding
	testBasicSecret = "s3cr3t/with+specials"
	testOtherID     = "some-other-client"
)

// TestResolveBasicClientAuth pins the RFC 6749 §2.3 decision table
// (highflame-firehog#700): two client authentication METHODS in one request are
// refused, but a body client_id that merely repeats the Basic identifier is an
// identifier (RFC 6749 §3.2.1, OAuth 2.1 §3.2.2), not a second method.
func TestResolveBasicClientAuth(t *testing.T) {
	const (
		twoMethods = "only one client authentication method"
		idMismatch = "does not match the client identifier"
		malformed  = "malformed Basic authorization header"
	)

	tests := []struct {
		name                         string
		authorization                string
		bodyID, bodySecret           string
		bodyAssertion, bodyAssertTyp string

		wantID, wantSecret string
		wantViaBasic       bool
		wantErr            string // substring of the description; "" means accepted
	}{
		{
			name:          "no Authorization header: body credentials pass through",
			bodyID:        testBasicID,
			bodySecret:    testBasicSecret,
			wantID:        testBasicID,
			wantSecret:    testBasicSecret,
			wantViaBasic:  false,
			authorization: "",
		},
		{
			name:          "non-Basic scheme is ignored, body passes through",
			authorization: "Bearer abc.def.ghi",
			bodyID:        testBasicID,
			wantID:        testBasicID,
		},
		{
			name:          "Basic only: accepted",
			authorization: basicHeader(testBasicID, testBasicSecret),
			wantID:        testBasicID,
			wantSecret:    testBasicSecret,
			wantViaBasic:  true,
		},
		{
			name:          "Basic + body client_id equal to the decoded Basic id: accepted (the #700 fix)",
			authorization: basicHeader(testBasicID, testBasicSecret),
			bodyID:        testBasicID,
			wantID:        testBasicID,
			wantSecret:    testBasicSecret,
			wantViaBasic:  true,
		},
		{
			name:          "lower-case scheme + matching body client_id: accepted",
			authorization: "basic " + strings.TrimPrefix(basicHeader(testBasicID, testBasicSecret), "Basic "),
			bodyID:        testBasicID,
			wantID:        testBasicID,
			wantSecret:    testBasicSecret,
			wantViaBasic:  true,
		},
		{
			// The comparison is against the DECODED Basic id. A body carrying
			// the still-encoded spelling names a different identifier.
			name:          "Basic + body client_id equal only to the ENCODED Basic id: refused",
			authorization: basicHeader(testBasicID, testBasicSecret),
			bodyID:        url.QueryEscape(testBasicID),
			wantViaBasic:  true,
			wantErr:       idMismatch,
		},
		{
			name:          "Basic + different body client_id: refused, the ids disagree",
			authorization: basicHeader(testBasicID, testBasicSecret),
			bodyID:        testOtherID,
			wantViaBasic:  true,
			wantErr:       idMismatch,
		},
		{
			name:          "Basic + body client_id differing only in case: refused (ids are case-sensitive)",
			authorization: basicHeader(testBasicID, testBasicSecret),
			bodyID:        strings.ToUpper(testBasicID),
			wantViaBasic:  true,
			wantErr:       idMismatch,
		},
		{
			name:          "Basic + body client_secret alone: refused, two methods",
			authorization: basicHeader(testBasicID, testBasicSecret),
			bodySecret:    testBasicSecret,
			wantViaBasic:  true,
			wantErr:       twoMethods,
		},
		{
			name:          "Basic + matching body client_id AND client_secret: refused, two methods",
			authorization: basicHeader(testBasicID, testBasicSecret),
			bodyID:        testBasicID,
			bodySecret:    testBasicSecret,
			wantViaBasic:  true,
			wantErr:       twoMethods,
		},
		{
			name:          "Basic + different body client_id AND client_secret: refused, two methods",
			authorization: basicHeader(testBasicID, testBasicSecret),
			bodyID:        testOtherID,
			bodySecret:    "other",
			wantViaBasic:  true,
			wantErr:       twoMethods,
		},
		{
			name:          "Basic + client_assertion: refused, two methods",
			authorization: basicHeader(testBasicID, testBasicSecret),
			bodyAssertion: "eyJhbGciOiJFUzI1NiJ9.e30.sig",
			bodyAssertTyp: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			wantViaBasic:  true,
			wantErr:       twoMethods,
		},
		{
			// The service only sees the merged secret. With an empty Basic
			// password it would read this as "no secret + one assertion" and
			// let it through as a single method; the handler must catch it.
			name:          "Basic with EMPTY password + client_assertion: refused, two methods",
			authorization: basicHeader(testBasicID, ""),
			bodyID:        testBasicID,
			bodyAssertion: "eyJhbGciOiJFUzI1NiJ9.e30.sig",
			bodyAssertTyp: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			wantViaBasic:  true,
			wantErr:       twoMethods,
		},
		{
			name:          "Basic + client_assertion_type alone: refused, two methods",
			authorization: basicHeader(testBasicID, testBasicSecret),
			bodyAssertTyp: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			wantViaBasic:  true,
			wantErr:       twoMethods,
		},
		{
			name:          "malformed Basic + matching-looking body client_id: still malformed",
			authorization: "Basic not-base64!!",
			bodyID:        testBasicID,
			wantViaBasic:  true,
			wantErr:       malformed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id, secret, viaBasic, err := resolveBasicClientAuth(
				tc.authorization, tc.bodyID, tc.bodySecret, tc.bodyAssertion, tc.bodyAssertTyp)

			if viaBasic != tc.wantViaBasic {
				t.Errorf("viaBasic = %v, want %v", viaBasic, tc.wantViaBasic)
			}

			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("want accepted, got error %v", err)
				}
				if id != tc.wantID || secret != tc.wantSecret {
					t.Fatalf("credentials = (%q, %q), want (%q, %q)", id, secret, tc.wantID, tc.wantSecret)
				}
				return
			}

			if err == nil {
				t.Fatalf("want refusal containing %q, got accepted (%q)", tc.wantErr, id)
			}
			code, desc, status := extractOAuthError(err)
			if code != oautherror.InvalidRequest || status != http.StatusBadRequest {
				t.Fatalf("got %d %s, want 400 invalid_request (RFC 6749 §5.2)", status, code)
			}
			if !strings.Contains(desc, tc.wantErr) {
				t.Fatalf("description %q does not contain %q", desc, tc.wantErr)
			}
			if id != "" || secret != "" {
				t.Fatalf("a refusal must not return credentials, got (%q, %q)", id, secret)
			}
			assertNoRequestValues(t, desc, tc.bodyID, tc.bodySecret, testBasicID, testBasicSecret)
		})
	}
}

// assertNoRequestValues enforces zeroid#221: error_description is reflected to
// the caller, so it must never echo caller-supplied values.
func assertNoRequestValues(t *testing.T, desc string, values ...string) {
	t.Helper()
	for _, v := range values {
		if v != "" && strings.Contains(desc, v) {
			t.Fatalf("error_description %q echoes request value %q (zeroid#221)", desc, v)
		}
	}
}

// TestBasicClientAuth_RefusalsAtEveryCaller runs the refusal rows of the
// decision table through each of the three endpoints that call
// resolveBasicClientAuth — token, introspection, revocation — so a caller that
// stops wiring a body field through cannot silently reopen a two-method
// request. The accept rows reach the OAuth service and are covered against a
// live server in tests/integration (basic_auth_body_client_id_test.go).
//
// A bare API (no service) is enough: every refusal must happen before the
// service is consulted, and a nil service would panic if one did not.
func TestBasicClientAuth_RefusalsAtEveryCaller(t *testing.T) {
	type body struct{ id, secret, assertion, assertionType string }

	rows := []struct {
		name string
		body body
	}{
		{"different body client_id", body{id: testOtherID}},
		{"body client_secret", body{secret: testBasicSecret}},
		{"matching body client_id + client_secret", body{id: testBasicID, secret: testBasicSecret}},
		{"client_assertion", body{
			assertion:     "eyJhbGciOiJFUzI1NiJ9.e30.sig",
			assertionType: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		}},
	}

	type result struct {
		status          int
		code, desc      string
		wwwAuthenticate string
	}

	callers := map[string]func(api *API, auth string, b body) result{
		"token": func(api *API, auth string, b body) result {
			in := &TokenInput{Authorization: auth}
			// A grant type with no built-in handler: Token's dispatch then reads
			// the (nil) service's custom-grant table, so a request that got past
			// the handler panics instead of being refused by some later grant
			// check that would mask a missing handler-level refusal.
			in.Body.GrantType = "urn:example:unregistered-grant"
			in.Body.ClientID, in.Body.ClientSecret = b.id, b.secret
			in.Body.ClientAssertion, in.Body.ClientAssertionType = b.assertion, b.assertionType
			out, err := api.tokenOp(context.Background(), in)
			if err != nil {
				t.Fatalf("tokenOp returned a transport error: %v", err)
			}
			return result{out.Status, out.Body.(oauthErrorBody).Error, out.Body.(oauthErrorBody).ErrorDescription, out.WWWAuthenticate}
		},
		"introspection": func(api *API, auth string, b body) result {
			in := &IntrospectInput{Authorization: auth}
			in.Body.Token = "tok"
			in.Body.ClientID, in.Body.ClientSecret = b.id, b.secret
			in.Body.ClientAssertion, in.Body.ClientAssertionType = b.assertion, b.assertionType
			out, err := api.introspectOp(context.Background(), in)
			if err != nil {
				t.Fatalf("introspectOp returned a transport error: %v", err)
			}
			eb, ok := out.Body.(oauthErrorBody)
			if !ok {
				t.Fatalf("introspection body = %#v, want an oauthErrorBody refusal", out.Body)
			}
			return result{out.Status, eb.Error, eb.ErrorDescription, out.WWWAuthenticate}
		},
		"revocation": func(api *API, auth string, b body) result {
			in := &OAuthRevokeInput{Authorization: auth}
			in.Body.Token = "tok"
			in.Body.ClientID, in.Body.ClientSecret = b.id, b.secret
			in.Body.ClientAssertion, in.Body.ClientAssertionType = b.assertion, b.assertionType
			out, err := api.revokeOp(context.Background(), in)
			if err != nil {
				t.Fatalf("revokeOp returned a transport error: %v", err)
			}
			if out.Body.Revoked {
				t.Fatal("a refused revocation must not report revoked=true")
			}
			return result{out.Status, out.Body.Error, out.Body.ErrorDescription, out.WWWAuthenticate}
		},
	}

	for callerName, call := range callers {
		for _, row := range rows {
			t.Run(callerName+"/"+row.name, func(t *testing.T) {
				var api API // no service: a refusal must not need one
				got := call(&api, basicHeader(testBasicID, testBasicSecret), row.body)

				if got.status != http.StatusBadRequest || got.code != oautherror.InvalidRequest {
					t.Fatalf("got %d %q, want 400 invalid_request", got.status, got.code)
				}
				// RFC 6749 §5.2 echoes WWW-Authenticate only on a 401.
				if got.wwwAuthenticate != "" {
					t.Fatalf("400 must not carry WWW-Authenticate, got %q", got.wwwAuthenticate)
				}
				assertNoRequestValues(t, got.desc, row.body.id, row.body.secret, testBasicID, testBasicSecret)
			})
		}
	}
}
