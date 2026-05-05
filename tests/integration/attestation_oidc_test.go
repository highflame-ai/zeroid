package integration_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// assertErrorBodyContains reads the response body (non-destructively — the
// body is restored after inspection so tests can still decode it) and
// asserts that the error message inside includes substr. Covers the case
// where a test passed with the right status but the WRONG reason (e.g.
// DB blip 500 → 400 after wrapping); without a body check, those slip
// through.
func assertErrorBodyContains(t *testing.T, resp *http.Response, substr string) {
	t.Helper()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	// Put the bytes back so defer Close and any further decode still work.
	resp.Body = io.NopCloser(bytes.NewReader(raw))
	assert.Containsf(t, string(raw), substr,
		"error response body must mention %q (got: %s)", substr, string(raw))
}

// oidcIssuer stands up a minimal OIDC discovery + JWKS server for tests so
// the attestation OIDC verifier has a real issuer to talk to. It returns
// the issuer URL and a function that mints signed JWTs with caller-supplied
// claims.
type oidcIssuer struct {
	URL     string
	signKey jwk.Key
	sign    func(claims map[string]any) string
	close   func()
}

func newOIDCIssuer(t *testing.T) *oidcIssuer {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signKey, err := jwk.FromRaw(priv)
	require.NoError(t, err)
	require.NoError(t, signKey.Set(jwk.KeyIDKey, "test-issuer-key-1"))
	require.NoError(t, signKey.Set(jwk.AlgorithmKey, jwa.RS256))

	pubKey, err := signKey.PublicKey()
	require.NoError(t, err)
	require.NoError(t, pubKey.Set(jwk.KeyIDKey, "test-issuer-key-1"))
	require.NoError(t, pubKey.Set(jwk.AlgorithmKey, jwa.RS256))
	require.NoError(t, pubKey.Set(jwk.KeyUsageKey, "sig"))

	jwks := jwk.NewSet()
	require.NoError(t, jwks.AddKey(pubKey))

	mux := http.NewServeMux()
	var issuerURL string

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":   issuerURL,
			"jwks_uri": issuerURL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	})

	srv := httptest.NewServer(mux)
	issuerURL = srv.URL

	sign := func(claims map[string]any) string {
		t.Helper()
		tok := jwt.New()
		require.NoError(t, tok.Set(jwt.IssuerKey, issuerURL))
		require.NoError(t, tok.Set(jwt.IssuedAtKey, time.Now().Unix()))
		require.NoError(t, tok.Set(jwt.ExpirationKey, time.Now().Add(5*time.Minute).Unix()))
		for k, v := range claims {
			require.NoError(t, tok.Set(k, v))
		}
		signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, signKey))
		require.NoError(t, err)
		return string(signed)
	}

	return &oidcIssuer{URL: issuerURL, signKey: signKey, sign: sign, close: srv.Close}
}

// submitAttestation wraps the submit endpoint so each test can post a proof
// in one line. Returns the created record's UUID.
func submitAttestation(t *testing.T, identityID, proofType, proofValue string) string {
	t.Helper()
	resp := post(t, adminPath("/attestation/submit"), map[string]any{
		"identity_id": identityID,
		"level":       "software",
		"proof_type":  proofType,
		"proof_value": proofValue,
	}, adminHeaders())
	require.Equal(t, http.StatusCreated, resp.StatusCode,
		"attestation submit expected 201")
	return decode(t, resp)["id"].(string)
}

func verifyAttestation(t *testing.T, attestationID string) *http.Response {
	t.Helper()
	return post(t, adminPath("/attestation/verify"), map[string]any{
		"attestation_id": attestationID,
	}, adminHeaders())
}

func upsertOIDCPolicy(t *testing.T, cfg map[string]any) {
	t.Helper()
	body := map[string]any{
		"proof_type": "oidc_token",
		"config":     cfg,
	}
	resp := doRequest(t, http.MethodPut, adminPath("/attestation-policies"), body, adminHeaders())
	require.Equal(t, http.StatusOK, resp.StatusCode, "upsert policy expected 200")
	_ = resp.Body.Close()
}

// TestAttestationFailsClosedWithNoPolicy verifies the top-level contract:
// a submitted oidc_token attestation must not be marked verified when no
// AttestationPolicy exists for the tenant + proof type. This is the fix
// for the "any submitted attestation becomes verified trust" bug.
func TestAttestationFailsClosedWithNoPolicy(t *testing.T) {
	iss := newOIDCIssuer(t)
	defer iss.close()

	reg := registerAgent(t, uid("attest-no-policy"))
	token := iss.sign(map[string]any{"sub": "ci-job-1"})
	id := submitAttestation(t, reg.AgentID, "oidc_token", token)

	resp := verifyAttestation(t, id)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"verify must fail closed when the tenant has no attestation policy")
	assertErrorBodyContains(t, resp, "no attestation policy configured")
}

// TestAttestationOIDCVerifierHappyPath covers the full working flow:
// trusted issuer + signed JWT + matching audience/claims → verified,
// identity trust promoted, credential issued.
func TestAttestationOIDCVerifierHappyPath(t *testing.T) {
	iss := newOIDCIssuer(t)
	defer iss.close()

	reg := registerAgent(t, uid("attest-oidc-ok"))

	upsertOIDCPolicy(t, map[string]any{
		"issuers": []map[string]any{{
			"url":       iss.URL,
			"audiences": []string{"zeroid://test"},
			"required_claims": map[string]string{
				"repository": "myorg/myrepo",
			},
		}},
	})

	token := iss.sign(map[string]any{
		"sub":        "ci-job-42",
		"aud":        "zeroid://test",
		"repository": "myorg/myrepo",
	})
	id := submitAttestation(t, reg.AgentID, "oidc_token", token)

	resp := verifyAttestation(t, id)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode, "happy-path verify expected 200")

	body := decode(t, resp)
	record := body["record"].(map[string]any)
	assert.Equal(t, true, record["is_verified"], "record must be marked verified")
	assert.NotEmpty(t, record["verified_at"])
	assert.NotEmpty(t, body["token"], "verified attestation must auto-issue a credential")
}

// TestAttestationOIDCVerifierRejectsUntrustedIssuer enforces the issuer
// allowlist: a perfectly-signed JWT from an issuer that is NOT in the
// tenant's policy must be rejected without ever fetching that issuer's JWKS.
func TestAttestationOIDCVerifierRejectsUntrustedIssuer(t *testing.T) {
	trusted := newOIDCIssuer(t)
	untrusted := newOIDCIssuer(t)
	defer trusted.close()
	defer untrusted.close()

	reg := registerAgent(t, uid("attest-oidc-untrusted"))
	upsertOIDCPolicy(t, map[string]any{
		"issuers": []map[string]any{{"url": trusted.URL}},
	})

	token := untrusted.sign(map[string]any{"sub": "attacker"})
	id := submitAttestation(t, reg.AgentID, "oidc_token", token)

	resp := verifyAttestation(t, id)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"JWT from an untrusted issuer must be rejected")
	assertErrorBodyContains(t, resp, "issuer not in allowlist")
}

// TestAttestationOIDCVerifierRejectsTamperedSignature ensures the JWT
// signature is actually checked: flipping a byte in the signature segment
// must cause verification to fail even when the issuer is trusted.
func TestAttestationOIDCVerifierRejectsTamperedSignature(t *testing.T) {
	iss := newOIDCIssuer(t)
	defer iss.close()

	reg := registerAgent(t, uid("attest-oidc-tampered"))
	upsertOIDCPolicy(t, map[string]any{
		"issuers": []map[string]any{{"url": iss.URL}},
	})

	good := iss.sign(map[string]any{"sub": "ci-job-1"})
	// Flip the last signature byte — the token string format is
	// header.payload.signature.
	tampered := good[:len(good)-1] + flipLastByte(good)
	id := submitAttestation(t, reg.AgentID, "oidc_token", tampered)

	resp := verifyAttestation(t, id)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"tampered JWT must fail signature verification")
	// Either "malformed JWT" (base64 decode flagged the corruption) or
	// "token validation failed" (signature check flagged it) is an
	// acceptable rejection reason — both come from the OIDC verifier.
	assertErrorBodyContains(t, resp, "oidc verifier")
}

// TestAttestationOIDCVerifierRejectsExpired ensures the verifier enforces
// the JWT exp claim (exp in the past should reject).
func TestAttestationOIDCVerifierRejectsExpired(t *testing.T) {
	iss := newOIDCIssuer(t)
	defer iss.close()

	reg := registerAgent(t, uid("attest-oidc-expired"))
	upsertOIDCPolicy(t, map[string]any{
		"issuers": []map[string]any{{"url": iss.URL}},
	})

	// Mint a JWT that expired an hour ago by building it manually — we can't
	// easily override exp through the iss.sign helper, so do it inline.
	tok := jwt.New()
	require.NoError(t, tok.Set(jwt.IssuerKey, iss.URL))
	require.NoError(t, tok.Set(jwt.IssuedAtKey, time.Now().Add(-2*time.Hour).Unix()))
	require.NoError(t, tok.Set(jwt.ExpirationKey, time.Now().Add(-1*time.Hour).Unix()))
	require.NoError(t, tok.Set(jwt.SubjectKey, "ci-job-1"))
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, iss.signKey))
	require.NoError(t, err)

	id := submitAttestation(t, reg.AgentID, "oidc_token", string(signed))
	resp := verifyAttestation(t, id)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"expired JWT must be rejected")
	assertErrorBodyContains(t, resp, "token validation failed")
}

// TestAttestationOIDCVerifierRejectsRequiredClaimMismatch verifies that the
// RequiredClaims binder actually runs — a token missing/mismatching a
// configured claim must fail even if signature + issuer + aud all pass.
func TestAttestationOIDCVerifierRejectsRequiredClaimMismatch(t *testing.T) {
	iss := newOIDCIssuer(t)
	defer iss.close()

	reg := registerAgent(t, uid("attest-oidc-claim"))
	upsertOIDCPolicy(t, map[string]any{
		"issuers": []map[string]any{{
			"url":             iss.URL,
			"required_claims": map[string]string{"repository": "myorg/myrepo"},
		}},
	})

	// Claim value is wrong (different repo).
	token := iss.sign(map[string]any{
		"sub":        "ci-job-1",
		"repository": "rogueorg/rogue",
	})
	id := submitAttestation(t, reg.AgentID, "oidc_token", token)

	resp := verifyAttestation(t, id)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"required_claims mismatch must reject the attestation")
	assertErrorBodyContains(t, resp, "required claim")
}

// TestAttestationDoubleVerifyIsRejected enforces the ErrAttestationAlreadyVerified
// guard: once a record has been verified (even once successfully), a second
// /verify on the same record must be rejected so a retry-after-partial-
// failure can't mint a second credential from a single proof.
func TestAttestationDoubleVerifyIsRejected(t *testing.T) {
	iss := newOIDCIssuer(t)
	defer iss.close()

	reg := registerAgent(t, uid("attest-double"))
	upsertOIDCPolicy(t, map[string]any{
		"issuers": []map[string]any{{"url": iss.URL}},
	})

	token := iss.sign(map[string]any{"sub": "ci-job-double"})
	id := submitAttestation(t, reg.AgentID, "oidc_token", token)

	first := verifyAttestation(t, id)
	require.Equal(t, http.StatusOK, first.StatusCode, "first verify expected 200")
	_ = first.Body.Close()

	second := verifyAttestation(t, id)
	defer func() { _ = second.Body.Close() }()
	assert.Equal(t, http.StatusConflict, second.StatusCode,
		"second verify on an already-verified record must be 409 Conflict")
	assertErrorBodyContains(t, second, "already verified")
}

// TestAttestationPolicyUpsertReactivatesDisabled verifies the upsert-against-
// inactive-row bug is fixed: disabling a policy via is_active=false and then
// PUTting a fresh config must update the row in place, not violate the
// unique constraint.
func TestAttestationPolicyUpsertReactivatesDisabled(t *testing.T) {
	iss := newOIDCIssuer(t)
	defer iss.close()

	// First create an active policy.
	upsertOIDCPolicy(t, map[string]any{
		"issuers": []map[string]any{{"url": iss.URL}},
	})

	// Soft-disable it.
	disabled := false
	disableResp := doRequest(t, http.MethodPut, adminPath("/attestation-policies"), map[string]any{
		"proof_type": "oidc_token",
		"config": map[string]any{
			"issuers": []map[string]any{{"url": iss.URL}},
		},
		"is_active": &disabled,
	}, adminHeaders())
	require.Equal(t, http.StatusOK, disableResp.StatusCode)
	_ = disableResp.Body.Close()

	// Now re-enable (or just upsert again). Before the fix this hit the
	// unique constraint because GetByTenantProofType filters is_active.
	enabled := true
	reenable := doRequest(t, http.MethodPut, adminPath("/attestation-policies"), map[string]any{
		"proof_type": "oidc_token",
		"config": map[string]any{
			"issuers": []map[string]any{{"url": iss.URL}},
		},
		"is_active": &enabled,
	}, adminHeaders())
	defer func() { _ = reenable.Body.Close() }()
	assert.Equal(t, http.StatusOK, reenable.StatusCode,
		"upserting an inactive policy must reactivate it, not 500 on unique constraint")
}

// TestAttestationPolicyUpsertIsConcurrencySafe fires N simultaneous PUTs
// for the same (tenant, proof_type) and asserts every one returns 200.
// Under the prior read-then-write implementation two concurrent upserts
// could both see "not found", both try to INSERT, and the loser would
// 500 with a unique-constraint violation. The atomic INSERT ... ON
// CONFLICT path eliminates that race.
func TestAttestationPolicyUpsertIsConcurrencySafe(t *testing.T) {
	iss := newOIDCIssuer(t)
	defer iss.close()

	// Use a tenant that no other test touches so the race is clean.
	tenant := tenantHeaders("acct-upsert-race-"+uid(""), "proj-upsert-race-"+uid(""))

	const parallelism = 8
	results := make(chan int, parallelism)
	body := map[string]any{
		"proof_type": "oidc_token",
		"config": map[string]any{
			"issuers": []map[string]any{{"url": iss.URL}},
		},
	}
	for range parallelism {
		go func() {
			resp := doRequest(t, http.MethodPut, adminPath("/attestation-policies"), body, tenant)
			_ = resp.Body.Close()
			results <- resp.StatusCode
		}()
	}
	for range parallelism {
		status := <-results
		assert.Equal(t, http.StatusOK, status,
			"every concurrent upsert must succeed; atomic INSERT ... ON CONFLICT has no race window")
	}
}

// TestAttestationPolicyRejectsNonHTTPSIssuer exercises the write-time config
// validator: an http://... issuer URL should be rejected before it's stored,
// because OIDC discovery over plaintext lets a network attacker swap JWKS.
func TestAttestationPolicyRejectsNonHTTPSIssuer(t *testing.T) {
	resp := doRequest(t, http.MethodPut, adminPath("/attestation-policies"), map[string]any{
		"proof_type": "oidc_token",
		"config": map[string]any{
			"issuers": []map[string]any{{"url": "http://plaintext.example.com"}},
		},
	}, adminHeaders())
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"non-https issuer URL must be rejected at write time with 400")
	assertErrorBodyContains(t, resp, "https")
}

// TestAttestationOIDCDiscoveryBodyCap guards the 1 MiB body limit on
// OIDC discovery doc fetches: a malicious or compromised issuer that serves
// an arbitrarily large discovery response must not be able to exhaust
// ZeroID's memory during decode. The test stands up a discovery endpoint
// that streams padding beyond the cap, configures it as a trusted issuer,
// and asserts the verify call fails without crashing.
func TestAttestationOIDCDiscoveryBodyCap(t *testing.T) {
	mux := http.NewServeMux()
	var issuerURL string
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Preamble starts a valid JSON object; padding then pushes the
		// response well past the 1 MiB cap. The decoder must fail before
		// finishing the object.
		_, _ = w.Write([]byte(`{"issuer":"` + issuerURL + `","jwks_uri":"` + issuerURL + `/jwks","padding":"`))
		padding := make([]byte, 2*1024*1024) // 2 MiB
		for i := range padding {
			padding[i] = 'A'
		}
		_, _ = w.Write(padding)
		_, _ = w.Write([]byte(`"}`))
	})
	// A trivial jwks handler — we shouldn't reach it because discovery
	// fails, but Huma's Go client still completes the request cleanly.
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()
	issuerURL = srv.URL

	reg := registerAgent(t, uid("attest-oidc-oom"))
	upsertOIDCPolicy(t, map[string]any{
		"issuers": []map[string]any{{"url": issuerURL}},
	})

	// Token's iss claim MUST match the configured issuer — otherwise
	// findIssuer rejects on the allowlist and the verifier never runs
	// discoverJWKSURL, so the test would pass for the wrong reason and
	// silently leave the body cap uncovered. A hand-built unsigned JWT
	// is fine because we want the verifier to fail at discovery, before
	// any signature check.
	//
	// Each JWT segment is base64url. The signature segment must have a
	// length in {4n, 4n+2, 4n+3} — anything else (e.g. the literal
	// string "signature" at length 9 = 4n+1) makes jwx reject the token
	// at parse time with "malformed JWT", which short-circuits before
	// discovery and leaves the body cap unexercised. Use 8-char "A"s.
	b64 := base64.RawURLEncoding
	header := b64.EncodeToString([]byte(`{"alg":"RS256"}`))
	payload := b64.EncodeToString([]byte(`{"iss":"` + issuerURL + `"}`))
	bogusToken := header + "." + payload + ".AAAAAAAA"
	id := submitAttestation(t, reg.AgentID, "oidc_token", bogusToken)

	resp := verifyAttestation(t, id)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"oversized discovery response must be rejected, not OOM the server")
	// Body assertion keeps the test honest: status alone would also
	// pass for "issuer not in allowlist" (a no-op test). Pin to the
	// JWKS-fetch path so a regression on the body cap is visible.
	assertErrorBodyContains(t, resp, "JWKS fetch failed")
}

// registerAgentInTenant is a local helper for the permissive-bypass tests
// below: registerAgent uses adminHeaders, but the bypass tests need
// agents in tenants no other test touches so a missing-policy state
// can be observed without races. Inlines the same call shape with
// caller-supplied tenant headers.
func registerAgentInTenant(t *testing.T, externalID string, tenant map[string]string) agentRegistration {
	t.Helper()
	resp := post(t, adminPath("/agents/register"), map[string]any{
		"name":        externalID,
		"external_id": externalID,
		"sub_type":    "orchestrator",
		"trust_level": "first_party",
		"created_by":  "test-user",
	}, tenant)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "registerAgentInTenant expected 201")
	raw := decode(t, resp)
	agent := raw["identity"].(map[string]any)
	return agentRegistration{
		AgentID: agent["id"].(string),
		APIKey:  raw["api_key"].(string),
	}
}

// TestAttestationPermissiveModeAcceptsMissingPolicy covers the
// transitional bypass that ships with the dev-stub default: when
// allow_unsafe_dev_stub=true, /attestation/verify accepts any submitted
// proof for a registered proof type even when the tenant has no
// AttestationPolicy configured. Existing customers using the legacy
// "any proof verifies" stub keep working without an upgrade-time
// scramble to PUT a policy. A WARN log fires per-request so operators
// can find tenants still using the bypass.
//
// Test flips the flag via Server.SetAttestationPermissive — the harness
// default is false so other tests keep their fail-closed semantics.
func TestAttestationPermissiveModeAcceptsMissingPolicy(t *testing.T) {
	testZeroIDServer.SetAttestationPermissive(true)
	t.Cleanup(func() { testZeroIDServer.SetAttestationPermissive(false) })

	// Use a tenant no other test touches; we deliberately do NOT
	// upsertOIDCPolicy here so the missing-policy branch fires.
	tenant := tenantHeaders("acct-permissive-"+uid(""), "proj-permissive-"+uid(""))
	reg := registerAgentInTenant(t, uid("attest-permissive"), tenant)

	// Token contents are irrelevant — the bypass synthesises a Result
	// without invoking the OIDC verifier. A valid-shape JWT is enough
	// to clear the SubmitAttestation handler's enum check.
	bogusToken := "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FueXRoaW5nIn0.AAAAAAAA"
	subResp := doRequest(t, http.MethodPost, adminPath("/attestation/submit"), map[string]any{
		"identity_id": reg.AgentID,
		"level":       "software",
		"proof_type":  "oidc_token",
		"proof_value": bogusToken,
	}, tenant)
	require.Equal(t, http.StatusCreated, subResp.StatusCode, "submit expected 201")
	id := decode(t, subResp)["id"].(string)

	resp := doRequest(t, http.MethodPost, adminPath("/attestation/verify"), map[string]any{
		"attestation_id": id,
	}, tenant)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode, "permissive mode: missing policy should not reject")

	body := decode(t, resp)
	record := body["record"].(map[string]any)
	assert.Equal(t, true, record["is_verified"], "record marked verified via permissive bypass")
	assert.NotEmpty(t, body["token"], "credential auto-issued via permissive bypass")
}

// TestAttestationPermissiveModeOffStillFailsClosed pairs with the test
// above: when the bypass is OFF (the harness default) and no policy
// exists, /verify must reject. Catches an accidental "always permissive"
// regression in the service-layer switch.
func TestAttestationPermissiveModeOffStillFailsClosed(t *testing.T) {
	// No SetAttestationPermissive(true) — harness default is false.
	tenant := tenantHeaders("acct-strict-"+uid(""), "proj-strict-"+uid(""))
	reg := registerAgentInTenant(t, uid("attest-strict"), tenant)

	bogusToken := "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FueXRoaW5nIn0.AAAAAAAA"
	subResp := doRequest(t, http.MethodPost, adminPath("/attestation/submit"), map[string]any{
		"identity_id": reg.AgentID,
		"level":       "software",
		"proof_type":  "oidc_token",
		"proof_value": bogusToken,
	}, tenant)
	require.Equal(t, http.StatusCreated, subResp.StatusCode)
	id := decode(t, subResp)["id"].(string)

	resp := doRequest(t, http.MethodPost, adminPath("/attestation/verify"), map[string]any{
		"attestation_id": id,
	}, tenant)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "strict mode rejects missing policy")
	assertErrorBodyContains(t, resp, "no attestation policy configured")
}

// flipLastByte returns the last byte of s with a single bit flipped, so
// good[:len(good)-1] + flipLastByte(good) produces a JWT with a corrupted
// signature byte.
func flipLastByte(s string) string {
	b := []byte{s[len(s)-1]}
	b[0] ^= 0x01
	// base64url alphabet: keep it valid-looking so parsing gets past the
	// format check and hits actual signature verification.
	if b[0] == '.' || b[0] == '=' {
		b[0] = 'A'
	}
	return string(b)
}
