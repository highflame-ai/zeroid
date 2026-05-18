package integration_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// End-to-end coverage of workload-attested ephemeral signing credentials
// against a real ZeroID + Postgres. These tests deliberately reproduce
// EXACTLY what downstream consumers do:
//
//   - Shield (the signer): generates an ephemeral Ed25519 keypair in
//     memory, attests the PUBLIC half, signs receipts locally with the
//     private half.
//   - Observatory / any auditor (the verifier): fetches the public JWKS
//     by kid and verifies offline — never trusting ZeroID's verdict.
//
// If these pass, AuthZ and Shield can build their signing features on
// this primitive with confidence the full loop works.

const signingWorkload = "highflame-shield"

// attestKey simulates a workload: generate an ephemeral keypair, attest
// the public half, return the kid + the private key kept locally.
func attestKey(t *testing.T, purpose string, ttlSeconds int) (kid string, priv ed25519.PrivateKey) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	headers := map[string]string{
		"X-Account-ID":       testAccountID,
		"X-Project-ID":       testProjectID,
		"X-Internal-Service": signingWorkload, // validated workload identity
	}
	body := map[string]any{
		"public_key":  base64.RawURLEncoding.EncodeToString(pub),
		"algorithm":   "EdDSA",
		"purpose":     purpose,
		"ttl_seconds": ttlSeconds,
	}

	resp := post(t, adminPath("/signing-credentials"), body, headers)
	require.Equal(t, http.StatusOK, resp.StatusCode, "attest should succeed")

	m := decode(t, resp)
	kid, _ = m["kid"].(string)
	require.NotEmpty(t, kid, "attest must return a kid")
	require.NotEmpty(t, m["not_after"], "attest must return not_after")

	return kid, priv
}

// jwksKey fetches the public verification JWKS and returns the raw
// Ed25519 public key for kid, or nil if absent. This is the exact path
// Observatory's resolver takes — public route, no auth.
func jwksKey(t *testing.T, kid string) ed25519.PublicKey {
	t.Helper()

	resp := get(t, "/.well-known/"+testSigningJWKSName, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	doc := decode(t, resp)

	keys, _ := doc["keys"].([]any)
	for _, k := range keys {
		jwk, _ := k.(map[string]any)
		if jwk["kid"] != kid {
			continue
		}

		assert.Equal(t, "OKP", jwk["kty"])
		assert.Equal(t, "Ed25519", jwk["crv"])
		assert.Equal(t, "EdDSA", jwk["alg"])
		assert.Equal(t, "sig", jwk["use"])

		x, _ := jwk["x"].(string)
		raw, err := base64.RawURLEncoding.DecodeString(x)
		require.NoError(t, err)
		require.Len(t, raw, ed25519.PublicKeySize)

		return ed25519.PublicKey(raw)
	}

	return nil
}

// TestSigningCredential_EndToEnd_AttestSignVerify is THE downstream
// proof: a consumer holding the private key produces a signature that
// verifies against the JWKS-published public key resolved by kid.
func TestSigningCredential_EndToEnd_AttestSignVerify(t *testing.T) {
	kid, priv := attestKey(t, "receipt", 3600)

	// Shield-side: sign a canonical receipt locally.
	canonical := []byte(`{"schema":"hf-receipt/1","decision":"deny","kid":"` + kid + `"}`)
	sig := ed25519.Sign(priv, canonical)

	// Verifier-side: resolve the public key from the JWKS by kid, verify
	// offline (no trust in ZeroID's word).
	pub := jwksKey(t, kid)
	require.NotNil(t, pub, "attested kid must appear in the public JWKS")
	require.True(t, ed25519.Verify(pub, canonical, sig),
		"signature from the attested private key must verify against the JWKS public key")

	// Tamper detection: any change to the signed bytes breaks it.
	require.False(t, ed25519.Verify(pub, []byte(`{"decision":"allow"}`), sig),
		"tampered canonical must not verify")
}

// TestSigningCredential_Rotation_Overlap proves that after key rotation
// BOTH kids resolve in the JWKS, so receipts emitted under the old key
// keep verifying (no verification gap across a Shield rotation).
func TestSigningCredential_Rotation_Overlap(t *testing.T) {
	kidA, privA := attestKey(t, "receipt", 3600)
	canonicalA := []byte(`{"turn":1,"kid":"` + kidA + `"}`)
	sigA := ed25519.Sign(privA, canonicalA)

	// Rotate: a fresh ephemeral key is attested (new kid).
	kidB, privB := attestKey(t, "receipt", 3600)
	require.NotEqual(t, kidA, kidB, "rotation must mint a distinct kid")

	// Both verify — old receipts under kidA still resolve during overlap.
	pubA := jwksKey(t, kidA)
	require.NotNil(t, pubA, "old kid must remain in JWKS during overlap")
	require.True(t, ed25519.Verify(pubA, canonicalA, sigA))

	canonicalB := []byte(`{"turn":2,"kid":"` + kidB + `"}`)
	pubB := jwksKey(t, kidB)
	require.NotNil(t, pubB)
	require.True(t, ed25519.Verify(pubB, canonicalB, ed25519.Sign(privB, canonicalB)))
}

// TestSigningCredential_ExpiredButRetained_StillVerifies pins the
// two-clock invariant end-to-end: once not_after passes the key may no
// longer SIGN, but its public key stays in the JWKS (audit retention ≫
// not_after) so a receipt signed before expiry STILL verifies. This is
// the property a not_after-only filter cannot express — and exactly the
// "what if Shield rotated / the pod restarted?" case.
func TestSigningCredential_ExpiredButRetained_StillVerifies(t *testing.T) {
	kid, priv := attestKey(t, "receipt", 1) // 1-second operational window

	canonical := []byte(`{"signed":"before-expiry","kid":"` + kid + `"}`)
	sig := ed25519.Sign(priv, canonical)

	time.Sleep(2 * time.Second) // not_after has now passed (key un-signable)

	pub := jwksKey(t, kid)
	require.NotNil(t, pub,
		"an operationally-expired but non-revoked key must remain verifiable within the audit-retention window")
	require.True(t, ed25519.Verify(pub, canonical, sig),
		"a receipt signed before not_after must still verify after expiry")
}

// TestSigningCredential_Revoke_RemovesFromJWKS proves revocation is
// immediate and overrides retention: a revoked kid drops out of the
// JWKS, so anything signed under it can no longer be verified.
func TestSigningCredential_Revoke_RemovesFromJWKS(t *testing.T) {
	kid, priv := attestKey(t, "receipt", 3600)

	canonical := []byte(`{"x":1,"kid":"` + kid + `"}`)
	sig := ed25519.Sign(priv, canonical)

	require.NotNil(t, jwksKey(t, kid), "kid present before revocation")

	resp := post(t, adminPath("/signing-credentials/"+kid+"/revoke"),
		map[string]any{"reason": "integration test"},
		map[string]string{
			"X-Account-ID":       testAccountID,
			"X-Project-ID":       testProjectID,
			"X-Internal-Service": signingWorkload,
		})
	require.Equal(t, http.StatusOK, resp.StatusCode, "revoke should succeed")

	pub := jwksKey(t, kid)
	require.Nil(t, pub,
		"a revoked kid must NOT appear in the JWKS even within its retention window")
	_ = sig // a verifier can no longer obtain a key for this kid → cannot verify
}

// TestSigningCredential_Attest_Rejections asserts the endpoint defends
// the contract: malformed inputs are rejected before persistence.
func TestSigningCredential_Attest_Rejections(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	goodKey := base64.RawURLEncoding.EncodeToString(pub)

	hdr := map[string]string{
		"X-Account-ID":       testAccountID,
		"X-Project-ID":       testProjectID,
		"X-Internal-Service": signingWorkload,
	}

	cases := []struct {
		name string
		body map[string]any
		hdr  map[string]string
	}{
		{"wrong algorithm", map[string]any{"public_key": goodKey, "algorithm": "RS256", "purpose": "receipt"}, hdr},
		{"disallowed purpose", map[string]any{"public_key": goodKey, "algorithm": "EdDSA", "purpose": "exfiltrate"}, hdr},
		{"malformed key", map[string]any{"public_key": "not-a-key", "algorithm": "EdDSA", "purpose": "receipt"}, hdr},
		{
			"missing workload identity",
			map[string]any{"public_key": goodKey, "algorithm": "EdDSA", "purpose": "receipt"},
			map[string]string{"X-Account-ID": testAccountID, "X-Project-ID": testProjectID},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := post(t, adminPath("/signing-credentials"), tc.body, tc.hdr)
			defer func() { _ = resp.Body.Close() }()
			assert.GreaterOrEqual(t, resp.StatusCode, 400,
				"invalid attestation must be rejected before persistence")
		})
	}
}
