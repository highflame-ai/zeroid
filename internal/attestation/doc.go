// Package attestation implements the verifier framework used by the
// /attestation/verify endpoint to promote an identity's trust level.
//
// Two collaborating types live here:
//
//   - Registry maps domain.ProofType to a Verifier implementation.
//     One verifier per proof type. Built at server startup; read-only
//     at request time, so no locking is needed after construction.
//
//   - PolicyService manages per-tenant AttestationPolicy rows and
//     gates write-time creation against the registry: a policy can
//     only exist for a proof type that has a verifier wired in this
//     deployment. The two types are co-located because the policy is
//     read on every Verifier.Verify call.
//
// Verifiers plug in via Registry.Register from server.go. The OIDC
// verifier (oidc.go) is the production implementation. DevStubVerifier
// (stub.go) is an opt-in backstop for proof types whose real verifier
// hasn't shipped yet (image_hash, tpm); it is gated by
// cfg.Attestation.AllowUnsafeDevStub and prints a startup WARN
// whenever it's installed.
//
// The framework is fail-closed: missing verifier, missing tenant
// policy, or a verifier-side rejection all leave the identity
// un-promoted and no credential issued. See docs/attestation.md for
// the full reference, including the OIDC verify flow, the
// AttestationPolicy schema with worked examples, the operator
// runbook, and the steps to add a new verifier.
package attestation
