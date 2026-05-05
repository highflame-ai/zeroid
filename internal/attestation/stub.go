package attestation

import (
	"context"
	"time"

	"github.com/highflame-ai/zeroid/domain"
)

// DevStubVerifier accepts any submitted proof without inspecting it.
// Registered ONLY when cfg.Attestation.AllowUnsafeDevStub is set, and
// ONLY for proof types that have no real verifier shipped yet
// (image_hash, tpm). The server emits a WARN-level startup log whenever
// the stub is installed.
//
// Currently the flag defaults to true — until image_hash / tpm real
// verifiers ship, this is the only way demos that submit those proof
// types keep working. Deployments that don't need them (or that have
// landed real verifiers) should set AllowUnsafeDevStub=false. The OIDC
// verifier is unaffected: it's always wired and runs fail-closed.
type DevStubVerifier struct {
	pt domain.ProofType
}

// NewDevStubVerifier returns a stub bound to a specific proof type. One
// stub instance per proof type so Register can place each under its
// expected key.
func NewDevStubVerifier(pt domain.ProofType) *DevStubVerifier {
	return &DevStubVerifier{pt: pt}
}

// ProofType reports which proof type this stub covers.
func (v *DevStubVerifier) ProofType() domain.ProofType { return v.pt }

// Verify unconditionally accepts the proof and returns a Result whose
// Subject is the submitted ProofValue. This matches the legacy demo
// behaviour so existing flows keep working when the unsafe flag is set.
// The 24-hour ExpiresAt gives the dev path a finite lifetime so
// downstream code that bounds trust by ExpiresAt still behaves.
func (v *DevStubVerifier) Verify(_ context.Context, record *domain.AttestationRecord, _ []byte) (*Result, error) {
	expires := time.Now().Add(24 * time.Hour)
	return &Result{
		Subject:   record.ProofValue,
		Issuer:    "dev-stub",
		ExpiresAt: &expires,
	}, nil
}
