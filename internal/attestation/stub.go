package attestation

import (
	"context"
	"time"

	"github.com/highflame-ai/zeroid/domain"
)

// DevStubVerifier accepts any submitted proof without inspecting it.
// Registered ONLY when cfg.Attestation.AllowUnsafeDevStub is set, and
// ONLY for proof types that do not already have a real verifier wired
// (the registry overwrites on double-Register, but the server wires the
// stub last per-type so it fills gaps rather than replacing real
// verifiers).
//
// The server emits a WARN-level startup log whenever this verifier is
// installed. Do not use in production — it exists only to preserve
// legacy demo flows during the transition from the old "mark verified
// unconditionally" code path.
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
