// Package attestation defines the verifier plug-in interface and concrete
// verifiers used by the attestation submission → verification pipeline.
//
// Design: one Verifier per domain.ProofType, discovered through a Registry.
// If a tenant has no AttestationPolicy for a proof type, or no Verifier is
// registered for that type, verification fails closed — the record stays
// unverified, no trust promotion, no credential issuance. This replaces the
// previous stub that accepted any submitted proof.
package attestation

import (
	"context"
	"errors"
	"time"

	"github.com/highflame-ai/zeroid/domain"
)

// ErrNoVerifier is returned when the registry has no Verifier wired for a
// requested ProofType. Callers surface this as a 400 (invalid proof type
// for this deployment) rather than 500.
var ErrNoVerifier = errors.New("no verifier registered for this proof type")

// Result is what a Verifier returns on success. These values are copied onto
// the AttestationRecord so subsequent auditing, introspection, and trust
// decisions can see WHO attested, via WHICH issuer, and WHEN the proof
// expires (for short-lived proofs like OIDC JWTs).
type Result struct {
	// Subject is the verified principal bound to the proof (e.g. the JWT
	// sub claim for oidc_token, the image digest for image_hash).
	Subject string

	// Issuer identifies the authority that produced the proof (e.g. the
	// JWT iss claim). Empty for proof types with no external authority.
	Issuer string

	// ExpiresAt, when non-nil, bounds the attestation's validity. For
	// time-bounded proofs like OIDC JWTs this mirrors the exp claim and
	// propagates to AttestationRecord.ExpiresAt.
	ExpiresAt *time.Time

	// Claims is an optional grab-bag of verified claims (e.g. the full JWT
	// claim set on oidc_token). Kept for audit logging and for future
	// policy matchers that key on structured claims.
	Claims map[string]any
}

// Verifier validates the ProofValue on an AttestationRecord against a
// tenant-scoped policy. Implementations MUST be safe to call concurrently.
//
// policyConfig is the raw JSONB Config from the AttestationPolicy row for
// the caller's tenant + this proof type. Verifiers own the parsing of that
// blob so the registry doesn't need to know each verifier's config shape.
type Verifier interface {
	// ProofType returns the ProofType this verifier handles. One Verifier
	// per ProofType; the registry uses this for lookup.
	ProofType() domain.ProofType

	// Verify returns a Result when the proof is valid under the supplied
	// policy, or an error describing why it was rejected. An error must
	// NOT be swallowed into a zero-value Result — the caller treats any
	// error as "attestation rejected, do not promote trust".
	Verify(ctx context.Context, record *domain.AttestationRecord, policyConfig []byte) (*Result, error)
}

// Registry maps ProofType → Verifier. Built at server startup; read-only at
// request time, so no locking is needed after construction.
type Registry struct {
	verifiers map[domain.ProofType]Verifier
}

// NewRegistry creates an empty registry. Register each Verifier via Register
// before the server begins serving requests.
func NewRegistry() *Registry {
	return &Registry{verifiers: make(map[domain.ProofType]Verifier)}
}

// Register wires a Verifier into the registry. Registering twice for the
// same ProofType overwrites; this is intentional for the dev-stub path
// where the stub fills in wherever no real verifier is wired.
func (r *Registry) Register(v Verifier) {
	r.verifiers[v.ProofType()] = v
}

// Get returns the Verifier for pt, or ErrNoVerifier if none is registered.
func (r *Registry) Get(pt domain.ProofType) (Verifier, error) {
	v, ok := r.verifiers[pt]
	if !ok {
		return nil, ErrNoVerifier
	}
	return v, nil
}

// ProofTypes returns the ProofTypes that have a verifier wired. Order is
// not specified. Used for startup logging so operators can see which
// verifiers are active.
func (r *Registry) ProofTypes() []domain.ProofType {
	out := make([]domain.ProofType, 0, len(r.verifiers))
	for pt := range r.verifiers {
		out = append(out, pt)
	}
	return out
}
