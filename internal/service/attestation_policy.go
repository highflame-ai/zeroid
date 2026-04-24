package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/google/uuid"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// ErrInvalidAttestationPolicy is returned for caller-induced validation
// errors on UpsertPolicy (bad proof_type, malformed config, non-https
// issuer URL, etc.). Distinguished from infrastructure errors so the
// handler maps it to 400 rather than 500.
var ErrInvalidAttestationPolicy = errors.New("invalid attestation policy")

// AttestationPolicyService is a thin wrapper around the policy repo. The
// verifier registry holds the concrete verification code; this service
// just manages the per-tenant configuration those verifiers read.
type AttestationPolicyService struct {
	repo *postgres.AttestationPolicyRepository
}

// NewAttestationPolicyService creates a new service.
func NewAttestationPolicyService(repo *postgres.AttestationPolicyRepository) *AttestationPolicyService {
	return &AttestationPolicyService{repo: repo}
}

// UpsertAttestationPolicyRequest captures the payload accepted by the
// admin API. Config is JSONB and its shape depends on ProofType.
type UpsertAttestationPolicyRequest struct {
	AccountID string
	ProjectID string
	ProofType domain.ProofType
	Config    json.RawMessage
	IsActive  *bool
}

// UpsertPolicy creates a policy if none exists for the (tenant, proof_type)
// pair, or updates the existing one in place. Backed by a single atomic
// INSERT ... ON CONFLICT statement so two concurrent admin PUTs for the
// same key can't both see "not found" and race on the unique constraint —
// an earlier read-then-write version did, producing a 500 under concurrent
// writes.
func (s *AttestationPolicyService) UpsertPolicy(ctx context.Context, req UpsertAttestationPolicyRequest) (*domain.AttestationPolicy, error) {
	if !req.ProofType.Valid() {
		return nil, fmt.Errorf("%w: invalid proof_type %q", ErrInvalidAttestationPolicy, req.ProofType)
	}
	if len(req.Config) == 0 {
		return nil, fmt.Errorf("%w: config is required", ErrInvalidAttestationPolicy)
	}
	// Validate the per-proof-type config shape up front so bad configs can't
	// sit in the DB until a /verify call finally trips on them. Catches
	// typos, wrong types, missing issuer URLs, etc. at write time.
	if err := validatePolicyConfig(req.ProofType, req.Config); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidAttestationPolicy, err)
	}

	active := true
	if req.IsActive != nil {
		active = *req.IsActive
	}
	p := &domain.AttestationPolicy{
		ID:        uuid.New().String(),
		AccountID: req.AccountID,
		ProjectID: req.ProjectID,
		ProofType: req.ProofType,
		Config:    req.Config,
		IsActive:  active,
	}
	// Only overwrite is_active on conflict when the caller explicitly set
	// it. Otherwise a PUT that lacks is_active would silently re-enable a
	// previously disabled policy.
	if err := s.repo.Upsert(ctx, p, req.IsActive != nil); err != nil {
		return nil, err
	}
	return p, nil
}

// validatePolicyConfig checks the per-proof-type Config shape at write time.
// Parsing the JSONB into its typed Go struct catches the obvious "this will
// never verify successfully" cases (missing issuer list, non-https issuer
// URL, malformed URL, etc.) before the config reaches the verifier.
func validatePolicyConfig(pt domain.ProofType, cfg json.RawMessage) error {
	switch pt {
	case domain.ProofTypeOIDCToken:
		var oidc domain.OIDCPolicyConfig
		if err := json.Unmarshal(cfg, &oidc); err != nil {
			return fmt.Errorf("invalid oidc_token config: %w", err)
		}
		if len(oidc.Issuers) == 0 {
			return fmt.Errorf("invalid oidc_token config: at least one issuer is required")
		}
		for i, iss := range oidc.Issuers {
			if strings.TrimSpace(iss.URL) == "" {
				return fmt.Errorf("invalid oidc_token config: issuer[%d].url is empty", i)
			}
			u, err := url.Parse(iss.URL)
			if err != nil {
				return fmt.Errorf("invalid oidc_token config: issuer[%d].url is malformed: %w", i, err)
			}
			// OIDC discovery is unauthenticated — if we'd fetch jwks_uri
			// over plain HTTP, a DNS or network attacker could substitute
			// their own keys and forge any workload identity. Require TLS
			// except for loopback addresses, which are safe to serve over
			// HTTP because traffic never leaves the machine — useful for
			// local dev and httptest-based integration tests.
			if u.Scheme != "https" && !isLoopbackHost(u.Host) {
				return fmt.Errorf("invalid oidc_token config: issuer[%d].url must use https (got %q)", i, u.Scheme)
			}
		}
	case domain.ProofTypeImageHash, domain.ProofTypeTPM:
		// No typed config yet — verifiers for these proof types haven't
		// shipped. Accept the raw blob so operators can pre-configure
		// policy rows before the verifier lands.
	default:
		return fmt.Errorf("unsupported proof_type: %s", pt)
	}
	return nil
}

// isLoopbackHost reports whether the host portion of a URL (possibly
// including a port) is a loopback address. Used to carve out a safe-to-
// serve-over-HTTP exception for OIDC discovery in dev/test environments.
func isLoopbackHost(host string) bool {
	// net.SplitHostPort strips brackets from IPv6 hosts and separates the
	// port cleanly. On hosts without a port it returns an error; fall back
	// to the raw host string and strip any brackets that remain.
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}
	h = strings.TrimPrefix(strings.TrimSuffix(h, "]"), "[")
	switch h {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

// GetPolicy returns the policy for the given tenant + proof type, or
// ErrAttestationPolicyNotFound if unset. Used by the verification path.
func (s *AttestationPolicyService) GetPolicy(ctx context.Context, accountID, projectID string, pt domain.ProofType) (*domain.AttestationPolicy, error) {
	return s.repo.GetByTenantProofType(ctx, accountID, projectID, pt)
}

// ListPolicies returns all policies for a tenant.
func (s *AttestationPolicyService) ListPolicies(ctx context.Context, accountID, projectID string) ([]*domain.AttestationPolicy, error) {
	return s.repo.List(ctx, accountID, projectID)
}

// DeletePolicy removes a policy by ID. Policies not belonging to the tenant
// are silently no-op per the repo's idempotent delete semantics.
func (s *AttestationPolicyService) DeletePolicy(ctx context.Context, id, accountID, projectID string) error {
	return s.repo.Delete(ctx, id, accountID, projectID)
}
