package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/middleware"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// ErrIdentityAlreadyExists is returned when (account_id, project_id, external_id) already exists.
var ErrIdentityAlreadyExists = errors.New("identity already exists")

// ErrInvalidIdentityField marks caller-fixable input errors on registration
// (currently the SPIFFE path-segment check). Maps to 400 at the HTTP boundary.
var ErrInvalidIdentityField = errors.New("invalid identity field")

// ErrIdentityNotFound is returned by lookup methods when no identity matches
// the supplied selector within the caller's tenant. Wraps sql.ErrNoRows from
// the store layer so handlers can errors.Is and map to 404 without coupling
// to the database driver.
var ErrIdentityNotFound = errors.New("identity not found")

// IdentityService handles identity lifecycle operations.
type IdentityService struct {
	repo          *postgres.IdentityRepository
	policySvc     *CredentialPolicyService
	apiKeyRepo    *postgres.APIKeyRepository
	credentialSvc *CredentialService
	signalSvc     *SignalService
	wimseDomain   string
}

// NewIdentityService creates a new IdentityService. policySvc must be non-nil —
// every identity is assigned the tenant's default credential policy at
// registration time if the caller does not choose a specific one, so the
// service cannot function without a policy resolver.
//
// apiKeyRepo, credentialSvc, and signalSvc are required because status
// transitions to "deactivated" (and identity deletion) must sweep linked API
// keys, cascade-revoke active credentials, and emit a retirement CAE signal.
// Centralizing that cleanup here ensures every path that deactivates or
// deletes an identity runs the sweep — not just the dedicated agent endpoint.
func NewIdentityService(
	repo *postgres.IdentityRepository,
	policySvc *CredentialPolicyService,
	apiKeyRepo *postgres.APIKeyRepository,
	credentialSvc *CredentialService,
	signalSvc *SignalService,
	wimseDomain string,
) *IdentityService {
	return &IdentityService{
		repo:          repo,
		policySvc:     policySvc,
		apiKeyRepo:    apiKeyRepo,
		credentialSvc: credentialSvc,
		signalSvc:     signalSvc,
		wimseDomain:   wimseDomain,
	}
}

// validateECPublicKeyPEM ensures the provided PEM string is a valid EC P-256 public key.
// Returns nil if keyPEM is empty (the field is optional).
func validateECPublicKeyPEM(keyPEM string) error {
	if keyPEM == "" {
		return nil
	}
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil || block.Type != "PUBLIC KEY" {
		return errors.New("invalid public_key_pem: must be a PEM block of type PUBLIC KEY")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("invalid public_key_pem: %w", err)
	}
	ecKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("invalid public_key_pem: not an ECDSA key")
	}
	if ecKey.Curve.Params().Name != "P-256" {
		return fmt.Errorf("invalid public_key_pem: must use P-256 curve, got %s", ecKey.Curve.Params().Name)
	}
	return nil
}

// RegisterIdentityRequest holds parameters for identity registration.
type RegisterIdentityRequest struct {
	AccountID    string
	ProjectID    string
	ExternalID   string
	Name         string
	TrustLevel   domain.TrustLevel
	IdentityType domain.IdentityType
	SubType      domain.SubType
	// Origin is the provenance discriminator. Empty defaults to `native`. When
	// external (a discovery ecosystem like `okta`), the identity is created in
	// the `discovered` state and OwnerUserID is OPTIONAL — ownerless is the
	// posture signal discovery exists to surface, not a validation error
	// (identity-lifecycle.md "Ownership: relaxed for discovered only").
	Origin domain.Origin
	// SourceID identifies the discovery source instance (connector) for a
	// discovered identity, so a sync can prune only its own rows. Empty for
	// native identities.
	SourceID      string
	OwnerUserID   string
	AllowedScopes []string // Deprecated: set scope ceiling on the identity's credential policy.
	PublicKeyPEM  string
	Framework     string
	Version       string
	Publisher     string
	Description   string
	Capabilities  json.RawMessage
	Labels        json.RawMessage
	Metadata      json.RawMessage
	CreatedBy     string
	// CredentialPolicyID is the identity policy — the authority ceiling for
	// every credential this identity can hold. If empty, the tenant's default
	// policy is assigned. Must exist within the caller's tenant; cross-tenant
	// IDs are rejected with ErrPolicyNotFound.
	CredentialPolicyID string
	// Risk + assurance classification (CoSAI §3.2 / NIST SP 800-63).
	// Empty strings are valid and mean "unclassified."
	CapabilityTier string
	RiskTier       string
	IAL            string
	// ExpiresAt time-bounds the grant of authority. Nil means "no expiry"
	// (historical default). When set, the cleanup worker deactivates the
	// identity past this time and IssueCredential fail-closes on it.
	ExpiresAt *time.Time
}

// RegisterIdentity creates a new identity with a WIMSE URI.
//
// Origin drives two things: a `native` identity is created `active` and MUST
// have an owner; an external-origin (discovered) identity is created in the
// `discovered` state — credential-less, not usable, owner OPTIONAL — until it
// is adopted (identity-lifecycle.md). The discovery service reaches this path
// through UpsertDiscoveredIdentity (idempotent on external_id), not directly.
func (s *IdentityService) RegisterIdentity(ctx context.Context, req RegisterIdentityRequest) (*domain.Identity, error) {
	if req.Origin == "" {
		req.Origin = domain.OriginNative
	}
	if !domain.ValidOrigin(string(req.Origin)) {
		return nil, fmt.Errorf("%w: invalid origin: %q (allowed: a lowercase identifier, e.g. native, okta, entra)", ErrInvalidIdentityField, req.Origin)
	}
	discovered := req.Origin.IsExternal()

	// Ownership is mandatory for native identities and relaxed for discovered
	// (ownerless is the posture signal). It becomes mandatory again at adoption
	// (discovered → pending/active), enforced in UpdateIdentity.
	if !discovered && req.OwnerUserID == "" {
		return nil, fmt.Errorf("owner_user_id is required")
	}

	// A discovered identity is pre-authoritative; a native one is active on
	// registration (the historical default).
	initialStatus := domain.IdentityStatusActive
	if discovered {
		initialStatus = domain.IdentityStatusDiscovered
	}

	if req.TrustLevel == "" {
		req.TrustLevel = domain.TrustLevelUnverified
	}
	if req.IdentityType == "" {
		req.IdentityType = domain.IdentityTypeAgent
	}
	if !req.IdentityType.Valid() {
		return nil, fmt.Errorf("invalid identity_type: %s", req.IdentityType)
	}
	// Anything that lands in the WIMSE URI path needs to be SPIFFE-clean —
	// otherwise we mint URIs strict verifiers reject, and a "/" in any of
	// these fields silently shifts the path layout when parsed back out.
	for _, f := range []struct{ name, value string }{
		{"account_id", req.AccountID},
		{"project_id", req.ProjectID},
		{"external_id", req.ExternalID},
		{"identity_type", string(req.IdentityType)},
	} {
		if err := domain.ValidateSPIFFEPathSegment(f.name, f.value); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidIdentityField, err)
		}
	}
	if req.SubType == "" && req.IdentityType == domain.IdentityTypeAgent {
		req.SubType = domain.SubTypeToolAgent
	}
	if !req.SubType.ValidForIdentityType(req.IdentityType) {
		return nil, fmt.Errorf("invalid sub_type: %s", req.SubType)
	}
	if req.AllowedScopes == nil {
		req.AllowedScopes = []string{}
	}
	if req.Capabilities == nil {
		req.Capabilities = json.RawMessage("[]")
	}
	if req.Labels == nil {
		req.Labels = json.RawMessage("{}")
	}
	if req.Metadata == nil {
		req.Metadata = json.RawMessage("{}")
	}
	if err := validateECPublicKeyPEM(req.PublicKeyPEM); err != nil {
		return nil, err
	}
	if !domain.ValidCapabilityTier(req.CapabilityTier) {
		return nil, fmt.Errorf("%w: invalid capability_tier: %q (allowed: low, high, or empty)", ErrInvalidIdentityField, req.CapabilityTier)
	}
	if !domain.ValidRiskTier(req.RiskTier) {
		return nil, fmt.Errorf("%w: invalid risk_tier: %q (allowed: low, high, or empty)", ErrInvalidIdentityField, req.RiskTier)
	}
	if !domain.ValidIAL(req.IAL) {
		return nil, fmt.Errorf("%w: invalid ial: %q (allowed: ial1, ial2, ial3, or empty)", ErrInvalidIdentityField, req.IAL)
	}

	// Resolve the identity policy: a caller-supplied policy ID must be
	// tenant-scoped (IDOR guard via GetPolicy). When absent, assign the
	// tenant's default policy so every identity has a non-null authority
	// ceiling from the moment it is created.
	policyID, err := s.resolveIdentityPolicyID(ctx, req.AccountID, req.ProjectID, req.CredentialPolicyID)
	if err != nil {
		return nil, err
	}

	wimseURI, err := domain.BuildWIMSEURI(s.wimseDomain, req.AccountID, req.ProjectID, req.IdentityType, req.ExternalID)
	if err != nil {
		return nil, err
	}

	identity := &domain.Identity{
		ID:                 uuid.New().String(),
		AccountID:          req.AccountID,
		ProjectID:          req.ProjectID,
		ExternalID:         req.ExternalID,
		Name:               req.Name,
		WIMSEURI:           wimseURI,
		IdentityType:       req.IdentityType,
		SubType:            req.SubType,
		TrustLevel:         req.TrustLevel,
		Status:             initialStatus,
		Origin:             req.Origin,
		SourceID:           req.SourceID,
		OwnerUserID:        req.OwnerUserID,
		CredentialPolicyID: policyID,
		AllowedScopes:      req.AllowedScopes,
		PublicKeyPEM:       req.PublicKeyPEM,
		Framework:          req.Framework,
		Version:            req.Version,
		Publisher:          req.Publisher,
		Description:        req.Description,
		Capabilities:       req.Capabilities,
		Labels:             req.Labels,
		Metadata:           req.Metadata,
		CapabilityTier:     req.CapabilityTier,
		RiskTier:           req.RiskTier,
		IAL:                req.IAL,
		ExpiresAt:          req.ExpiresAt,
		CreatedBy:          req.CreatedBy,
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}

	if err := s.repo.Create(ctx, identity); err != nil {
		if isDuplicateKeyError(err) {
			// Distinguish a collision with a DEACTIVATED (soft-deleted) identity
			// — which is actionable via reactivation — from a live duplicate.
			// Best-effort: if the lookup fails, fall back to the generic error.
			if existing, gerr := s.repo.GetByExternalID(ctx, req.ExternalID, req.AccountID, req.ProjectID); gerr == nil &&
				existing != nil && existing.Status == domain.IdentityStatusDeactivated {
				return nil, &IdentityDeactivatedConflictError{ExternalID: req.ExternalID, ExistingID: existing.ID}
			}

			return nil, ErrIdentityAlreadyExists
		}
		return nil, fmt.Errorf("failed to register identity: %w", err)
	}

	log.Info().
		Str("identity_id", identity.ID).
		Str("external_id", req.ExternalID).
		Str("identity_type", string(req.IdentityType)).
		Str("sub_type", string(req.SubType)).
		Str("wimse_uri", identity.WIMSEURI).
		Msg("Identity registered")

	return identity, nil
}

// DiscoveredIdentityRequest is the ingestion payload from a discovery connector
// — the descriptive fields enumerated from an external IdP. Owner is OPTIONAL
// (ownerless is the discovery posture signal). Origin MUST be external.
type DiscoveredIdentityRequest struct {
	AccountID    string
	ProjectID    string
	ExternalID   string // the IdP object id — the reconciliation key
	Origin       domain.Origin
	SourceID     string // the discovery source instance (connector) — enables source-scoped pruning
	Name         string
	IdentityType domain.IdentityType
	SubType      domain.SubType
	TrustLevel   domain.TrustLevel
	OwnerUserID  string // optional
	Framework    string
	Version      string
	Publisher    string
	Description  string
	Capabilities json.RawMessage
	Labels       json.RawMessage
	Metadata     json.RawMessage
	CreatedBy    string
}

// UpsertDiscoveredIdentity idempotently ingests an identity observed in an
// external IdP. It is the discovery service's write path into the one identity
// registry (see docs/identity-lifecycle.md, "Reconciliation is structural"):
// keyed on (account_id, project_id, external_id), a re-sync reconciles to the
// SAME row rather than creating a duplicate or 409ing.
//
//   - new external_id              → create in the `discovered` state.
//   - existing (still discovered)  → refresh the connector-sourced descriptive
//     fields; lifecycle untouched.
//   - existing (already adopted or dismissed) → refresh only non-authoritative
//     descriptive fields and NEVER regress status / owner / policy. The agent
//     EMA/ID-JAG reconnects onto this same row; a deliberately dismissed row is
//     not silently resurrected.
//
// Returns the resulting identity and whether it was newly created.
func (s *IdentityService) UpsertDiscoveredIdentity(ctx context.Context, req DiscoveredIdentityRequest) (*domain.Identity, bool, error) {
	if !req.Origin.IsExternal() {
		return nil, false, fmt.Errorf("%w: a discovered identity requires an external origin (got %q)", ErrInvalidIdentityField, req.Origin)
	}
	// Validate shape here too (not only in RegisterIdentity), so a malformed
	// origin is rejected on the reconcile path and in a bulk batch, not just on
	// first create.
	if !domain.ValidOrigin(string(req.Origin)) {
		return nil, false, fmt.Errorf("%w: invalid origin: %q", ErrInvalidIdentityField, req.Origin)
	}

	if existing, err := s.repo.GetByExternalID(ctx, req.ExternalID, req.AccountID, req.ProjectID); err == nil && existing != nil {
		return s.reconcileDiscovered(ctx, existing, req)
	}

	identity, err := s.RegisterIdentity(ctx, RegisterIdentityRequest{
		AccountID:    req.AccountID,
		ProjectID:    req.ProjectID,
		ExternalID:   req.ExternalID,
		Name:         req.Name,
		TrustLevel:   req.TrustLevel,
		IdentityType: req.IdentityType,
		SubType:      req.SubType,
		Origin:       req.Origin,
		SourceID:     req.SourceID,
		OwnerUserID:  req.OwnerUserID,
		Framework:    req.Framework,
		Version:      req.Version,
		Publisher:    req.Publisher,
		Description:  req.Description,
		Capabilities: req.Capabilities,
		Labels:       req.Labels,
		Metadata:     req.Metadata,
		CreatedBy:    req.CreatedBy,
	})
	if err != nil {
		// A concurrent sync may have created the row between our lookup and
		// Create. Fold any "already exists" signal (live duplicate or a
		// soft-deleted/dismissed collision) back into the reconcile path so the
		// upsert stays idempotent under races.
		var deactErr *IdentityDeactivatedConflictError
		if errors.Is(err, ErrIdentityAlreadyExists) || errors.As(err, &deactErr) {
			existing, gerr := s.repo.GetByExternalID(ctx, req.ExternalID, req.AccountID, req.ProjectID)
			// Only a genuine "no row" result lets us fall through to the
			// original conflict error. An operational DB failure (connection
			// loss, timeout) must surface as-is, not be masked as a 409.
			if gerr != nil && !errors.Is(gerr, sql.ErrNoRows) {
				return nil, false, gerr
			}
			if gerr == nil && existing != nil {
				return s.reconcileDiscovered(ctx, existing, req)
			}
		}
		return nil, false, err
	}
	return identity, true, nil
}

// reconcileDiscovered refreshes the connector-sourced descriptive fields on an
// existing row without touching lifecycle, ownership, policy, or origin. Only
// non-empty inputs overwrite, so a connector that omits a field leaves the
// curated value intact. Returns (identity, created=false).
//
// A native-origin row that happens to share this external_id is a genuine
// collision, not the same agent: discovery must never mutate a natively-managed
// identity, so we reject rather than clobber. A row that began as discovered
// keeps its external origin even after adoption/activation (origin is immutable
// provenance), so the EMA/ID-JAG reconnect still lands here.
func (s *IdentityService) reconcileDiscovered(ctx context.Context, identity *domain.Identity, req DiscoveredIdentityRequest) (*domain.Identity, bool, error) {
	if !identity.Origin.IsExternal() {
		return nil, false, fmt.Errorf("%w: external_id %q already belongs to a native identity", ErrIdentityAlreadyExists, identity.ExternalID)
	}
	// Adopt a source_id only when the row doesn't already have one (e.g. it was
	// ingested manually first, then a connector picked it up). Never overwrite a
	// non-empty source_id, so one connector can't claim another's row.
	if identity.SourceID == "" && req.SourceID != "" {
		identity.SourceID = req.SourceID
	}
	if req.Name != "" {
		identity.Name = req.Name
	}
	if req.Description != "" {
		identity.Description = req.Description
	}
	if req.Framework != "" {
		identity.Framework = req.Framework
	}
	if req.Publisher != "" {
		identity.Publisher = req.Publisher
	}
	if req.Version != "" {
		identity.Version = req.Version
	}
	if len(req.Labels) > 0 {
		identity.Labels = req.Labels
	}
	if len(req.Capabilities) > 0 {
		identity.Capabilities = req.Capabilities
	}
	if len(req.Metadata) > 0 {
		identity.Metadata = req.Metadata
	}
	identity.UpdatedAt = time.Now()
	if err := s.repo.Update(ctx, identity); err != nil {
		return nil, false, err
	}
	return identity, false, nil
}

// BulkDiscoveredFailure records one agent that failed to ingest, by external_id.
type BulkDiscoveredFailure struct {
	ExternalID string `json:"external_id"`
	Error      string `json:"error"`
}

// BulkDiscoveredResult summarizes a bulk discovery ingest.
type BulkDiscoveredResult struct {
	Created    int                     `json:"created"`
	Reconciled int                     `json:"reconciled"`
	Failed     []BulkDiscoveredFailure `json:"failed"`
}

// MaxDiscoveredBatchSize caps a single bulk ingest so one request can't be
// unbounded. A connector with more agents pages across multiple batches.
const MaxDiscoveredBatchSize = 1000

// BulkUpsertDiscoveredIdentities ingests many discovered identities in one call
// — the connector-sync write path. Each agent goes through the same idempotent
// UpsertDiscoveredIdentity, so the no-clobber-native guard and create-vs-
// reconcile logic apply per row. It is best-effort: a per-agent failure is
// recorded in the result and does not abort the batch, so a connector ingests
// everything it can and reports the rest.
func (s *IdentityService) BulkUpsertDiscoveredIdentities(ctx context.Context, reqs []DiscoveredIdentityRequest) (*BulkDiscoveredResult, error) {
	if len(reqs) > MaxDiscoveredBatchSize {
		return nil, fmt.Errorf("%w: batch of %d exceeds the maximum of %d", ErrInvalidIdentityField, len(reqs), MaxDiscoveredBatchSize)
	}
	result := &BulkDiscoveredResult{Failed: []BulkDiscoveredFailure{}}
	for _, req := range reqs {
		_, created, err := s.UpsertDiscoveredIdentity(ctx, req)
		if err != nil {
			result.Failed = append(result.Failed, BulkDiscoveredFailure{ExternalID: req.ExternalID, Error: err.Error()})
			continue
		}
		if created {
			result.Created++
		} else {
			result.Reconciled++
		}
	}
	return result, nil
}

// PruneStaleDiscovered deactivates discovered identities a connector sync no
// longer observed — the offboarding half of a reconcile (OWASP NHI1). It targets
// ONLY rows that are:
//   - still in the `discovered` state — an adopted/active agent that vanished
//     from its source is a governance decision for its owner, never an automatic
//     deactivation;
//   - tagged with this (origin, source_id) — so one connector's sweep never
//     touches another connector's agents of the same origin;
//   - last touched before notSeenSince — i.e. not refreshed by this sync's
//     upserts (the connector records notSeenSince at sync start, then upserts,
//     then calls prune).
//
// origin and sourceID are required, so a prune is always scoped to one source
// and can never sweep the whole tenant. Discovered rows hold no credential, so
// this is a plain bulk status flip (no cascade revoke). Returns the count
// deactivated.
func (s *IdentityService) PruneStaleDiscovered(ctx context.Context, accountID, projectID string, origin domain.Origin, sourceID string, notSeenSince time.Time) (int, error) {
	if !origin.IsExternal() {
		return 0, fmt.Errorf("%w: prune requires an external origin (got %q)", ErrInvalidIdentityField, origin)
	}
	if sourceID == "" {
		return 0, fmt.Errorf("%w: prune requires a source_id (a prune is always scoped to one discovery source)", ErrInvalidIdentityField)
	}
	if notSeenSince.IsZero() {
		return 0, fmt.Errorf("%w: prune requires not_seen_since", ErrInvalidIdentityField)
	}
	// not_seen_since is the sync-start time and must be in the past — a connector
	// bug sending a future timestamp would otherwise deactivate every still-
	// discovered row of the source (everything is "older" than the future). Guard
	// it like the expires_at-in-the-future foot-gun (security-review hardening).
	if notSeenSince.After(time.Now()) {
		return 0, fmt.Errorf("%w: not_seen_since must not be in the future (got %s)", ErrInvalidIdentityField, notSeenSince.UTC().Format(time.RFC3339))
	}
	ctx = middleware.SetCallerName(ctx, middleware.SystemCallerPrefix+"discovery_prune")
	n, err := s.repo.DeactivateStaleDiscovered(ctx, accountID, projectID, string(origin), sourceID, notSeenSince)
	if err != nil {
		return 0, fmt.Errorf("prune stale discovered: %w", err)
	}
	if n > 0 {
		log.Info().Int("count", n).Str("origin", string(origin)).Str("source_id", sourceID).
			Msg("discovery prune: deactivated stale discovered identities")
	}
	return n, nil
}

// GetIdentity retrieves an identity by ID.
func (s *IdentityService) GetIdentity(ctx context.Context, id, accountID, projectID string) (*domain.Identity, error) {
	return s.repo.GetByID(ctx, id, accountID, projectID)
}

// SetPublicKey replaces the identity's EC actor-assertion public key (the key
// used to verify its self-signed assertion on the jwt_bearer and token_exchange
// grants). The PEM is validated as an SPKI EC P-256 key. Persisted via
// repo.Update so the AFTER UPDATE audit trigger records the change with the
// caller as modified_by. Authorization — proof-of-possession for a self-service
// rotation, or admin authority for a force-set — is the caller's
// responsibility; this method only validates and persists. Returns the updated
// identity.
func (s *IdentityService) SetPublicKey(ctx context.Context, id, accountID, projectID, publicKeyPEM string) (*domain.Identity, error) {
	if err := validateECPublicKeyPEM(publicKeyPEM); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidIdentityField, err)
	}
	identity, err := s.repo.GetByID(ctx, id, accountID, projectID)
	if err != nil {
		return nil, err
	}
	identity.PublicKeyPEM = publicKeyPEM
	if err := s.repo.Update(ctx, identity); err != nil {
		return nil, err
	}
	return identity, nil
}

// GetIdentityByExternalID retrieves an identity by its external_id within a tenant.
func (s *IdentityService) GetIdentityByExternalID(ctx context.Context, externalID, accountID, projectID string) (*domain.Identity, error) {
	return s.repo.GetByExternalID(ctx, externalID, accountID, projectID)
}

// GetIdentityByWIMSEURI resolves an identity by its WIMSE/SPIFFE URI within a
// tenant. Used by the /identities/by-wimse lookup endpoint that downstream
// gateways (firehog) hit to confirm a JWT's sub claim still resolves to an
// active identity row before forwarding the request.
//
// Tenant isolation is enforced at the store layer: the same URI in a
// different tenant returns ErrIdentityNotFound, not the other tenant's row.
// A sql.ErrNoRows from the store is normalised to ErrIdentityNotFound so the
// handler stays decoupled from the database driver.
func (s *IdentityService) GetIdentityByWIMSEURI(ctx context.Context, wimseURI, accountID, projectID string) (*domain.Identity, error) {
	identity, err := s.repo.GetByWIMSEURI(ctx, wimseURI, accountID, projectID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrIdentityNotFound
		}
		return nil, err
	}
	return identity, nil
}

// ListIdentities returns identities for a tenant, optionally filtered by
// identity_type(s), label, metadata (key presence or key:value), origin
// (provenance, e.g. okta — or the sentinel "external" for any non-native), and
// status (e.g. discovered). origin + status are the discovery-inventory filters:
// status=discovered surfaces the adoption inbox, origin=<idp> drills into one
// ecosystem.
func (s *IdentityService) ListIdentities(ctx context.Context, accountID, projectID string, identityTypes []string, label, trustLevel, isActive, search, metadata, identityClass, origin, status string, limit, offset int) ([]*domain.Identity, int, error) {
	return s.repo.List(ctx, accountID, projectID, identityTypes, label, trustLevel, isActive, search, metadata, identityClass, origin, status, limit, offset)
}

// GetFacets returns grouped counts for each filterable identity dimension.
func (s *IdentityService) GetFacets(ctx context.Context, accountID, projectID string) (*postgres.IdentityFacets, error) {
	return s.repo.GetFacets(ctx, accountID, projectID)
}

// ListExpiringSoon returns active identities whose expires_at falls within
// now..now+within. Used by GET /expiring-soon.
func (s *IdentityService) ListExpiringSoon(ctx context.Context, accountID, projectID string, now time.Time, within time.Duration) ([]*domain.Identity, error) {
	return s.repo.ListExpiringSoon(ctx, accountID, projectID, now, within)
}

// UpdateIdentityRequest holds parameters for identity updates.
// Zero-value fields are left unchanged. Pointer fields distinguish "not set" from "clear."
type UpdateIdentityRequest struct {
	Name          string
	TrustLevel    domain.TrustLevel
	IdentityType  domain.IdentityType
	SubType       domain.SubType
	OwnerUserID   string
	AllowedScopes []string
	PublicKeyPEM  string
	Framework     *string
	Version       *string
	Publisher     *string
	Description   *string
	Capabilities  json.RawMessage
	Labels        json.RawMessage
	Metadata      json.RawMessage
	Status        *domain.IdentityStatus
	// CredentialPolicyID changes the identity policy — the authority ceiling
	// for this identity. Pointer so callers can distinguish "not set" from
	// "clear to tenant default". A non-empty value must exist in the caller's
	// tenant; an empty string reassigns the tenant default.
	CredentialPolicyID *string
	// Risk + assurance classification (CoSAI §3.2 / NIST SP 800-63). Pointer
	// so callers can distinguish "not set" from "clear to unclassified" via
	// an explicit empty-string assignment.
	CapabilityTier *string
	RiskTier       *string
	IAL            *string
	// ExpiresAt uses RFC3339 string + tri-state pointer to carry the three
	// update intents that a single *time.Time can't express:
	//   nil pointer            → leave unchanged
	//   pointer to ""          → clear to NULL (remove expiry, extend forever)
	//   pointer to RFC3339 str → set new expiry
	ExpiresAt *string
}

// UpdateIdentity updates mutable fields of an existing identity.
func (s *IdentityService) UpdateIdentity(ctx context.Context, id, accountID, projectID string, req UpdateIdentityRequest) (*domain.Identity, error) {
	identity, err := s.repo.GetByID(ctx, id, accountID, projectID)
	if err != nil {
		return nil, err
	}
	if req.Name != "" {
		identity.Name = req.Name
	}
	if req.TrustLevel != "" {
		identity.TrustLevel = req.TrustLevel
	}
	if req.IdentityType != "" {
		if !req.IdentityType.Valid() {
			return nil, fmt.Errorf("invalid identity_type: %s", req.IdentityType)
		}
		identity.IdentityType = req.IdentityType
	}
	if req.SubType != "" {
		if !req.SubType.ValidForIdentityType(identity.IdentityType) {
			return nil, fmt.Errorf("invalid sub_type: %s", req.SubType)
		}
		identity.SubType = req.SubType
	}
	if req.OwnerUserID != "" {
		identity.OwnerUserID = req.OwnerUserID
	}
	if req.AllowedScopes != nil {
		identity.AllowedScopes = req.AllowedScopes
	}
	if req.PublicKeyPEM != "" {
		if err := validateECPublicKeyPEM(req.PublicKeyPEM); err != nil {
			return nil, err
		}
		identity.PublicKeyPEM = req.PublicKeyPEM
	}
	if req.Framework != nil {
		identity.Framework = *req.Framework
	}
	if req.Version != nil {
		identity.Version = *req.Version
	}
	if req.Publisher != nil {
		identity.Publisher = *req.Publisher
	}
	if req.Description != nil {
		identity.Description = *req.Description
	}
	if req.Capabilities != nil {
		identity.Capabilities = req.Capabilities
	}
	if req.Labels != nil {
		identity.Labels = req.Labels
	}
	if req.Metadata != nil {
		identity.Metadata = req.Metadata
	}
	// Capture prior status so we can tell whether the update is a fresh
	// transition into deactivated (in which case cleanup must run).
	priorStatus := identity.Status
	// A status PATCH that names the current status is a no-op, not a transition:
	// CanTransitionTo is pure topology and rejects self-transitions, so without
	// this guard an idempotent retry (e.g. re-adopting an already-pending
	// identity) would fail with "invalid status transition". Skip the transition
	// and owner-at-adopt checks when the target equals the current status.
	if req.Status != nil && *req.Status != identity.Status {
		if !identity.Status.CanTransitionTo(*req.Status) {
			return nil, fmt.Errorf("invalid status transition: %s → %s", identity.Status, *req.Status)
		}
		// Adopting (discovered → pending) or directly activating
		// (discovered → active) makes a human accountable for the identity —
		// the platform NHI ownership invariant, relaxed only while discovered,
		// becomes mandatory at this transition (identity-lifecycle.md). The
		// owner may be supplied in this same request (applied above), so we
		// check the resolved value, not the request field.
		if priorStatus == domain.IdentityStatusDiscovered &&
			(*req.Status == domain.IdentityStatusPending || *req.Status == domain.IdentityStatusActive) &&
			identity.OwnerUserID == "" {
			return nil, fmt.Errorf("%w: adopting a discovered identity requires an owner_user_id", ErrInvalidIdentityField)
		}
		identity.Status = *req.Status
	}
	if req.CredentialPolicyID != nil {
		policyID, err := s.resolveIdentityPolicyID(ctx, identity.AccountID, identity.ProjectID, *req.CredentialPolicyID)
		if err != nil {
			return nil, err
		}
		identity.CredentialPolicyID = policyID
	}
	if req.CapabilityTier != nil {
		if !domain.ValidCapabilityTier(*req.CapabilityTier) {
			return nil, fmt.Errorf("%w: invalid capability_tier: %q (allowed: low, high, or empty)", ErrInvalidIdentityField, *req.CapabilityTier)
		}
		identity.CapabilityTier = *req.CapabilityTier
	}
	if req.RiskTier != nil {
		if !domain.ValidRiskTier(*req.RiskTier) {
			return nil, fmt.Errorf("%w: invalid risk_tier: %q (allowed: low, high, or empty)", ErrInvalidIdentityField, *req.RiskTier)
		}
		identity.RiskTier = *req.RiskTier
	}
	if req.IAL != nil {
		if !domain.ValidIAL(*req.IAL) {
			return nil, fmt.Errorf("%w: invalid ial: %q (allowed: ial1, ial2, ial3, or empty)", ErrInvalidIdentityField, *req.IAL)
		}
		identity.IAL = *req.IAL
	}
	if req.ExpiresAt != nil {
		t, cleared, err := parseExpiresAtPatch(*req.ExpiresAt)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidIdentityField, err)
		}
		if cleared {
			identity.ExpiresAt = nil
		} else {
			identity.ExpiresAt = &t
		}
	}
	identity.UpdatedAt = time.Now()
	if err := s.repo.Update(ctx, identity); err != nil {
		return nil, err
	}

	// Fresh transition into deactivated or expired: sweep linked API keys,
	// cascade-revoke active credentials, and emit a retirement/expiry signal.
	// Centralized here so every update path (PUT /identities/{id},
	// AgentService.DeactivateAgent, or any programmatic caller) runs the same
	// cleanup.
	if priorStatus != domain.IdentityStatusDeactivated &&
		identity.Status == domain.IdentityStatusDeactivated {
		s.runDeactivationCleanup(ctx, identity, "identity_deactivated")
	}
	if priorStatus != domain.IdentityStatusExpired &&
		identity.Status == domain.IdentityStatusExpired {
		s.runDeactivationCleanup(ctx, identity, "expired")
	}
	return identity, nil
}

// EnsureServiceIdentity returns the service identity for a given external ID within a tenant,
// creating it if it doesn't exist. Used to guarantee every API key has an identity.
func (s *IdentityService) EnsureServiceIdentity(ctx context.Context, accountID, projectID, externalID, createdBy string) (*domain.Identity, error) {
	existing, err := s.repo.GetByExternalID(ctx, externalID, accountID, projectID)
	if err == nil && existing != nil {
		return existing, nil
	}

	identity, err := s.RegisterIdentity(ctx, RegisterIdentityRequest{
		AccountID:    accountID,
		ProjectID:    projectID,
		ExternalID:   externalID,
		Name:         externalID,
		IdentityType: domain.IdentityTypeService,
		OwnerUserID:  createdBy,
	})
	if err != nil {
		// Race condition — another request created it concurrently.
		if errors.Is(err, ErrIdentityAlreadyExists) {
			existing, err = s.repo.GetByExternalID(ctx, externalID, accountID, projectID)
			if err == nil && existing != nil {
				return existing, nil
			}
		}
		return nil, fmt.Errorf("failed to ensure service identity for %s: %w", externalID, err)
	}

	log.Info().
		Str("identity_id", identity.ID).
		Str("external_id", externalID).
		Str("account_id", accountID).
		Str("project_id", projectID).
		Msg("Service identity auto-created")

	return identity, nil
}

// parseExpiresAtPatch decodes a tri-state expires_at PATCH value:
//   - "" → cleared = true, caller should NULL the column
//   - RFC3339 timestamp strictly after now → returns the parsed time
//   - RFC3339 at or before now → rejected: an admin who fat-fingers a
//     backdated value would otherwise trigger an immediate sweep-cascade
//     revocation of every credential issued to the affected identity /
//     policy. Hard foot-gun; we require expires_at > now (strict) at
//     the PATCH boundary.
//
// Returns: (time, cleared, err). When cleared is true the time value is
// zero and the caller assigns nil.
func parseExpiresAtPatch(raw string) (time.Time, bool, error) {
	if raw == "" {
		return time.Time{}, true, nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("invalid expires_at %q (must be RFC3339)", raw)
	}
	now := time.Now().UTC()
	if !t.After(now) {
		return time.Time{}, false, fmt.Errorf("expires_at must be in the future (got %s, now %s)", t.Format(time.RFC3339), now.Format(time.RFC3339))
	}
	return t, false, nil
}

// SweepExpiredIdentities is called by the cleanup worker. The atomic
// DeactivateIfActive UPDATE is the per-row claim that prevents concurrent
// replicas from running the cascade twice for the same identity. The
// caller_name stamp gives the audit trigger a non-empty modified_by so
// auto-expiries are distinguishable from admin actions on the audit_log.
func (s *IdentityService) SweepExpiredIdentities(ctx context.Context) (int, error) {
	expired, err := s.repo.ListExpiredActive(ctx, time.Now())
	if err != nil {
		return 0, fmt.Errorf("list expired identities: %w", err)
	}
	ctx = middleware.SetCallerName(ctx, middleware.SystemCallerPrefix+"expired_sweep")
	count := 0
	for _, row := range expired {
		claimed, identity, err := s.repo.DeactivateIfActive(ctx, row.ID, row.AccountID, row.ProjectID)
		if err != nil {
			log.Warn().Err(err).
				Str("identity_id", row.ID).
				Str("account_id", row.AccountID).
				Str("project_id", row.ProjectID).
				Msg("sweep: failed to deactivate expired identity")
			continue
		}
		if !claimed {
			continue
		}
		s.runDeactivationCleanup(ctx, identity, "expired")
		count++
	}
	if count > 0 {
		log.Info().Int("count", count).Msg("sweep: deactivated expired identities")
	}
	return count, nil
}

// PurgeIdentity permanently removes an identity row (hard delete) and cascades
// to related records. It is reserved for the compensating rollback of a
// half-created identity (see AgentService.RegisterAgent).
//
// User-facing deletes must NOT call this: DELETE /identities/{id} and
// DELETE /agents/registry/{id} are SOFT deletes (DeactivateIdentity /
// DeactivateAgent) per the platform "never hard DELETE" convention, which also
// preserves the audit trail. A hard delete additionally trips the
// non-cascading service_keys FK on existing deployments (authn#109); that is
// safe in the rollback path only because it runs before any service key is
// persisted (CreateKey writes its row last).
//
// Cleanup runs before the DB delete: API keys are revoked, active credentials
// are cascade-revoked, and a retirement CAE signal is emitted. This ensures
// tokens issued to the identity stop working at the same moment the identity
// is removed, not just whenever they happen to TTL-expire (which can be up to
// 90 days for api_key tokens).
func (s *IdentityService) PurgeIdentity(ctx context.Context, id, accountID, projectID string) error {
	identity, err := s.repo.GetByID(ctx, id, accountID, projectID)
	if err != nil {
		// Fall through to Delete so callers get the same not-found semantics.
		return s.repo.Delete(ctx, id, accountID, projectID)
	}
	s.runDeactivationCleanup(ctx, identity, "identity_deleted")
	return s.repo.Delete(ctx, id, accountID, projectID)
}

// DeactivateIdentity is the soft delete: it flips the identity to the
// deactivated status via the shared UpdateIdentity path, which sweeps linked
// API keys, cascade-revokes active credentials, and emits the retirement CAE
// signal on a fresh transition. This is what DELETE /identities/{id} and
// DELETE /agents/registry/{id} resolve to — the identity row is RETAINED
// (preserving the audit trail) and no hard DELETE is issued, so the
// non-cascading service_keys FK (authn#109) is never touched.
//
// Idempotent: an already-deactivated identity is a no-op success. Without this
// short-circuit a repeated DELETE would hit UpdateIdentity's status-transition
// guard (deactivated → deactivated is rejected) and surface a spurious 400,
// breaking the idempotency callers expect of DELETE. A missing identity
// returns the repo's not-found error so the handler can map it to 404.
// Returns the resulting identity so callers that need to render a response
// (e.g. AgentService.DeleteAgent) can reuse it instead of issuing a second
// load.
func (s *IdentityService) DeactivateIdentity(ctx context.Context, id, accountID, projectID string) (*domain.Identity, error) {
	identity, err := s.repo.GetByID(ctx, id, accountID, projectID)
	if err != nil {
		return nil, err
	}

	if identity.Status == domain.IdentityStatusDeactivated {
		return identity, nil
	}

	status := domain.IdentityStatusDeactivated

	updated, err := s.UpdateIdentity(ctx, id, accountID, projectID, UpdateIdentityRequest{Status: &status})
	if err != nil {
		return nil, err
	}

	return updated, nil
}

// ExpireIdentity transitions an active identity to expired. It runs the same
// cleanup cascade as deactivation (revoke keys, credentials, emit CAE signal).
func (s *IdentityService) ExpireIdentity(ctx context.Context, id, accountID, projectID string) (*domain.Identity, error) {
	identity, err := s.repo.GetByID(ctx, id, accountID, projectID)
	if err != nil {
		return nil, err
	}

	if identity.Status == domain.IdentityStatusExpired {
		return identity, nil
	}

	status := domain.IdentityStatusExpired

	updated, err := s.UpdateIdentity(ctx, id, accountID, projectID, UpdateIdentityRequest{Status: &status})
	if err != nil {
		return nil, err
	}

	return updated, nil
}

// AdoptIdentity adopts a discovered identity (discovered → pending): it assigns
// the accountable human owner (CSA "Ownership Assignment" / ISO "Enrolment")
// and, optionally, a credential policy, moving the identity out of the
// pre-authoritative `discovered` state into the governed-but-not-yet-granted
// `pending` state. Owner is mandatory — adoption IS the act of making an
// external agent accountable (identity-lifecycle.md). The identity stays
// non-usable (IsUsable is false for pending) until a subsequent activation.
// Reuses UpdateIdentity so the transition guard, the owner-at-adopt check, and
// the audit trail all apply.
func (s *IdentityService) AdoptIdentity(ctx context.Context, id, accountID, projectID, ownerUserID, credentialPolicyID string) (*domain.Identity, error) {
	if ownerUserID == "" {
		return nil, fmt.Errorf("%w: adopting a discovered identity requires an owner_user_id", ErrInvalidIdentityField)
	}
	status := domain.IdentityStatusPending
	req := UpdateIdentityRequest{OwnerUserID: ownerUserID, Status: &status}
	if credentialPolicyID != "" {
		req.CredentialPolicyID = &credentialPolicyID
	}
	return s.UpdateIdentity(ctx, id, accountID, projectID, req)
}

// DismissIdentity dismisses a discovered identity (discovered → deactivated):
// an operator marks an externally-observed agent out of scope. The row is
// archived (audit-retained, never hard-deleted) per the offboarding obligation.
// A discovered identity holds no credential, so the shared deactivation cleanup
// finds nothing to revoke and only emits the lifecycle CAE signal.
//
// Idempotent: an already-dismissed (deactivated) identity is a no-op success.
// Only a discovered identity can be dismissed; deactivating a live identity is
// DeactivateIdentity's job, not this one.
func (s *IdentityService) DismissIdentity(ctx context.Context, id, accountID, projectID string) (*domain.Identity, error) {
	identity, err := s.repo.GetByID(ctx, id, accountID, projectID)
	if err != nil {
		return nil, err
	}
	if identity.Status == domain.IdentityStatusDeactivated {
		return identity, nil
	}
	if identity.Status != domain.IdentityStatusDiscovered {
		return nil, fmt.Errorf("%w: only a discovered identity can be dismissed (status=%s); use delete to deactivate a live identity", ErrInvalidIdentityField, identity.Status)
	}
	status := domain.IdentityStatusDeactivated
	return s.UpdateIdentity(ctx, id, accountID, projectID, UpdateIdentityRequest{Status: &status})
}

// runDeactivationCleanup sweeps everything a deactivated or deleted identity
// should no longer be able to use. Each step is best-effort — failures are
// logged but do not block the surrounding operation, because the
// authoritative outcome (status flip or row delete) has already happened and
// the IssueCredential gate ensures no new tokens will be minted regardless.
//
// The reason string is carried through the revocation audit trail and the
// CAE signal payload so subscribers can distinguish "deactivated" from
// "deleted" cleanups.
func (s *IdentityService) runDeactivationCleanup(ctx context.Context, identity *domain.Identity, reason string) {
	if err := s.apiKeyRepo.RevokeByIdentityID(ctx, identity.ID); err != nil {
		log.Warn().Err(err).Str("identity_id", identity.ID).Str("reason", reason).
			Msg("identity cleanup: failed to revoke linked API keys")
	}

	if n, err := s.credentialSvc.RevokeAllActiveForIdentity(ctx, identity.ID, reason); err != nil {
		log.Warn().Err(err).Str("identity_id", identity.ID).Str("reason", reason).
			Msg("identity cleanup: failed to revoke active credentials")
	} else if n > 0 {
		log.Info().Str("identity_id", identity.ID).Str("reason", reason).Int64("count", n).
			Msg("identity cleanup: revoked active credentials (cascade)")
	}

	// Auto-expiry gets its own signal type so CAE subscribers can filter
	// the indexed signal_type column directly (e.g. for offboarding-driven
	// audit reports). Admin-initiated deactivation / deletion stays on
	// SignalTypeRetirement so existing subscribers don't need to know
	// about the split.
	signalType := domain.SignalTypeRetirement
	if reason == "expired" {
		signalType = domain.SignalTypeIdentityExpired
	}
	if _, err := s.signalSvc.IngestSignal(
		ctx,
		identity.AccountID,
		identity.ProjectID,
		identity.ID,
		signalType,
		domain.SignalSeverityHigh,
		"identity_lifecycle",
		map[string]any{"reason": reason},
	); err != nil {
		log.Warn().Err(err).Str("identity_id", identity.ID).Str("reason", reason).
			Str("signal_type", string(signalType)).
			Msg("identity cleanup: failed to emit lifecycle CAE signal")
	}
}

// resolveIdentityPolicyID picks the policy to attach to an identity. When the
// caller supplies an explicit ID, it is validated against the tenant (IDOR
// guard via GetPolicy). When empty, the tenant's default policy is ensured
// and its ID is returned. Never returns an empty string on success.
func (s *IdentityService) resolveIdentityPolicyID(ctx context.Context, accountID, projectID, suppliedID string) (string, error) {
	if s.policySvc == nil {
		return "", fmt.Errorf("identity service is missing credential policy dependency")
	}
	if suppliedID == "" {
		p, err := s.policySvc.EnsureDefaultPolicy(ctx, accountID, projectID)
		if err != nil {
			return "", fmt.Errorf("failed to ensure default credential policy: %w", err)
		}
		return p.ID, nil
	}
	if _, err := s.policySvc.GetPolicy(ctx, suppliedID, accountID, projectID); err != nil {
		return "", fmt.Errorf("credential policy %s: %w", suppliedID, err)
	}
	return suppliedID, nil
}

// ResolveCredentialPolicy returns the credential policy that governs this
// identity. Callers use it as the authority ceiling for scope, TTL, grant
// type, delegation depth, trust level, and attestation checks.
//
// Dual-read: if the identity has a CredentialPolicyID the policy is
// returned directly. Legacy identities written before migration 008 may
// still have a NULL column; we lazily fall back to the tenant default in
// that case so the OAuth flows never observe a policy-less identity.
func (s *IdentityService) ResolveCredentialPolicy(ctx context.Context, identity *domain.Identity) (*domain.CredentialPolicy, error) {
	if s.policySvc == nil {
		return nil, fmt.Errorf("identity service is missing credential policy dependency")
	}
	if identity == nil {
		return nil, fmt.Errorf("nil identity")
	}
	if identity.CredentialPolicyID != "" {
		return s.policySvc.GetPolicy(ctx, identity.CredentialPolicyID, identity.AccountID, identity.ProjectID)
	}
	return s.policySvc.EnsureDefaultPolicy(ctx, identity.AccountID, identity.ProjectID)
}
