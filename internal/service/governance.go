package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/signing"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// GovernanceService binds the Decision-Rights Matrix and Constraint
// Catalog (issue #59) to token issuance. The service is intentionally
// a no-op when no DRM/catalog rows exist for a tenant — direct-OIDC
// federation, plain client_credentials, and every existing flow keep
// working unchanged for tenants that never opt in to governance binding.
type GovernanceService struct {
	drmRepo     *postgres.DRMRepository
	catalogRepo *postgres.ConstraintCatalogRepository
	credRepo    *postgres.CredentialRepository
	signalSvc   *SignalService
	jwksSvc     *signing.JWKSService

	// svcCtx is the long-lived context used by detached policy_drift
	// fan-out goroutines. Parented on context.Background() at
	// construction; Server.Shutdown calls Stop() to cancel in-flight
	// drift fan-outs so they don't outlive the listener close.
	mu        sync.Mutex
	svcCtx    context.Context
	svcCancel context.CancelFunc
	// driftPageSize bounds memory for a single fan-out by paginating
	// the affected-identity scan. Configurable mainly so tests can
	// exercise the multi-page path.
	driftPageSize int
}

func NewGovernanceService(
	drmRepo *postgres.DRMRepository,
	catalogRepo *postgres.ConstraintCatalogRepository,
	credRepo *postgres.CredentialRepository,
	signalSvc *SignalService,
	jwksSvc *signing.JWKSService,
) *GovernanceService {
	svcCtx, svcCancel := context.WithCancel(context.Background())
	return &GovernanceService{
		drmRepo:       drmRepo,
		catalogRepo:   catalogRepo,
		credRepo:      credRepo,
		signalSvc:     signalSvc,
		jwksSvc:       jwksSvc,
		svcCtx:        svcCtx,
		svcCancel:     svcCancel,
		driftPageSize: 500,
	}
}

// Stop cancels the service lifecycle context so detached drift fan-out
// goroutines wind down. Idempotent. Server.Shutdown calls this so a
// large drift fan-out doesn't keep work running past listener close.
func (g *GovernanceService) Stop() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.svcCancel != nil {
		g.svcCancel()
		g.svcCancel = nil
	}
}

// HashSHA256 returns "sha256:<lowercase-hex>" of the canonical JSON
// encoding of v. Canonical encoding sorts object keys recursively so the
// same logical document always produces the same hash regardless of
// writer-side key order.
func HashSHA256(v any) (string, error) {
	bytes, err := canonicalJSON(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(bytes)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// canonicalJSON returns a deterministic JSON encoding of v: keys are
// sorted lexicographically at every level. We achieve this by first
// marshaling v (collapsing structs/typed maps), then unmarshaling into
// `any` so every object becomes `map[string]any`, then re-marshaling —
// encoding/json's Marshal sorts string-keyed map keys, so the second
// pass produces canonical output without a hand-rolled encoder.
func canonicalJSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil, err
	}
	return json.Marshal(generic)
}

// PublishDRM validates, hashes, and inserts a new DRM. If a prior active
// DRM existed and the new hash differs, a policy_drift signal is emitted
// for every identity with an outstanding (non-revoked) credential bound
// to the old hash.
func (g *GovernanceService) PublishDRM(ctx context.Context, accountID, projectID string, doc domain.DRMDocument) (*domain.DecisionRightsMatrix, error) {
	if err := doc.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", domain.ErrDRMInvalid, err)
	}
	hash, err := HashSHA256(doc)
	if err != nil {
		return nil, err
	}

	// Look up the previously active DRM for drift detection. A lookup
	// failure here is non-fatal — the new DRM still gets written and
	// the only consequence is missed policy_drift signals for tokens
	// minted under the old hash. Log so this doesn't go silent.
	previous, prevErr := g.drmRepo.GetActive(ctx, accountID, projectID)
	if prevErr != nil {
		log.Warn().Err(prevErr).Msg("PublishDRM: failed to look up previous active DRM for drift detection")
	}

	row := &domain.DecisionRightsMatrix{
		ID:          uuid.New().String(),
		AccountID:   accountID,
		ProjectID:   projectID,
		Version:     doc.Version,
		EffectiveAt: doc.EffectiveAt,
		ExpiresAt:   doc.ExpiresAt,
		Document:    doc,
		Hash:        hash,
	}
	if err := g.drmRepo.Create(ctx, row); err != nil {
		return nil, err
	}

	if previous != nil && previous.Hash != hash {
		g.emitDriftSignals(ctx, accountID, projectID, "drm", previous.Hash, hash)
	}
	return row, nil
}

// GetActiveDRM returns the active DRM row for a tenant, or (nil, nil) if
// no DRM is configured.
func (g *GovernanceService) GetActiveDRM(ctx context.Context, accountID, projectID string) (*domain.DecisionRightsMatrix, error) {
	return g.drmRepo.GetActive(ctx, accountID, projectID)
}

// ListDRM returns every DRM row for a tenant in descending-effective order.
func (g *GovernanceService) ListDRM(ctx context.Context, accountID, projectID string) ([]*domain.DecisionRightsMatrix, error) {
	return g.drmRepo.List(ctx, accountID, projectID)
}

// AuthorizeDelegation returns nil when the from→to delegation is permitted
// by the active DRM, ErrDRMUnauthorized when it isn't, or nil when no DRM
// is configured (backward compat).
func (g *GovernanceService) AuthorizeDelegation(ctx context.Context, accountID, projectID, fromURI, toURI string) (*domain.DecisionRightsMatrix, error) {
	drm, err := g.drmRepo.GetActive(ctx, accountID, projectID)
	if err != nil {
		return nil, err
	}
	if drm == nil {
		return nil, nil
	}
	for _, rule := range drm.Document.AllowedDelegations {
		if matchSPIFFE(rule.From, fromURI) && matchSPIFFE(rule.To, toURI) {
			return drm, nil
		}
	}
	return drm, fmt.Errorf("%w: %s → %s under DRM %s", domain.ErrDRMUnauthorized, fromURI, toURI, drm.Version)
}

// matchSPIFFE implements the minimal SPIFFE pattern semantics ZeroID
// needs: exact match, or a single trailing `*` glob that matches any
// suffix on the path component. We deliberately avoid a full glob
// library — DRM rules are operator-authored and we want predictable
// failure modes.
func matchSPIFFE(pattern, uri string) bool {
	if pattern == "" {
		return false
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(uri, prefix)
	}
	return pattern == uri
}

// GetActiveCatalog returns the most recently signed catalog row for a
// tenant, or (nil, nil) when none is configured.
func (g *GovernanceService) GetActiveCatalog(ctx context.Context, accountID, projectID string) (*domain.ConstraintCatalogVersion, error) {
	return g.catalogRepo.GetActive(ctx, accountID, projectID)
}

// PublishCatalog hashes, signs, and stores a new catalog version. If the
// hash differs from the previously active row, a policy_drift signal is
// emitted for outstanding tokens bound to the previous catalog hash.
func (g *GovernanceService) PublishCatalog(ctx context.Context, accountID, projectID, version string, effectiveAt time.Time, document json.RawMessage) (*domain.ConstraintCatalogVersion, error) {
	hash, err := hashRawJSON(document)
	if err != nil {
		return nil, err
	}
	// Same drift-detection lookup as PublishDRM — non-fatal but noisy
	// on failure so missed policy_drift signals are visible.
	previous, prevErr := g.catalogRepo.GetActive(ctx, accountID, projectID)
	if prevErr != nil {
		log.Warn().Err(prevErr).Msg("PublishCatalog: failed to look up previous active catalog for drift detection")
	}

	signedAt := time.Now().UTC()
	sig, err := g.signCatalog(hash, signedAt)
	if err != nil {
		return nil, err
	}

	row := &domain.ConstraintCatalogVersion{
		ID:           uuid.New().String(),
		AccountID:    accountID,
		ProjectID:    projectID,
		Version:      version,
		EffectiveAt:  effectiveAt,
		Document:     document,
		Hash:         hash,
		SignedAt:     signedAt,
		Signature:    sig,
		SigningKeyID: g.jwksSvc.KeyID(),
	}
	if err := g.catalogRepo.Create(ctx, row); err != nil {
		return nil, err
	}

	if previous != nil && previous.Hash != hash {
		g.emitDriftSignals(ctx, accountID, projectID, "constraint_catalog", previous.Hash, hash)
	}
	return row, nil
}

// ResignCatalog rewrites the active catalog row with a fresh SignedAt
// signature, preserving the Hash. Used by the 24h liveness worker so
// that consumers of the hash claim can detect a stale/replayed catalog
// without forcing a token re-mint when no policy change occurred.
func (g *GovernanceService) ResignCatalog(ctx context.Context, accountID, projectID string) error {
	current, err := g.catalogRepo.GetActive(ctx, accountID, projectID)
	if err != nil {
		return err
	}
	if current == nil {
		return nil
	}
	signedAt := time.Now().UTC()
	sig, err := g.signCatalog(current.Hash, signedAt)
	if err != nil {
		return err
	}
	row := &domain.ConstraintCatalogVersion{
		ID:           uuid.New().String(),
		AccountID:    current.AccountID,
		ProjectID:    current.ProjectID,
		Version:      current.Version,
		EffectiveAt:  current.EffectiveAt,
		Document:     current.Document,
		Hash:         current.Hash,
		SignedAt:     signedAt,
		Signature:    sig,
		SigningKeyID: g.jwksSvc.KeyID(),
	}
	return g.catalogRepo.Create(ctx, row)
}

// signCatalog signs SHA-256(hash || "|" || signed_at) with the ES256
// service key. The "|" separator prevents any chance of length-extension
// ambiguity between the two fields.
func (g *GovernanceService) signCatalog(hash string, signedAt time.Time) (string, error) {
	payload := hash + "|" + signedAt.Format(time.RFC3339Nano)
	digest := sha256.Sum256([]byte(payload))
	priv := g.jwksSvc.PrivateKey()
	if priv == nil {
		return "", fmt.Errorf("catalog sign: no ES256 key loaded")
	}
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		return "", fmt.Errorf("catalog sign: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

func hashRawJSON(raw json.RawMessage) (string, error) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", fmt.Errorf("catalog hash: invalid json: %w", err)
	}
	return HashSHA256(v)
}

// emitDriftSignals fires policy_drift signals for every identity
// holding an outstanding credential bound to oldHash. The fan-out runs
// on a background goroutine parented on the service lifecycle context
// (svcCtx) so a hash transition affecting many identities does not
// block the admin POST that triggered it, but also does not outlive
// the server: Server.Shutdown -> GovernanceService.Stop cancels svcCtx
// and in-flight pagination winds down. Errors are logged and swallowed
// — the new DRM/catalog row write must remain durable even if signal
// fan-out partially fails.
func (g *GovernanceService) emitDriftSignals(_ context.Context, accountID, projectID, kind, oldHash, newHash string) {
	if g.signalSvc == nil || g.credRepo == nil {
		return
	}
	g.mu.Lock()
	parent := g.svcCtx
	g.mu.Unlock()
	if parent == nil {
		// Stop() already called — no detached work after shutdown.
		return
	}
	pageSize := g.driftPageSize
	if pageSize <= 0 {
		pageSize = 500
	}
	go g.runDriftFanout(parent, accountID, projectID, kind, oldHash, newHash, pageSize)
}

func (g *GovernanceService) runDriftFanout(ctx context.Context, accountID, projectID, kind, oldHash, newHash string, pageSize int) {
	afterID := ""
	for {
		if ctx.Err() != nil {
			log.Info().Str("kind", kind).Msg("policy_drift: fan-out cancelled by shutdown")
			return
		}
		ids, err := g.credRepo.ListIdentitiesByGovernanceHashPage(ctx, accountID, projectID, kind, oldHash, afterID, pageSize)
		if err != nil {
			log.Warn().Err(err).Str("kind", kind).Msg("policy_drift: failed to enumerate affected identities")
			return
		}
		if len(ids) == 0 {
			return
		}
		for _, identityID := range ids {
			if ctx.Err() != nil {
				return
			}
			_, emitErr := g.signalSvc.IngestSignal(ctx, accountID, projectID, identityID,
				domain.SignalTypePolicyDrift, domain.SignalSeverityMedium, "governance",
				map[string]any{
					"kind":     kind,
					"old_hash": oldHash,
					"new_hash": newHash,
				})
			if emitErr != nil {
				log.Warn().Err(emitErr).Str("identity_id", identityID).Msg("policy_drift: signal emit failed")
			}
		}
		// Advance keyset cursor. ListIdentitiesByGovernanceHashPage
		// returns rows ordered by identity_id ASC, so the last id is
		// the high-water mark.
		afterID = ids[len(ids)-1]
		if len(ids) < pageSize {
			return
		}
	}
}
