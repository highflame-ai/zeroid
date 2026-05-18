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
	"sort"
	"strings"
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
}

func NewGovernanceService(
	drmRepo *postgres.DRMRepository,
	catalogRepo *postgres.ConstraintCatalogRepository,
	credRepo *postgres.CredentialRepository,
	signalSvc *SignalService,
	jwksSvc *signing.JWKSService,
) *GovernanceService {
	return &GovernanceService{
		drmRepo:     drmRepo,
		catalogRepo: catalogRepo,
		credRepo:    credRepo,
		signalSvc:   signalSvc,
		jwksSvc:     jwksSvc,
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

// canonicalJSON re-encodes v with object keys sorted lexicographically
// at every level. Round-trips through encoding/json into a
// map[string]any/[]any tree first, then walks it.
func canonicalJSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("canonical json: marshal: %w", err)
	}
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil, fmt.Errorf("canonical json: unmarshal: %w", err)
	}
	return canonicalEncode(generic), nil
}

func canonicalEncode(v any) []byte {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			kb, _ := json.Marshal(k)
			b.Write(kb)
			b.WriteByte(':')
			b.Write(canonicalEncode(t[k]))
		}
		b.WriteByte('}')
		return []byte(b.String())
	case []any:
		var b strings.Builder
		b.WriteByte('[')
		for i, el := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			b.Write(canonicalEncode(el))
		}
		b.WriteByte(']')
		return []byte(b.String())
	default:
		out, _ := json.Marshal(t)
		return out
	}
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

	previous, _ := g.drmRepo.GetActive(ctx, accountID, projectID)

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
	previous, _ := g.catalogRepo.GetActive(ctx, accountID, projectID)

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

// emitDriftSignals best-effort-fans-out policy_drift signals for every
// identity holding an outstanding credential bound to oldHash. Errors
// are logged and swallowed — the new DRM/catalog write must remain
// durable even if signal fan-out partially fails.
func (g *GovernanceService) emitDriftSignals(ctx context.Context, accountID, projectID, kind, oldHash, newHash string) {
	if g.signalSvc == nil || g.credRepo == nil {
		return
	}
	identities, err := g.credRepo.ListIdentitiesByGovernanceHash(ctx, accountID, projectID, kind, oldHash)
	if err != nil {
		log.Warn().Err(err).Str("kind", kind).Msg("policy_drift: failed to enumerate affected identities")
		return
	}
	for _, identityID := range identities {
		_, err := g.signalSvc.IngestSignal(ctx, accountID, projectID, identityID,
			domain.SignalTypePolicyDrift, domain.SignalSeverityMedium, "governance",
			map[string]any{
				"kind":     kind,
				"old_hash": oldHash,
				"new_hash": newHash,
			})
		if err != nil {
			log.Warn().Err(err).Str("identity_id", identityID).Msg("policy_drift: signal emit failed")
		}
	}
}
