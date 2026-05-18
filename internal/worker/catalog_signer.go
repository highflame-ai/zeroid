package worker

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// CatalogResigner is a tenant resigner abstraction. The governance
// service implements this; we keep the worker decoupled from the
// service package to avoid an import cycle (service imports worker
// for testing helpers in other places).
type CatalogResigner interface {
	ResignCatalog(ctx context.Context, accountID, projectID string) error
}

// CatalogSignerWorker re-signs the active Constraint Catalog row for
// every tenant on a 24h cadence (issue #59). A re-sign preserves the
// document Hash but rewrites SignedAt+Signature, so outstanding tokens
// bound to the hash stay valid; downstream consumers that watch
// SignedAt can detect a stale/replayed catalog.
type CatalogSignerWorker struct {
	repo     *postgres.ConstraintCatalogRepository
	resigner CatalogResigner
	interval time.Duration
}

// NewCatalogSignerWorker — pass time.Hour*24 in production. Tests pass
// a short interval and rely on runOnce being deterministic.
func NewCatalogSignerWorker(repo *postgres.ConstraintCatalogRepository, resigner CatalogResigner, interval time.Duration) *CatalogSignerWorker {
	return &CatalogSignerWorker{repo: repo, resigner: resigner, interval: interval}
}

func (w *CatalogSignerWorker) Run(ctx context.Context) {
	log.Info().Dur("interval", w.interval).Msg("Catalog signer worker started")
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	// First re-sign happens after one full interval, not at startup —
	// avoids a spurious re-sign every restart.
	for {
		select {
		case <-ticker.C:
			w.runOnce(ctx)
		case <-ctx.Done():
			log.Info().Msg("Catalog signer worker stopped")
			return
		}
	}
}

func (w *CatalogSignerWorker) runOnce(ctx context.Context) {
	tenants, err := w.repo.ListTenants(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Catalog signer: failed to list tenants")
		return
	}
	for _, t := range tenants {
		if err := w.resigner.ResignCatalog(ctx, t.AccountID, t.ProjectID); err != nil {
			log.Warn().Err(err).
				Str("account_id", t.AccountID).
				Str("project_id", t.ProjectID).
				Msg("Catalog signer: re-sign failed")
		}
	}
}
