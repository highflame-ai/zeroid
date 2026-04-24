package worker

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/uptrace/bun"
)

// CleanupWorker periodically removes expired issued_credentials and proof_tokens rows.
// Running the cleanup prevents unbounded table growth since credentials have a finite TTL.
// It is safe to run multiple instances concurrently — DELETE WHERE is idempotent.
type CleanupWorker struct {
	db       *bun.DB
	interval time.Duration
}

// NewCleanupWorker creates a cleanup worker with the given tick interval.
func NewCleanupWorker(db *bun.DB, interval time.Duration) *CleanupWorker {
	return &CleanupWorker{db: db, interval: interval}
}

// Run starts the cleanup loop and blocks until ctx is cancelled.
func (w *CleanupWorker) Run(ctx context.Context) {
	log.Info().Dur("interval", w.interval).Msg("Cleanup worker started")
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	// Run immediately on start, then on every tick.
	w.runOnce(ctx)

	for {
		select {
		case <-ticker.C:
			w.runOnce(ctx)
		case <-ctx.Done():
			log.Info().Msg("Cleanup worker stopped")
			return
		}
	}
}

func (w *CleanupWorker) runOnce(ctx context.Context) {
	now := time.Now()

	// Delete all expired credentials regardless of revocation status.
	credRes, err := w.db.NewDelete().
		TableExpr("issued_credentials").
		Where("expires_at < ?", now).
		Exec(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Cleanup: failed to delete expired credentials")
	} else if n, err := credRes.RowsAffected(); err == nil && n > 0 {
		log.Info().Int64("count", n).Msg("Cleanup: deleted expired credentials")
	}

	proofRes, err := w.db.NewDelete().
		TableExpr("proof_tokens").
		Where("expires_at < ?", now).
		Exec(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Cleanup: failed to delete expired proof tokens")
	} else if n, err := proofRes.RowsAffected(); err == nil && n > 0 {
		log.Info().Int64("count", n).Msg("Cleanup: deleted expired proof tokens")
	}

	// Delete consumed auth codes past their expiry (single-use enforcement records).
	authCodeRes, err := w.db.NewDelete().
		TableExpr("auth_codes").
		Where("expires_at < ?", now).
		Exec(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Cleanup: failed to delete expired auth codes")
	} else if n, err := authCodeRes.RowsAffected(); err == nil && n > 0 {
		log.Info().Int64("count", n).Msg("Cleanup: deleted expired auth codes")
	}
}
