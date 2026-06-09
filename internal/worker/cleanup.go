package worker

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/uptrace/bun"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// IdentityExpirer is implemented by IdentityService.SweepExpiredIdentities.
// Defined here so the worker package doesn't have to import service (which
// would create a cycle: service → worker → service).
type IdentityExpirer interface {
	SweepExpiredIdentities(ctx context.Context) (int, error)
}

// CleanupWorker periodically removes expired issued_credentials, proof_tokens,
// and auth_codes rows, and sweeps expired identities into status=deactivated
// via IdentityService.SweepExpiredIdentities (an atomic conditional UPDATE
// claim followed by the existing runDeactivationCleanup cascade).
// Running the cleanup prevents unbounded table growth since credentials have
// a finite TTL. Safe to run multiple instances concurrently — DELETE WHERE
// is idempotent and the DeactivateIfActive claim guarantees only one worker
// fires the cascade per expired identity.
type CleanupWorker struct {
	db              *bun.DB
	backchannelRepo *postgres.BackchannelRequestRepository
	expirer         IdentityExpirer
	interval        time.Duration
	credRetention   time.Duration
}

// NewCleanupWorker creates a cleanup worker with the given tick interval.
// backchannelRepo is required so the worker can flip expired CIBA requests
// to status='expired' (so an in-flight poll sees expired_token before the
// row is reaped) and then delete the resolved rows.
//
// credRetention is how long expired issued_credentials rows are retained
// before deletion. Expired rows are not just garbage: their parent_jti
// edges are the path the cascade-revocation walk takes to reach still-live
// delegated descendants. Deleting a parent row at the moment of expiry
// severs that edge and strands any child that outlives it. token_exchange
// now clamps child expiry to the parent's, so retaining for the max token
// TTL guarantees every edge survives as long as any descendant could —
// including legacy chains issued before the clamp. Callers pass the
// configured token max TTL.
//
// The identity-expiry sweep is wired separately via SetIdentityExpirer
// after IdentityService is constructed.
func NewCleanupWorker(db *bun.DB, backchannelRepo *postgres.BackchannelRequestRepository, interval, credRetention time.Duration) *CleanupWorker {
	// A negative retention would make now.Add(-credRetention) a FUTURE
	// cutoff and the worker would delete unexpired credentials. Clamp to
	// zero so a misconfigured max TTL degrades to delete-at-expiry, never
	// delete-before-expiry.
	if credRetention < 0 {
		credRetention = 0
	}
	return &CleanupWorker{db: db, backchannelRepo: backchannelRepo, interval: interval, credRetention: credRetention}
}

// SetIdentityExpirer installs the identity-expiry sweep callback. Nil
// disables the sweep (the row-cleanup steps still run). Wired in server.go
// after IdentityService is constructed.
func (w *CleanupWorker) SetIdentityExpirer(e IdentityExpirer) {
	w.expirer = e
}

// Run starts the cleanup loop and blocks until ctx is cancelled.
func (w *CleanupWorker) Run(ctx context.Context) {
	log.Info().Dur("interval", w.interval).Msg("Cleanup worker started")
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	// Run immediately on start, then on every tick.
	w.RunOnce(ctx)

	for {
		select {
		case <-ticker.C:
			w.RunOnce(ctx)
		case <-ctx.Done():
			log.Info().Msg("Cleanup worker stopped")
			return
		}
	}
}

// RunOnce executes one cleanup pass. Exported so integration tests can
// drive a deterministic sweep without spinning up the periodic loop.
func (w *CleanupWorker) RunOnce(ctx context.Context) {
	now := time.Now()

	// Delete expired credentials regardless of revocation status, but only
	// after the retention window: parent_jti edges on expired rows are still
	// needed by the cascade-revocation walk to reach live descendants (see
	// NewCleanupWorker).
	credRes, err := w.db.NewDelete().
		TableExpr("issued_credentials").
		Where("expires_at < ?", now.Add(-w.credRetention)).
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

	// DPoP JTIs are only needed within the freshness window (RFC 9449 §4.2).
	// Purge expired rows to prevent unbounded table growth under high
	// token-request volume.
	dpopRes, err := w.db.NewDelete().
		TableExpr("dpop_jti").
		Where("expires_at < ?", now).
		Exec(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Cleanup: failed to delete expired dpop jti records")
	} else if n, err := dpopRes.RowsAffected(); err == nil && n > 0 {
		log.Info().Int64("count", n).Msg("Cleanup: deleted expired dpop jti records")
	}

	// Refresh tokens: under rotation every refresh inserts a successor row and
	// revokes its predecessor, so the table grows linearly with token traffic
	// if never swept. Delete rows whose expires_at is past the reuse-detection
	// grace window. Reuse detection (service/refresh_token.go) consults
	// recently-revoked rows for RefreshTokenReuseGraceWindow after revocation to
	// distinguish a benign concurrent retry from a replay attack; lagging the
	// cutoff by that window guarantees we never delete a row reuse detection
	// could still need. Expiry is the bound (rotation revokes well before
	// expires_at), so a row past expires_at - graceWindow is safe to reap.
	refreshRepo := postgres.NewRefreshTokenRepository(w.db)
	if n, err := refreshRepo.DeleteExpired(ctx, now.Add(-domain.RefreshTokenReuseGraceWindow)); err != nil {
		log.Error().Err(err).Msg("Cleanup: failed to delete expired refresh tokens")
	} else if n > 0 {
		log.Info().Int64("count", n).Msg("Cleanup: deleted expired refresh tokens")
	}

	// Signing credentials: prune non-revoked rows whose audit-retention window
	// has fully elapsed. This mirrors SigningCredentialRepository.PruneExpiredRetention
	// exactly (same WHERE: revoked = false AND audit_retention_until <= now) —
	// replicated inline rather than wired through the repo because the worker is
	// constructed in server.go without a SigningCredentialRepository and that
	// constructor is out of scope to change. Revoked rows are retained as a
	// tamper-evidence trail. Backed by idx_signing_credentials_retention (023).
	signingRes, err := w.db.NewDelete().
		Model((*domain.SigningCredential)(nil)).
		Where("revoked = ?", false).
		Where("audit_retention_until <= ?", now).
		Exec(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Cleanup: failed to prune expired signing credentials")
	} else if n, err := signingRes.RowsAffected(); err == nil && n > 0 {
		log.Info().Int64("count", n).Msg("Cleanup: pruned expired signing credentials")
	}

	// CIBA backchannel requests:
	//   1. Flip pending → expired so an in-flight poll sees expired_token.
	//   2. Reap rows in a resolved terminal state past expires_at.
	// Order matters: sweep first, delete second.
	if w.backchannelRepo != nil {
		if n, err := w.backchannelRepo.SweepExpired(ctx, now); err != nil {
			log.Error().Err(err).Msg("Cleanup: failed to sweep expired backchannel auth requests")
		} else if n > 0 {
			log.Info().Int64("count", n).Msg("Cleanup: marked backchannel auth requests expired")
		}
		if n, err := w.backchannelRepo.DeleteExpired(ctx, now); err != nil {
			log.Error().Err(err).Msg("Cleanup: failed to delete expired backchannel auth requests")
		} else if n > 0 {
			log.Info().Int64("count", n).Msg("Cleanup: deleted expired backchannel auth requests")
		}
	}

	// Identity-expiry sweep. Runs after the row-deletes so that any tokens
	// cascade-revoked by the sweep are recorded as revocations rather than
	// being silently cleared by the credential-expiry delete above.
	if w.expirer != nil {
		if _, err := w.expirer.SweepExpiredIdentities(ctx); err != nil {
			log.Error().Err(err).Msg("Cleanup: identity-expiry sweep failed")
		}
	}
}
