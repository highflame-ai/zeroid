package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/driver/pgdriver"

	"github.com/highflame-ai/zeroid/pkg/dpop"
)

// dpopJTIRow is the bun model for the dpop_jti replay-prevention table.
// Schema is defined in migrations/025_dpop.up.sql; this struct must stay in
// sync with the column definitions there.
type dpopJTIRow struct {
	bun.BaseModel `bun:"table:dpop_jti"`
	JTI           string    `bun:"jti,pk"`
	ExpiresAt     time.Time `bun:"expires_at"`
}

// DPoPReplayStore is the Postgres-backed implementation of dpop.ReplayStore.
// One row per observed jti, primary-keyed; a unique-constraint violation on
// INSERT is the atomic replay signal.
//
// Expired rows are pruned by internal/worker/cleanup.go; this store doesn't
// run its own pruner — the worker handles it for every table at once.
type DPoPReplayStore struct {
	db *bun.DB
}

// NewDPoPReplayStore wires a DPoPReplayStore against the given bun.DB. The
// db must have the dpop_jti table available (migration 025_dpop.up.sql).
func NewDPoPReplayStore(db *bun.DB) *DPoPReplayStore {
	return &DPoPReplayStore{db: db}
}

// Insert implements dpop.ReplayStore. Returns dpop.ErrReplay on
// SQLSTATE 23505 (unique constraint violation — the jti is already in the
// table and the verifier should treat the proof as a replay). Other DB
// errors are returned as-is; the dpop.Verifier wraps them into
// dpop.ErrStorageFailure so the caller can map to a 5xx response.
func (s *DPoPReplayStore) Insert(ctx context.Context, jti string, expiresAt time.Time) error {
	row := &dpopJTIRow{JTI: jti, ExpiresAt: expiresAt}
	_, err := s.db.NewInsert().Model(row).Exec(ctx)
	if err == nil {
		return nil
	}
	if isDuplicateKeyError(err) {
		return dpop.ErrReplay
	}
	return err
}

// isDuplicateKeyError reports whether err is a PostgreSQL unique-constraint
// violation (SQLSTATE 23505). Local duplicate of the helper in
// internal/service/errors.go — kept here so internal/store has no upstream
// dependency on internal/service (would create an import cycle).
func isDuplicateKeyError(err error) bool {
	var pgErr pgdriver.Error
	return errors.As(err, &pgErr) && pgErr.Field('C') == "23505"
}
