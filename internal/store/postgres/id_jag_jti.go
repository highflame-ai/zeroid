package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/uptrace/bun"
)

// ErrIDJAGReplay is returned by IDJAGReplayStore.Insert when the jti is already
// present (SQLSTATE 23505 on the primary key). An MCP ID-JAG is a single-use
// authorization grant (ADR 0010 D2a); a second redemption of the same jti is a
// replay and the caller MUST reject the grant (OAuth invalid_grant).
//
// Defined as a package sentinel (not reusing dpop.ErrReplay) so the ID-JAG
// redemption path can errors.Is it independently of the DPoP proof path — the
// two replay domains are distinct (a grant jti vs a proof jti) even though the
// storage shape is identical.
var ErrIDJAGReplay = errors.New("id-jag jti has already been redeemed")

// idJAGJTIRow is the bun model for the id_jag_jti replay-prevention table.
// Schema is defined in migrations/034_id_jag_jti.up.sql; this struct must stay
// in sync with the column definitions there.
type idJAGJTIRow struct {
	bun.BaseModel `bun:"table:id_jag_jti"`
	JTI           string    `bun:"jti,pk"`
	ExpiresAt     time.Time `bun:"expires_at"`
}

// IDJAGReplayStore is the Postgres-backed single-use ledger for redeemed ID-JAG
// jti values (ADR 0010 D2a). One row per redeemed jti, primary-keyed; a
// unique-constraint violation on INSERT is the atomic replay signal.
//
// Mirrors DPoPReplayStore verbatim — same single-use replay-table shape. Expired
// rows are pruned by internal/worker/cleanup.go; this store doesn't run its own
// pruner — the worker handles it for every table at once.
type IDJAGReplayStore struct {
	db *bun.DB
}

// NewIDJAGReplayStore wires an IDJAGReplayStore against the given bun.DB. The
// db must have the id_jag_jti table available (migration 034_id_jag_jti.up.sql).
func NewIDJAGReplayStore(db *bun.DB) *IDJAGReplayStore {
	return &IDJAGReplayStore{db: db}
}

// Insert records a previously-unredeemed jti. Returns ErrIDJAGReplay on
// SQLSTATE 23505 (unique constraint violation — the jti is already in the table
// and the redemption is a replay). Other DB errors are returned as-is so the
// caller can map them to a 5xx response rather than a (mis-classified) replay.
//
// The check-and-insert is atomic: concurrent Insert calls for the same jti
// result in exactly one nil return and every other return being ErrIDJAGReplay.
//
// expiresAt should be the ID-JAG's own exp — the instant after which the entry
// may be safely garbage-collected, because a grant that old would fail its exp
// check before the jti is ever consulted.
func (s *IDJAGReplayStore) Insert(ctx context.Context, jti string, expiresAt time.Time) error {
	row := &idJAGJTIRow{JTI: jti, ExpiresAt: expiresAt}
	_, err := s.db.NewInsert().Model(row).Exec(ctx)
	if err == nil {
		return nil
	}
	// isDuplicateKeyError is defined in dpop_replay.go (same package) — reuse it
	// rather than re-declaring the SQLSTATE 23505 check.
	if isDuplicateKeyError(err) {
		return ErrIDJAGReplay
	}
	return err
}
