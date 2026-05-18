package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/highflame-ai/zeroid/domain"
)

// ErrBackchannelRequestNotFound is returned when GetByAuthReqID finds no row.
var ErrBackchannelRequestNotFound = errors.New("backchannel auth request not found")

// BackchannelRequestRepository persists CIBA authentication requests.
type BackchannelRequestRepository struct {
	db *bun.DB
}

// NewBackchannelRequestRepository constructs the repository.
func NewBackchannelRequestRepository(db *bun.DB) *BackchannelRequestRepository {
	return &BackchannelRequestRepository{db: db}
}

// Create inserts a new pending request. auth_req_id is the PK; a collision
// returns an error rather than overwriting (the service mints from crypto/rand,
// so collisions are an implementation bug, not normal-path).
func (r *BackchannelRequestRepository) Create(ctx context.Context, req *domain.BackchannelAuthRequest) error {
	if _, err := r.db.NewInsert().Model(req).Exec(ctx); err != nil {
		return fmt.Errorf("failed to insert backchannel auth request: %w", err)
	}
	return nil
}

// GetByAuthReqID loads the request by its opaque handle. Returns
// ErrBackchannelRequestNotFound when the row does not exist so callers can
// map cleanly to OAuth-standard error responses.
func (r *BackchannelRequestRepository) GetByAuthReqID(ctx context.Context, authReqID string) (*domain.BackchannelAuthRequest, error) {
	req := &domain.BackchannelAuthRequest{}
	err := r.db.NewSelect().Model(req).Where("auth_req_id = ?", authReqID).Scan(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrBackchannelRequestNotFound
		}
		return nil, fmt.Errorf("failed to load backchannel auth request: %w", err)
	}
	return req, nil
}

// MarkApproved transitions a pending row to approved and records the resolved
// subject. The status='pending' guard makes the operation idempotent and
// prevents re-approving a denied/expired row. Returns the number of rows
// affected so callers can detect "already approved/denied" as 0.
func (r *BackchannelRequestRepository) MarkApproved(ctx context.Context, authReqID, subjectID, subjectEmail, subjectName string) (int64, error) {
	now := time.Now()
	res, err := r.db.NewUpdate().
		Model((*domain.BackchannelAuthRequest)(nil)).
		Set("status = ?", domain.BackchannelStatusApproved).
		Set("approved_subject_id = ?", subjectID).
		Set("approved_subject_email = ?", subjectEmail).
		Set("approved_subject_name = ?", subjectName).
		Set("approved_at = ?", now).
		Where("auth_req_id = ?", authReqID).
		Where("status = ?", domain.BackchannelStatusPending).
		Where("expires_at > ?", now).
		Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to mark backchannel request approved: %w", err)
	}
	return res.RowsAffected()
}

// MarkDenied transitions a pending row to denied. Same guard semantics as MarkApproved.
func (r *BackchannelRequestRepository) MarkDenied(ctx context.Context, authReqID string) (int64, error) {
	now := time.Now()
	res, err := r.db.NewUpdate().
		Model((*domain.BackchannelAuthRequest)(nil)).
		Set("status = ?", domain.BackchannelStatusDenied).
		Where("auth_req_id = ?", authReqID).
		Where("status = ?", domain.BackchannelStatusPending).
		Where("expires_at > ?", now).
		Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to mark backchannel request denied: %w", err)
	}
	return res.RowsAffected()
}

// MarkIssued transitions an approved row to issued so a second redemption of
// the same auth_req_id returns access_denied instead of minting a second token.
func (r *BackchannelRequestRepository) MarkIssued(ctx context.Context, authReqID string) (int64, error) {
	res, err := r.db.NewUpdate().
		Model((*domain.BackchannelAuthRequest)(nil)).
		Set("status = ?", domain.BackchannelStatusIssued).
		Where("auth_req_id = ?", authReqID).
		Where("status = ?", domain.BackchannelStatusApproved).
		Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to mark backchannel request issued: %w", err)
	}
	return res.RowsAffected()
}

// TouchPoll records the time of the current poll. Used by the grant handler to
// enforce the CIBA "slow_down" rule (RFC says clients MUST honour the response
// interval; the server enforces a floor).
func (r *BackchannelRequestRepository) TouchPoll(ctx context.Context, authReqID string, at time.Time) error {
	_, err := r.db.NewUpdate().
		Model((*domain.BackchannelAuthRequest)(nil)).
		Set("last_polled_at = ?", at).
		Where("auth_req_id = ?", authReqID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to touch backchannel poll time: %w", err)
	}
	return nil
}

// SetLastNotifyError records the most recent notifier failure for operator
// debugging. Best-effort — failure to write the field is logged at the call
// site but does not abort the request lifecycle.
func (r *BackchannelRequestRepository) SetLastNotifyError(ctx context.Context, authReqID, msg string) error {
	_, err := r.db.NewUpdate().
		Model((*domain.BackchannelAuthRequest)(nil)).
		Set("last_notify_error = ?", msg).
		Where("auth_req_id = ?", authReqID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to set last_notify_error: %w", err)
	}
	return nil
}

// SweepExpired flips any pending row whose expires_at has passed to status='expired'.
// Run from the cleanup worker so an in-flight poll on a just-expired row sees
// a meaningful expired_token before the row is reaped.
func (r *BackchannelRequestRepository) SweepExpired(ctx context.Context, now time.Time) (int64, error) {
	res, err := r.db.NewUpdate().
		Model((*domain.BackchannelAuthRequest)(nil)).
		Set("status = ?", domain.BackchannelStatusExpired).
		Where("status = ?", domain.BackchannelStatusPending).
		Where("expires_at < ?", now).
		Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to sweep expired backchannel requests: %w", err)
	}
	return res.RowsAffected()
}

// DeleteExpired reaps resolved rows (expired/denied/issued) whose expires_at
// is past. Approved-but-not-yet-issued rows are retained so a slow poll can
// still complete the issuance.
func (r *BackchannelRequestRepository) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	res, err := r.db.NewDelete().
		Model((*domain.BackchannelAuthRequest)(nil)).
		Where("expires_at < ?", now).
		Where("status IN (?, ?, ?)",
			domain.BackchannelStatusExpired,
			domain.BackchannelStatusDenied,
			domain.BackchannelStatusIssued,
		).
		Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to delete expired backchannel requests: %w", err)
	}
	return res.RowsAffected()
}
