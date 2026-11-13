package postgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/uptrace/bun"
)

type AuditLogEntry struct {
	bun.BaseModel `bun:"table:identity_audit_logs,alias:ial"`

	ID         string          `bun:"id,pk"          json:"id"`
	AccountID  string          `bun:"account_id"     json:"account_id"`
	ProjectID  string          `bun:"project_id"     json:"project_id"`
	IdentityID string          `bun:"identity_id"    json:"identity_id"`
	TableName  string          `bun:"table_name"     json:"table_name"`
	Action     string          `bun:"action"         json:"action"`
	Status     string          `bun:"status"         json:"status"`
	UserID     string          `bun:"caller_user_id" json:"user_id"`
	OldData    json.RawMessage `bun:"old_data,type:jsonb"`
	NewData    json.RawMessage `bun:"new_data,type:jsonb"`
	CreatedAt  time.Time       `bun:"created_at"`
}

type AuditLogRepository struct {
	db *bun.DB
}

func NewAuditLogRepository(db *bun.DB) *AuditLogRepository {
	return &AuditLogRepository{db: db}
}

func (r *AuditLogRepository) List(ctx context.Context, accountID, projectID, identityID, tableName, action, userID string) ([]AuditLogEntry, error) {
	var entries []AuditLogEntry

	q := r.db.NewSelect().
		Model(&entries).
		Where("account_id = ?", accountID).
		OrderExpr("created_at DESC")

	if projectID != "" {
		q = q.Where("project_id = ?", projectID)
	}
	if identityID != "" {
		q = q.Where("identity_id = ?", identityID)
	}
	if tableName != "" {
		q = q.Where("table_name = ?", tableName)
	}
	if action != "" {
		q = q.Where("action = ?", action)
	}
	if userID != "" {
		q = q.Where("caller_user_id = ?", userID)
	}

	if err := q.Scan(ctx); err != nil {
		return nil, err
	}
	return entries, nil
}

// AuditFeedEntry is an audit row with its place in the feed (migration 066).
type AuditFeedEntry struct {
	AuditLogEntry `bun:",extend"`

	// TxID is the writing transaction's id (xid8), in its decimal text form.
	TxID string `bun:"txid" json:"txid"`
	Seq  int64  `bun:"seq"  json:"seq"`
}

// Feed returns up to limit rows after (afterTxID, afterSeq), in (txid, seq)
// order, from finished transactions only: a row whose transaction is still
// open, or was open when this read's snapshot was taken, is left for a later
// read. Every transaction below pg_snapshot_xmin has finished, so paging this
// way never passes a row that commits late. Sequence order alone would.
func (r *AuditLogRepository) Feed(ctx context.Context, afterTxID string, afterSeq int64, limit int) ([]AuditFeedEntry, error) {
	var entries []AuditFeedEntry

	err := r.db.NewSelect().
		Model(&entries).
		Where("(ial.txid, ial.seq) > (?::xid8, ?)", afterTxID, afterSeq).
		Where("ial.txid < pg_snapshot_xmin(pg_current_snapshot())").
		OrderExpr("ial.txid, ial.seq").
		Limit(limit).
		Scan(ctx)

	return entries, err
}
