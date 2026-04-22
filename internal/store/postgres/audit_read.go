package postgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/uptrace/bun"
)

// AuditLogEntry mirrors the identity_audit_logs table (written by DB trigger).
type AuditLogEntry struct {
	bun.BaseModel `bun:"table:identity_audit_logs,alias:ial"`

	ID           string          `bun:"id,pk"          json:"id"`
	AccountID    string          `bun:"account_id"     json:"account_id"`
	ProjectID    string          `bun:"project_id"     json:"project_id"`
	CallerUserID string          `bun:"caller_user_id" json:"caller_user_id"`
	IdentityID   string          `bun:"identity_id"    json:"identity_id"`
	Action       string          `bun:"action"         json:"action"`
	Status       string          `bun:"status"         json:"status"`
	OldData      json.RawMessage `bun:"old_data,type:jsonb"`
	NewData      json.RawMessage `bun:"new_data,type:jsonb"`
	CreatedAt    time.Time       `bun:"created_at"`
}

// AuditLogRepository reads from identity_audit_logs.
type AuditLogRepository struct {
	db *bun.DB
}

// NewAuditLogRepository creates a new AuditLogRepository.
func NewAuditLogRepository(db *bun.DB) *AuditLogRepository {
	return &AuditLogRepository{db: db}
}

// List returns audit log entries for a tenant, optionally filtered by identity ID.
func (r *AuditLogRepository) List(ctx context.Context, accountID, projectID, identityID string) ([]AuditLogEntry, error) {
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

	if err := q.Scan(ctx); err != nil {
		return nil, err
	}
	return entries, nil
}
