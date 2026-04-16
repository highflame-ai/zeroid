package postgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

// IdentityAuditLog is the DB model for the identity_audit_logs table.
type IdentityAuditLog struct {
	bun.BaseModel `bun:"table:identity_audit_logs,alias:ial"`

	ID           string          `bun:"id,pk,type:uuid,default:gen_random_uuid()"`
	AccountID    string          `bun:"account_id,notnull"`
	ProjectID    string          `bun:"project_id,notnull"`
	CallerUserID string          `bun:"caller_user_id,notnull"`
	IdentityID   string          `bun:"identity_id,notnull"`
	Action       string          `bun:"action,notnull"`
	Status       string          `bun:"status,notnull"`
	OldData      json.RawMessage `bun:"old_data,type:jsonb"`
	NewData      json.RawMessage `bun:"new_data,type:jsonb"`
	CreatedAt    time.Time       `bun:"created_at,notnull,default:current_timestamp"`
}

// AuditRepository handles writes to the identity_audit_logs table.
type AuditRepository struct {
	db *bun.DB
}

// NewAuditRepository creates a new AuditRepository.
func NewAuditRepository(db *bun.DB) *AuditRepository {
	return &AuditRepository{db: db}
}

// Insert writes a single audit record.
func (r *AuditRepository) Insert(ctx context.Context, accountID, projectID, callerUserID, identityID, action, status string, oldData, newData json.RawMessage) error {
	entry := &IdentityAuditLog{
		ID:           uuid.New().String(),
		AccountID:    accountID,
		ProjectID:    projectID,
		CallerUserID: callerUserID,
		IdentityID:   identityID,
		Action:       action,
		Status:       status,
		OldData:      oldData,
		NewData:      newData,
		CreatedAt:    time.Now().UTC(),
	}
	_, err := r.db.NewInsert().Model(entry).Exec(ctx)
	return err
}
