package service

import (
	"context"
	"encoding/json"
	"time"

	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// AuditLogFilter holds optional filters for querying audit logs.
type AuditLogFilter struct {
	IdentityID string
	Action     string
	UserID     string
}

// AuditLogResponse is the wire type for audit log entries returned to clients.
// It matches the AuditLog interface in packages/registry/src/types.ts.
type AuditLogResponse struct {
	AuditID     string                 `json:"audit_id"`
	AccountID   string                 `json:"account_id"`
	TableName   string                 `json:"table_name"`
	Action      string                 `json:"action"`
	Status      string                 `json:"status"`
	UserID      string                 `json:"user_id"`
	Timestamp   string                 `json:"timestamp"`
	OldData     map[string]interface{} `json:"old_data"`
	NewData     map[string]interface{} `json:"new_data"`
	ChangedData interface{}            `json:"changed_data"`
	EntityName  string                 `json:"entity_name"`
}

// AuditService handles audit log queries.
type AuditService struct {
	repo *postgres.AuditLogRepository
}

func NewAuditService(repo *postgres.AuditLogRepository) *AuditService {
	return &AuditService{repo: repo}
}

func (s *AuditService) ListAuditLogs(ctx context.Context, accountID, projectID string, filter AuditLogFilter) ([]AuditLogResponse, error) {
	entries, err := s.repo.List(ctx, accountID, projectID, filter.IdentityID, filter.Action, filter.UserID)
	if err != nil {
		return nil, err
	}

	responses := make([]AuditLogResponse, 0, len(entries))
	for _, e := range entries {
		responses = append(responses, toAuditLogResponse(e))
	}
	return responses, nil
}

func toAuditLogResponse(e postgres.AuditLogEntry) AuditLogResponse {
	var oldData, newData map[string]interface{}
	if len(e.OldData) > 0 {
		_ = json.Unmarshal(e.OldData, &oldData)
	}
	if len(e.NewData) > 0 {
		_ = json.Unmarshal(e.NewData, &newData)
	}

	var entityName string
	if name, ok := newData["name"].(string); ok {
		entityName = name
	} else if name, ok := oldData["name"].(string); ok {
		entityName = name
	}

	return AuditLogResponse{
		AuditID:    e.ID,
		AccountID:  e.AccountID,
		TableName:  "identities",
		Action:     e.Action,
		Status:     e.Status,
		UserID:     e.UserID,
		Timestamp:  e.CreatedAt.UTC().Format(time.RFC3339),
		OldData:    oldData,
		NewData:    newData,
		EntityName: entityName,
	}
}
