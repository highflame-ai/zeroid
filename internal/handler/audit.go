package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	internalMiddleware "github.com/highflame-ai/zeroid/internal/middleware"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// AuditLogResponse is the wire shape returned to Studio, matching the AuditLog
// interface in packages/registry/src/types.ts.
type AuditLogResponse struct {
	AuditID     string                 `json:"audit_id"`
	AccountID   string                 `json:"account_id"`
	GatewayID   string                 `json:"gateway_id"`
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

type ListAuditLogsInput struct {
	IdentityID string `query:"identity_id" doc:"Filter by identity ID"`
}

type ListAuditLogsOutput struct {
	Body struct {
		Audits []AuditLogResponse `json:"audits"`
	}
}

func (a *API) registerAuditRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "list-identity-audit-logs",
		Method:      http.MethodGet,
		Path:        "/identity-audit-logs",
		Summary:     "List audit log entries for identities in the current tenant",
		Tags:        []string{"Audit"},
	}, a.listAuditLogsOp)
}

func (a *API) listAuditLogsOp(ctx context.Context, input *ListAuditLogsInput) (*ListAuditLogsOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	repo := postgres.NewAuditLogRepository(a.db)
	entries, err := repo.List(ctx, tenant.AccountID, tenant.ProjectID, input.IdentityID)
	if err != nil {
		return nil, huma.Error500InternalServerError("failed to query audit logs")
	}

	out := &ListAuditLogsOutput{}
	out.Body.Audits = make([]AuditLogResponse, 0, len(entries))
	for _, e := range entries {
		out.Body.Audits = append(out.Body.Audits, auditEntryToResponse(e))
	}
	return out, nil
}

func auditEntryToResponse(e postgres.AuditLogEntry) AuditLogResponse {
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
		GatewayID:  "",
		TableName:  "identities",
		Action:     e.Action,
		Status:     e.Status,
		UserID:     e.CallerUserID,
		Timestamp:  e.CreatedAt.UTC().Format(time.RFC3339),
		OldData:    oldData,
		NewData:    newData,
		EntityName: entityName,
	}
}
