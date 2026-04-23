package handler

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	internalMiddleware "github.com/highflame-ai/zeroid/internal/middleware"
	"github.com/highflame-ai/zeroid/internal/service"
)

type ListAuditLogsInput struct {
	IdentityID string `query:"identity_id" doc:"Filter by identity ID"`
	Action     string `query:"action" doc:"Filter by action (INSERT, UPDATE, DELETE)"`
	UserID     string `query:"user_id" doc:"Filter by user ID"`
}

type ListAuditLogsOutput struct {
	Body struct {
		Audits []service.AuditLogResponse `json:"audits"`
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

	logs, err := a.auditSvc.ListAuditLogs(ctx, tenant.AccountID, tenant.ProjectID, service.AuditLogFilter{
		IdentityID: input.IdentityID,
		Action:     input.Action,
		UserID:     input.UserID,
	})
	if err != nil {
		return nil, huma.Error500InternalServerError("failed to query audit logs")
	}

	out := &ListAuditLogsOutput{}
	out.Body.Audits = logs
	return out, nil
}
