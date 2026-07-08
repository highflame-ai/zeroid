package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/highflame-ai/zeroid/domain"
	internalMiddleware "github.com/highflame-ai/zeroid/internal/middleware"
	"github.com/highflame-ai/zeroid/internal/service"
)

// Code-agent bootstrap endpoints (highflame-architecture#136, epic #132 S3).
//
// Four surfaces, three auth models:
//   - POST /code-agents/bootstrap        — public router, BootstrapAuthMiddleware
//     (zeroid:bootstrap-scoped developer token; tenant + owner from claims).
//   - POST /code-agents/{id}/attest      — public router, AgentAuthMiddleware
//     (the agent's OWN access token; it can only attest itself).
//   - POST /code-agents/by-machine/{machine_id}/revoke — admin router.
//   - GET  /code-agents/by-developer/{user_id}          — admin router.

// ── Bootstrap ────────────────────────────────────────────────────────────────

type BootstrapCodeAgentInput struct {
	Body struct {
		PublicKeyPEM string `json:"public_key_pem" required:"true" minLength:"1" doc:"SPKI EC P-256 custody public key (PEM). The matching private key never leaves the developer machine; it signs the agent's jwt_bearer assertions."`
		Framework    string `json:"framework" required:"true" minLength:"1" doc:"Code-agent runtime (e.g. claude-code, cursor). SPIFFE path segment characters only (a-z A-Z 0-9 . - _)."`
		MachineID    string `json:"machine_id" required:"true" minLength:"1" doc:"Stable identifier of the developer machine the custody key lives on. Enables revoke-by-machine. SPIFFE path segment characters only."`
		SubType      string `json:"sub_type,omitempty" enum:"orchestrator,tool_agent" doc:"Operational role (defaults to orchestrator)"`
		Name         string `json:"name,omitempty" doc:"Human-readable name (defaults to <framework>-<machine id prefix>)"`
	}
}

type BootstrapCodeAgentOutput struct {
	Body *service.CodeAgentBootstrapResponse
}

// ── Attest ───────────────────────────────────────────────────────────────────

type AttestCodeAgentInput struct {
	ID   string `path:"id" doc:"Code agent identity UUID (must be the caller's own identity)"`
	Body struct {
		Evidence json.RawMessage `json:"evidence" required:"true" doc:"Opaque JSON attestation evidence document (runtime environment facts). Stored verbatim; policy elsewhere decides on freshness/shape."`
	}
}

type AttestCodeAgentOutput struct {
	Body struct {
		LastAttestedAt time.Time `json:"last_attested_at" doc:"Server timestamp recorded for this attestation"`
	}
}

// ── Revoke by machine ────────────────────────────────────────────────────────

type RevokeCodeAgentsByMachineInput struct {
	MachineID string `path:"machine_id" doc:"Bootstrap machine identifier whose code agents should be revoked"`
	Body      struct {
		OwnerUserID string `json:"owner_user_id,omitempty" doc:"Optional filter: only revoke this developer's agents on the machine"`
	}
}

type RevokeCodeAgentsByMachineOutput struct {
	Body struct {
		Revoked int `json:"revoked" doc:"Number of code agents deactivated"`
	}
}

// ── List by developer ────────────────────────────────────────────────────────

type ListCodeAgentsByDeveloperInput struct {
	UserID string `path:"user_id" doc:"Developer (owner) user ID"`
}

type ListCodeAgentsByDeveloperOutput struct {
	Body struct {
		CodeAgents []service.AgentResponse `json:"code_agents"`
	}
}

// ── Route registration ───────────────────────────────────────────────────────

// RegisterCodeAgentBootstrap registers the public bootstrap endpoint. It MUST
// be mounted on the public router behind BootstrapAuthMiddleware — tenant and
// owner come from the validated zeroid:bootstrap token claims, never from the
// request body.
func (a *API) RegisterCodeAgentBootstrap(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID:   "bootstrap-code-agent",
		Method:        http.MethodPost,
		Path:          "/code-agents/bootstrap",
		Summary:       "Bootstrap a code agent from a developer machine (register identity + mint first token)",
		Tags:          []string{"Code Agents"},
		DefaultStatus: http.StatusCreated,
	}, a.bootstrapCodeAgentOp)
}

// registerCodeAgentAttestRoute registers the agent self-service attestation
// endpoint. Mounted with the other self-service routes on the public router
// behind AgentAuthMiddleware — the caller authenticates with its OWN access
// token and can only attest its own identity.
func (a *API) registerCodeAgentAttestRoute(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "attest-code-agent",
		Method:      http.MethodPost,
		Path:        "/code-agents/{id}/attest",
		Summary:     "Record fresh attestation evidence for the calling code agent",
		Tags:        []string{"Code Agents"},
	}, a.attestCodeAgentOp)
}

// registerCodeAgentAdminRoutes registers the operator surfaces on the admin
// router (tenant from X-Account-ID/X-Project-ID headers).
func (a *API) registerCodeAgentAdminRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "revoke-code-agents-by-machine",
		Method:      http.MethodPost,
		Path:        "/code-agents/by-machine/{machine_id}/revoke",
		Summary:     "Revoke every active code agent bootstrapped from a machine (lost/compromised laptop response)",
		Tags:        []string{"Code Agents"},
	}, a.revokeCodeAgentsByMachineOp)

	huma.Register(api, huma.Operation{
		OperationID: "list-code-agents-by-developer",
		Method:      http.MethodGet,
		Path:        "/code-agents/by-developer/{user_id}",
		Summary:     "List every bootstrapped code agent owned by a developer",
		Tags:        []string{"Code Agents"},
	}, a.listCodeAgentsByDeveloperOp)
}

// ── Handlers ─────────────────────────────────────────────────────────────────

func (a *API) bootstrapCodeAgentOp(ctx context.Context, input *BootstrapCodeAgentInput) (*BootstrapCodeAgentOutput, error) {
	claims, ok := internalMiddleware.GetBootstrapClaims(ctx)
	if !ok || claims.UserID == "" {
		return nil, huma.Error401Unauthorized("missing or invalid bootstrap token")
	}

	// Attribute the registration to the developer in the audit trail (this
	// endpoint runs outside TenantContextMiddleware, so caller_name is
	// otherwise unset).
	ctx = internalMiddleware.SetCallerName(ctx, claims.UserID)

	resp, err := a.agentSvc.RegisterCodeAgentFromBootstrap(ctx, service.CodeAgentBootstrapRequest{
		AccountID:    claims.AccountID,
		ProjectID:    claims.ProjectID,
		OwnerUserID:  claims.UserID,
		Framework:    input.Body.Framework,
		MachineID:    input.Body.MachineID,
		SubType:      domain.SubType(input.Body.SubType),
		PublicKeyPEM: input.Body.PublicKeyPEM,
		Name:         input.Body.Name,
	})
	if err != nil {
		// This machine's agent is still active and already has a key: refuse
		// to swap it from a bootstrap token (INV-IDN-004). Actionable 409.
		// (A REVOKED machine is not an error here — the service mints a fresh
		// identity and returns 201.)
		if errors.Is(err, service.ErrCodeAgentAlreadyBootstrapped) {
			return nil, huma.Error409Conflict(
				"this machine already has an active code agent with an enrolled key; rotate the key via the key-change (proof-of-possession) endpoint, or revoke this machine and bootstrap again",
				&huma.ErrorDetail{Location: "body.machine_id", Value: input.Body.MachineID},
			)
		}
		if errors.Is(err, service.ErrIdentityAlreadyExists) {
			return nil, huma.Error409Conflict("a code agent for this machine already exists and belongs to another developer")
		}
		if errors.Is(err, service.ErrInvalidIdentityField) {
			return nil, huma.Error400BadRequest(err.Error())
		}
		return nil, mapErr(err)
	}

	return &BootstrapCodeAgentOutput{Body: resp}, nil
}

// maxAttestationEvidenceBytes bounds the opaque attestation document so an
// agent owner can't store megabytes of arbitrary JSON per agent under the
// global 10 MiB body cap. 64 KiB is generous for runtime-environment facts.
const maxAttestationEvidenceBytes = 64 * 1024

func (a *API) attestCodeAgentOp(ctx context.Context, input *AttestCodeAgentInput) (*AttestCodeAgentOutput, error) {
	claims, ok := internalMiddleware.GetAgentClaims(ctx)
	if !ok || claims.Subject == "" {
		return nil, huma.Error401Unauthorized("missing or invalid agent token")
	}

	if len(input.Body.Evidence) > maxAttestationEvidenceBytes {
		return nil, huma.Error422UnprocessableEntity(fmt.Sprintf(
			"attestation evidence exceeds %d bytes", maxAttestationEvidenceBytes))
	}

	// The caller may only attest ITSELF. Access tokens carry the identity's
	// WIMSE URI as sub (and identity_id only when a deployment injects it),
	// so resolve the path id within the caller's tenant and require the
	// caller's subject to match. A cross-tenant id never resolves (tenant
	// scoping), which surfaces as 404 rather than leaking existence.
	if claims.IdentityID != "" && claims.IdentityID != input.ID {
		return nil, huma.Error403Forbidden("a code agent may only attest its own identity")
	}
	identity, err := a.identitySvc.GetIdentity(ctx, input.ID, claims.AccountID, claims.ProjectID)
	if err != nil {
		return nil, mapErr(err)
	}
	if identity.WIMSEURI != claims.Subject {
		return nil, huma.Error403Forbidden("a code agent may only attest its own identity")
	}

	// Attribute the attestation to the agent itself in the audit trail.
	ctx = internalMiddleware.SetCallerName(ctx, claims.Subject)

	attestedAt, err := a.agentSvc.RecordCodeAgentAttestation(ctx, input.ID, claims.AccountID, claims.ProjectID, input.Body.Evidence)
	if err != nil {
		return nil, mapErr(err)
	}

	out := &AttestCodeAgentOutput{}
	out.Body.LastAttestedAt = attestedAt
	return out, nil
}

func (a *API) revokeCodeAgentsByMachineOp(ctx context.Context, input *RevokeCodeAgentsByMachineInput) (*RevokeCodeAgentsByMachineOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	revoked, err := a.agentSvc.RevokeCodeAgentsByMachine(ctx, tenant.AccountID, tenant.ProjectID, input.MachineID, input.Body.OwnerUserID)
	if err != nil {
		return nil, mapErr(err)
	}

	out := &RevokeCodeAgentsByMachineOutput{}
	out.Body.Revoked = revoked
	return out, nil
}

func (a *API) listCodeAgentsByDeveloperOp(ctx context.Context, input *ListCodeAgentsByDeveloperInput) (*ListCodeAgentsByDeveloperOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	agents, err := a.agentSvc.ListCodeAgentsByDeveloper(ctx, tenant.AccountID, tenant.ProjectID, input.UserID)
	if err != nil {
		return nil, mapErr(err)
	}

	out := &ListCodeAgentsByDeveloperOutput{}
	out.Body.CodeAgents = agents
	return out, nil
}
