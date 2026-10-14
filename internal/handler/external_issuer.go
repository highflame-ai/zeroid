package handler

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
	internalMiddleware "github.com/highflame-ai/zeroid/internal/middleware"
	"github.com/highflame-ai/zeroid/internal/service"
)

// Trusted issuers and credential bindings (ADR 0042 D4, D4a, D6). The
// account is always the caller's tenant; another account's rows are 404.
// The contract is docs/external-issuers.md.

// SetExternalIssuerService wires the /external-issuers routes.
func (a *API) SetExternalIssuerService(svc *service.ExternalIssuerService) {
	a.externalIssuerSvc = svc
}

// issuerProblem is an RFC 9457 problem with a stable machine-readable code.
type issuerProblem struct {
	Status int    `json:"status"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
	Code   string `json:"code"`
}

func (e *issuerProblem) Error() string  { return e.Detail }
func (e *issuerProblem) GetStatus() int { return e.Status }

func issuerProblemFrom(err error, what string) error {
	var apiErr *service.IssuerAPIError
	if errors.As(err, &apiErr) {
		return &issuerProblem{Status: apiErr.Status, Title: http.StatusText(apiErr.Status), Detail: apiErr.Message, Code: apiErr.Code}
	}
	log.Error().Err(err).Msg("external issuer admin request failed: " + what)
	return &issuerProblem{Status: http.StatusInternalServerError, Title: http.StatusText(http.StatusInternalServerError),
		Detail: "failed to " + what, Code: "internal_error"}
}

func issuerTenant(ctx context.Context) (string, string, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return "", "", &issuerProblem{Status: http.StatusUnauthorized, Title: "Unauthorized", Detail: "missing tenant context", Code: "unauthorized"}
	}
	return tenant.AccountID, internalMiddleware.GetCallerName(ctx), nil
}

// ── Types ────────────────────────────────────────────────────────────────────

// ExternalIssuerCreateBody is POST /external-issuers.
type ExternalIssuerCreateBody struct {
	Preset              string              `json:"preset,omitempty" enum:"entra,okta,generic" doc:"Check the issuer's shape and fill IdP-fixed fields: entra (RS256, user key oid, email_verified from xms_edov, tid pinned) or okta (RS256, user key sub). Never overrides a field the request sets. jwks_uri always comes from the issuer's discovery document. Neither needs audiences: bind each agent's app id instead."`
	Kind                string              `json:"kind" enum:"person,workload" doc:"person: an IdP whose ID-JAGs and ID tokens name people. workload: a client-assertion issuer."`
	Issuer              string              `json:"issuer" doc:"The iss value tokens carry, matched exactly. https. Its {issuer}/.well-known/openid-configuration must name this issuer and the jwks_uri ZeroID uses."`
	DisplayName         string              `json:"display_name,omitempty"`
	Audiences           []string            `json:"audiences,omitempty" doc:"Optional on a person row, required on a workload row. Extra accepted aud values: on the ID-token exchange an enabled binding already admits the presenting client's client_id, and an ID-JAG's aud must be ZeroID's issuer."`
	Algorithms          []string            `json:"algorithms,omitempty" doc:"Subset of RS256, ES256, PS256. Default all three."`
	ClaimMapping        map[string]string   `json:"claim_mapping,omitempty" doc:"ZeroID name to token claim. user_id (the person's user key, required for person), email, email_verified, name, role, privilege_scope, scope, trust_level."`
	PropagateClaims     []string            `json:"propagate_claims,omitempty" doc:"Subset of auth_time, acr, amr."`
	ClaimConstraints    map[string][]string `json:"claim_constraints,omitempty" doc:"claim to accepted values; every listed claim must match. Required for a shared issuer."`
	MaxTokenAgeSeconds  int                 `json:"max_token_age_seconds,omitempty" doc:"1-3600, default 600."`
	JWKSCacheTTLSeconds int                 `json:"jwks_cache_ttl_seconds,omitempty" doc:"30-86400, default 300."`
	Source              string              `json:"source,omitempty" enum:"admin,connector" doc:"Default admin."`
	SourceRef           string              `json:"source_ref,omitempty" doc:"The connector that created the row; only with source connector."`
	Enabled             *bool               `json:"enabled,omitempty" doc:"Default true."`
}

// ExternalIssuerPatchBody is PATCH /external-issuers/{id}. Absent fields are
// unchanged; issuer, kind and source never change.
type ExternalIssuerPatchBody struct {
	DisplayName         *string              `json:"display_name,omitempty"`
	Audiences           *[]string            `json:"audiences,omitempty"`
	Algorithms          *[]string            `json:"algorithms,omitempty"`
	ClaimMapping        *map[string]string   `json:"claim_mapping,omitempty"`
	PropagateClaims     *[]string            `json:"propagate_claims,omitempty"`
	ClaimConstraints    *map[string][]string `json:"claim_constraints,omitempty"`
	MaxTokenAgeSeconds  *int                 `json:"max_token_age_seconds,omitempty"`
	JWKSCacheTTLSeconds *int                 `json:"jwks_cache_ttl_seconds,omitempty"`
	Enabled             *bool                `json:"enabled,omitempty"`
}

// ExternalIssuerView is an issuer row, with the JWKS probe made by the write
// when there was one.
type ExternalIssuerView struct {
	ID                  string              `json:"id"`
	AccountID           string              `json:"account_id"`
	Issuer              string              `json:"issuer"`
	Kind                string              `json:"kind"`
	DisplayName         string              `json:"display_name"`
	JWKSURI             string              `json:"jwks_uri"`
	Audiences           []string            `json:"audiences"`
	Algorithms          []string            `json:"algorithms"`
	ClaimMapping        map[string]string   `json:"claim_mapping"`
	PropagateClaims     []string            `json:"propagate_claims"`
	ClaimConstraints    map[string][]string `json:"claim_constraints"`
	MaxTokenAgeSeconds  int                 `json:"max_token_age_seconds"`
	JWKSCacheTTLSeconds int                 `json:"jwks_cache_ttl_seconds"`
	Source              string              `json:"source"`
	SourceRef           string              `json:"source_ref"`
	Enabled             bool                `json:"enabled"`
	CreatedBy           string              `json:"created_by"`
	UpdatedBy           string              `json:"updated_by"`
	CreatedAt           time.Time           `json:"created_at"`
	UpdatedAt           time.Time           `json:"updated_at"`
	JWKSCheck           *service.JWKSCheck  `json:"jwks_check,omitempty"`
}

func issuerView(r *domain.ExternalIssuer, check *service.JWKSCheck) ExternalIssuerView {
	return ExternalIssuerView{
		ID: r.ID, AccountID: r.AccountID, Issuer: r.Issuer, Kind: string(r.Kind), DisplayName: r.DisplayName,
		JWKSURI: r.JWKSURI, Audiences: nonNil(r.Audiences), Algorithms: nonNil(r.Algorithms),
		ClaimMapping: r.ClaimMapping, PropagateClaims: nonNil(r.PropagateClaims), ClaimConstraints: r.ClaimConstraints,
		MaxTokenAgeSeconds: r.MaxTokenAgeSeconds, JWKSCacheTTLSeconds: r.JWKSCacheTTLSeconds,
		Source: string(r.Source), SourceRef: r.SourceRef, Enabled: r.Enabled,
		CreatedBy: r.CreatedBy, UpdatedBy: r.UpdatedBy, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
		JWKSCheck: check,
	}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

type externalIssuerOutput struct {
	Body ExternalIssuerView
}

type externalIssuerListOutput struct {
	Body struct {
		IssuerStore string               `json:"issuer_store" doc:"db: rows are writable. config: static entries, read-only (source config)."`
		Items       []ExternalIssuerView `json:"items"`
	}
}

type externalIssuerIDInput struct {
	ID string `path:"id" doc:"Issuer row id"`
}

type externalIssuerCheckInput struct {
	Body struct {
		Issuer string `json:"issuer" doc:"The issuer to probe: its discovery document, then the key set it names."`
	}
}

type externalIssuerCheckOutput struct {
	Body *service.JWKSCheck
}

// BindingCreateBody is POST /external-issuers/{id}/bindings.
type BindingCreateBody struct {
	SubjectKey  string `json:"subject_key" doc:"The value the credential carries at runtime: the ID-JAG act.sub (P1b), the presenting client_id (P1c), the assertion sub (P2)."`
	IdentityID  string `json:"identity_id" doc:"An identity in this account."`
	Enabled     *bool  `json:"enabled,omitempty" doc:"Default true. A binding for an identity that is not active is created disabled."`
	OAuthClient *struct {
		ClientID string `json:"client_id,omitempty" doc:"Default subject_key."`
	} `json:"oauth_client,omitempty" doc:"Also create (or confirm) the OAuth client the agent presents: private_key_jwt with the identity's registered key, linked to the identity."`
}

// BindingView is a binding, with the presenting client when one was created
// or confirmed.
type BindingView struct {
	ID          string                       `json:"id"`
	AccountID   string                       `json:"account_id"`
	IssuerID    string                       `json:"issuer_id"`
	SubjectKey  string                       `json:"subject_key"`
	IdentityID  string                       `json:"identity_id"`
	Enabled     bool                         `json:"enabled"`
	CreatedBy   string                       `json:"created_by"`
	UpdatedBy   string                       `json:"updated_by"`
	CreatedAt   time.Time                    `json:"created_at"`
	UpdatedAt   time.Time                    `json:"updated_at"`
	OAuthClient *service.BindingClientResult `json:"oauth_client,omitempty"`
}

func bindingView(b *domain.IssuerBinding, client *service.BindingClientResult) BindingView {
	return BindingView{
		ID: b.ID, AccountID: b.AccountID, IssuerID: b.IssuerID, SubjectKey: b.SubjectKey, IdentityID: b.IdentityID,
		Enabled: b.Enabled, CreatedBy: b.CreatedBy, UpdatedBy: b.UpdatedBy, CreatedAt: b.CreatedAt, UpdatedAt: b.UpdatedAt,
		OAuthClient: client,
	}
}

type bindingOutput struct {
	Body BindingView
}

type bindingListOutput struct {
	Body struct {
		Items []BindingView `json:"items"`
	}
}

type bindingListInput struct {
	ID         string `path:"id" doc:"Issuer row id"`
	IdentityID string `query:"identity_id" doc:"Only this identity's bindings"`
}

type accountBindingListInput struct {
	IdentityID string `query:"identity_id" doc:"Only this identity's bindings"`
}

type bindingIDInput struct {
	ID        string `path:"id" doc:"Issuer row id"`
	BindingID string `path:"binding_id" doc:"Binding id"`
}

// ── Routes ───────────────────────────────────────────────────────────────────

func (a *API) registerExternalIssuerRoutes(api huma.API) {
	tags := []string{"External Issuers"}
	huma.Register(api, huma.Operation{OperationID: "list-external-issuers", Method: http.MethodGet,
		Path: "/external-issuers", Summary: "List the account's trusted issuers", Tags: tags}, a.listExternalIssuersOp)
	huma.Register(api, huma.Operation{OperationID: "create-external-issuer", Method: http.MethodPost,
		Path: "/external-issuers", Summary: "Trust an issuer for the account", Tags: tags,
		DefaultStatus: http.StatusCreated}, a.createExternalIssuerOp)
	huma.Register(api, huma.Operation{OperationID: "check-external-issuer-jwks", Method: http.MethodPost,
		Path: "/external-issuers/check", Summary: "Probe an issuer's JWKS", Tags: tags}, a.checkExternalIssuerOp)
	huma.Register(api, huma.Operation{OperationID: "get-external-issuer", Method: http.MethodGet,
		Path: "/external-issuers/{id}", Summary: "Get a trusted issuer", Tags: tags}, a.getExternalIssuerOp)
	huma.Register(api, huma.Operation{OperationID: "update-external-issuer", Method: http.MethodPatch,
		Path: "/external-issuers/{id}", Summary: "Update a trusted issuer", Tags: tags}, a.updateExternalIssuerOp)
	huma.Register(api, huma.Operation{OperationID: "refresh-external-issuer", Method: http.MethodPost,
		Path: "/external-issuers/{id}/refresh", Summary: "Re-read an issuer's discovery document and keys", Tags: tags}, a.refreshExternalIssuerOp)
	huma.Register(api, huma.Operation{OperationID: "delete-external-issuer", Method: http.MethodDelete,
		Path: "/external-issuers/{id}", Summary: "Stop trusting an issuer", Tags: tags,
		DefaultStatus: http.StatusNoContent}, a.deleteExternalIssuerOp)

	huma.Register(api, huma.Operation{OperationID: "list-account-issuer-bindings", Method: http.MethodGet,
		Path: "/external-issuers/bindings", Summary: "List the account's credential bindings across issuers", Tags: tags}, a.listAccountBindingsOp)
	huma.Register(api, huma.Operation{OperationID: "list-issuer-bindings", Method: http.MethodGet,
		Path: "/external-issuers/{id}/bindings", Summary: "List an issuer's credential bindings", Tags: tags}, a.listBindingsOp)
	huma.Register(api, huma.Operation{OperationID: "create-issuer-binding", Method: http.MethodPost,
		Path: "/external-issuers/{id}/bindings", Summary: "Bind a credential subject to an identity", Tags: tags,
		DefaultStatus: http.StatusCreated}, a.createBindingOp)
	huma.Register(api, huma.Operation{OperationID: "get-issuer-binding", Method: http.MethodGet,
		Path: "/external-issuers/{id}/bindings/{binding_id}", Summary: "Get a credential binding", Tags: tags}, a.getBindingOp)
	huma.Register(api, huma.Operation{OperationID: "update-issuer-binding", Method: http.MethodPatch,
		Path: "/external-issuers/{id}/bindings/{binding_id}", Summary: "Enable or disable a credential binding", Tags: tags}, a.updateBindingOp)
	huma.Register(api, huma.Operation{OperationID: "delete-issuer-binding", Method: http.MethodDelete,
		Path: "/external-issuers/{id}/bindings/{binding_id}", Summary: "Delete a credential binding", Tags: tags,
		DefaultStatus: http.StatusNoContent}, a.deleteBindingOp)
}

func (a *API) listExternalIssuersOp(ctx context.Context, _ *struct{}) (*externalIssuerListOutput, error) {
	account, _, err := issuerTenant(ctx)
	if err != nil {
		return nil, err
	}
	items, err := a.externalIssuerSvc.List(ctx, account)
	if err != nil {
		return nil, issuerProblemFrom(err, "list external issuers")
	}
	out := &externalIssuerListOutput{}
	out.Body.IssuerStore = string(a.externalIssuerSvc.Store())
	out.Body.Items = make([]ExternalIssuerView, 0, len(items))
	for _, r := range items {
		out.Body.Items = append(out.Body.Items, issuerView(r, nil))
	}
	return out, nil
}

func (a *API) createExternalIssuerOp(ctx context.Context, input *struct {
	Body ExternalIssuerCreateBody
}) (*externalIssuerOutput, error) {
	account, actor, err := issuerTenant(ctx)
	if err != nil {
		return nil, err
	}
	b := input.Body
	row, check, err := a.externalIssuerSvc.Create(ctx, account, actor, service.IssuerInput{
		Preset: b.Preset, Kind: domain.IssuerKind(b.Kind), Issuer: b.Issuer, DisplayName: b.DisplayName,
		Audiences: b.Audiences, Algorithms: b.Algorithms, ClaimMapping: b.ClaimMapping,
		PropagateClaims: b.PropagateClaims, ClaimConstraints: b.ClaimConstraints,
		MaxTokenAge: b.MaxTokenAgeSeconds, JWKSCacheTTL: b.JWKSCacheTTLSeconds,
		Source: domain.IssuerSource(b.Source), SourceRef: b.SourceRef, Enabled: b.Enabled,
	})
	if err != nil {
		return nil, issuerProblemFrom(err, "create external issuer")
	}
	return &externalIssuerOutput{Body: issuerView(row, check)}, nil
}

func (a *API) checkExternalIssuerOp(ctx context.Context, input *externalIssuerCheckInput) (*externalIssuerCheckOutput, error) {
	if _, _, err := issuerTenant(ctx); err != nil {
		return nil, err
	}
	check, err := a.externalIssuerSvc.Check(ctx, input.Body.Issuer)
	if err != nil {
		return nil, issuerProblemFrom(err, "check external issuer")
	}
	return &externalIssuerCheckOutput{Body: check}, nil
}

func (a *API) getExternalIssuerOp(ctx context.Context, input *externalIssuerIDInput) (*externalIssuerOutput, error) {
	account, _, err := issuerTenant(ctx)
	if err != nil {
		return nil, err
	}
	row, err := a.externalIssuerSvc.Get(ctx, account, input.ID)
	if err != nil {
		return nil, issuerProblemFrom(err, "get external issuer")
	}
	return &externalIssuerOutput{Body: issuerView(row, nil)}, nil
}

func (a *API) updateExternalIssuerOp(ctx context.Context, input *struct {
	ID   string `path:"id"`
	Body ExternalIssuerPatchBody
}) (*externalIssuerOutput, error) {
	account, actor, err := issuerTenant(ctx)
	if err != nil {
		return nil, err
	}
	b := input.Body
	row, check, err := a.externalIssuerSvc.Update(ctx, account, input.ID, actor, service.IssuerPatch{
		DisplayName: b.DisplayName, Audiences: b.Audiences, Algorithms: b.Algorithms,
		ClaimMapping: b.ClaimMapping, PropagateClaims: b.PropagateClaims, ClaimConstraints: b.ClaimConstraints,
		MaxTokenAge: b.MaxTokenAgeSeconds, JWKSCacheTTL: b.JWKSCacheTTLSeconds, Enabled: b.Enabled,
	})
	if err != nil {
		return nil, issuerProblemFrom(err, "update external issuer")
	}
	return &externalIssuerOutput{Body: issuerView(row, check)}, nil
}

func (a *API) refreshExternalIssuerOp(ctx context.Context, input *externalIssuerIDInput) (*externalIssuerOutput, error) {
	account, actor, err := issuerTenant(ctx)
	if err != nil {
		return nil, err
	}
	row, check, err := a.externalIssuerSvc.Refresh(ctx, account, input.ID, actor)
	if err != nil {
		return nil, issuerProblemFrom(err, "refresh external issuer")
	}
	return &externalIssuerOutput{Body: issuerView(row, check)}, nil
}

func (a *API) deleteExternalIssuerOp(ctx context.Context, input *externalIssuerIDInput) (*struct{}, error) {
	account, actor, err := issuerTenant(ctx)
	if err != nil {
		return nil, err
	}
	if err := a.externalIssuerSvc.Delete(ctx, account, input.ID, actor); err != nil {
		return nil, issuerProblemFrom(err, "delete external issuer")
	}
	return nil, nil
}

func (a *API) listBindingsOp(ctx context.Context, input *bindingListInput) (*bindingListOutput, error) {
	account, _, err := issuerTenant(ctx)
	if err != nil {
		return nil, err
	}
	items, err := a.externalIssuerSvc.ListBindings(ctx, account, input.ID, input.IdentityID)
	if err != nil {
		return nil, issuerProblemFrom(err, "list bindings")
	}
	return bindingList(items), nil
}

func (a *API) listAccountBindingsOp(ctx context.Context, input *accountBindingListInput) (*bindingListOutput, error) {
	account, _, err := issuerTenant(ctx)
	if err != nil {
		return nil, err
	}
	items, err := a.externalIssuerSvc.ListAccountBindings(ctx, account, input.IdentityID)
	if err != nil {
		return nil, issuerProblemFrom(err, "list bindings")
	}
	return bindingList(items), nil
}

func bindingList(items []*domain.IssuerBinding) *bindingListOutput {
	out := &bindingListOutput{}
	out.Body.Items = make([]BindingView, 0, len(items))
	for _, b := range items {
		out.Body.Items = append(out.Body.Items, bindingView(b, nil))
	}
	return out
}

func (a *API) createBindingOp(ctx context.Context, input *struct {
	ID   string `path:"id"`
	Body BindingCreateBody
}) (*bindingOutput, error) {
	account, actor, err := issuerTenant(ctx)
	if err != nil {
		return nil, err
	}
	in := service.BindingInput{SubjectKey: input.Body.SubjectKey, IdentityID: input.Body.IdentityID, Enabled: input.Body.Enabled}
	if input.Body.OAuthClient != nil {
		in.Client = &service.BindingClientInput{ClientID: input.Body.OAuthClient.ClientID}
	}
	b, client, err := a.externalIssuerSvc.CreateBinding(ctx, account, input.ID, actor, in)
	if err != nil {
		return nil, issuerProblemFrom(err, "create binding")
	}
	return &bindingOutput{Body: bindingView(b, client)}, nil
}

func (a *API) getBindingOp(ctx context.Context, input *bindingIDInput) (*bindingOutput, error) {
	account, _, err := issuerTenant(ctx)
	if err != nil {
		return nil, err
	}
	b, err := a.externalIssuerSvc.GetBinding(ctx, account, input.ID, input.BindingID)
	if err != nil {
		return nil, issuerProblemFrom(err, "get binding")
	}
	return &bindingOutput{Body: bindingView(b, nil)}, nil
}

func (a *API) updateBindingOp(ctx context.Context, input *struct {
	ID        string `path:"id"`
	BindingID string `path:"binding_id"`
	Body      struct {
		Enabled bool `json:"enabled"`
	}
}) (*bindingOutput, error) {
	account, actor, err := issuerTenant(ctx)
	if err != nil {
		return nil, err
	}
	b, err := a.externalIssuerSvc.SetBindingEnabled(ctx, account, input.ID, input.BindingID, actor, input.Body.Enabled)
	if err != nil {
		return nil, issuerProblemFrom(err, "update binding")
	}
	return &bindingOutput{Body: bindingView(b, nil)}, nil
}

func (a *API) deleteBindingOp(ctx context.Context, input *bindingIDInput) (*struct{}, error) {
	account, actor, err := issuerTenant(ctx)
	if err != nil {
		return nil, err
	}
	if err := a.externalIssuerSvc.DeleteBinding(ctx, account, input.ID, input.BindingID, actor); err != nil {
		return nil, issuerProblemFrom(err, "delete binding")
	}
	return nil, nil
}
