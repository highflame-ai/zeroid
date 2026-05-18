package handler

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	internalMiddleware "github.com/highflame-ai/zeroid/internal/middleware"
	"github.com/highflame-ai/zeroid/internal/service"
)

// ── Workload-attested ephemeral signing credentials ──────────────────────────
//
// Attest + revoke are ADMIN routes. ZeroID's admin surface performs no
// authentication of its own: it is operator-protected at the network
// layer (separate port, not externally exposed; VPN / service mesh /
// reverse proxy, or the deployer's optional admin-auth hook) — see
// TenantContextMiddleware. Authorization within that surface is tenant
// isolation: every read/write is scoped to the (account_id, project_id)
// derived from the validated tenant context (GetTenant, fail-closed),
// exactly like every other ZeroID admin handler. `X-Internal-Service` is
// a logical workload label (e.g. which signer attested this key) that is
// only ever trusted within an already tenant-scoped, operator-protected
// request — never as a standalone cross-tenant principal. The
// verification JWKS is a PUBLIC route: offline verification by any party
// is the point, and only non-secret public keys, keyed by a globally
// unique kid, are exposed.

type attestSigningKeyInput struct {
	Workload string `header:"X-Internal-Service" doc:"Attesting workload label (tenant-scoped)"`
	Body     struct {
		PublicKey  string `json:"public_key"  doc:"base64url Ed25519 public key (32 bytes)"`
		Algorithm  string `json:"algorithm"   doc:"EdDSA"`
		Purpose    string `json:"purpose"     doc:"one of the deployment's configured signing purposes"`
		TTLSeconds int    `json:"ttl_seconds" doc:"requested operational signing window"`
	}
}

type attestSigningKeyOutput struct {
	Body service.AttestResult
}

type revokeSigningKeyInput struct {
	KID      string `path:"kid"`
	Workload string `header:"X-Internal-Service"`
	Body     struct {
		Reason string `json:"reason,omitempty"`
	}
}

type revokeSigningKeyOutput struct {
	Body struct {
		KID     string `json:"kid"`
		Revoked bool   `json:"revoked"`
	}
}

type signingJWKSOutput struct {
	Body *service.JWKS
}

func (a *API) registerSigningCredentialRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "attest-signing-credential",
		Method:      http.MethodPost,
		Path:        "/signing-credentials",
		Summary:     "Attest a workload's ephemeral signing public key",
		Tags:        []string{"Attestation"},
	}, a.attestSigningKeyOp)

	huma.Register(api, huma.Operation{
		OperationID: "revoke-signing-credential",
		Method:      http.MethodPost,
		Path:        "/signing-credentials/{kid}/revoke",
		Summary:     "Revoke an attested signing credential (CAE / manual)",
		Tags:        []string{"Attestation"},
	}, a.revokeSigningKeyOp)
}

// registerSigningJWKSRoute is PUBLIC (no auth) — the verification JWKS is
// meant to be fetched unauthenticated for offline verification. The path
// is deployer-configured (SigningCredsConfig.WellKnownJWKSName); the
// route is only registered when a JWKS purpose is configured, so a
// default product-agnostic ZeroID exposes nothing here.
func (a *API) registerSigningJWKSRoute(api huma.API) {
	if !a.signingCredSvc.JWKSEnabled() {
		return
	}

	huma.Register(api, huma.Operation{
		OperationID: "signing-credential-jwks",
		Method:      http.MethodGet,
		Path:        a.signingCredSvc.WellKnownPath(),
		Summary:     "Workload-attested signing verification JWKS (non-revoked, audit-retained)",
		Tags:        []string{"Discovery"},
	}, a.signingJWKSOp)
}

func (a *API) attestSigningKeyOp(ctx context.Context, in *attestSigningKeyInput) (*attestSigningKeyOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	if in.Workload == "" {
		return nil, huma.Error401Unauthorized("caller is not a trusted internal service")
	}

	res, err := a.signingCredSvc.Attest(ctx, service.AttestRequest{
		Workload:   in.Workload,
		AccountID:  tenant.AccountID,
		ProjectID:  tenant.ProjectID,
		PublicKey:  in.Body.PublicKey,
		Algorithm:  in.Body.Algorithm,
		Purpose:    in.Body.Purpose,
		TTLSeconds: in.Body.TTLSeconds,
	})
	if err != nil {
		if errors.Is(err, service.ErrSigningCredInvalid) {
			return nil, huma.Error400BadRequest(err.Error())
		}

		return nil, huma.Error500InternalServerError("failed to attest signing credential")
	}

	return &attestSigningKeyOutput{Body: *res}, nil
}

func (a *API) revokeSigningKeyOp(ctx context.Context, in *revokeSigningKeyInput) (*revokeSigningKeyOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	if in.Workload == "" {
		return nil, huma.Error401Unauthorized("caller is not a trusted internal service")
	}

	revoked, err := a.signingCredSvc.RevokeKID(ctx, in.KID, in.Workload, tenant.AccountID, tenant.ProjectID, in.Body.Reason)
	if err != nil {
		return nil, huma.Error500InternalServerError("failed to revoke signing credential")
	}

	if !revoked {
		return nil, huma.Error404NotFound("no active credential with that kid for this workload")
	}

	out := &revokeSigningKeyOutput{}
	out.Body.KID = in.KID
	out.Body.Revoked = true

	return out, nil
}

func (a *API) signingJWKSOp(ctx context.Context, _ *struct{}) (*signingJWKSOutput, error) {
	set, err := a.signingCredSvc.VerificationJWKS(ctx)
	if err != nil {
		return nil, huma.Error500InternalServerError("failed to build verification JWKS")
	}

	return &signingJWKSOutput{Body: set}, nil
}
