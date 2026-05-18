package handler

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/highflame-ai/zeroid/internal/service"
)

// ── Workload-attested ephemeral signing credentials ──────────────────────────
//
// Attest + revoke are ADMIN routes: the deployer's admin-auth middleware
// (AuthN's InternalServiceAuth) only lets trusted internal services
// reach them and validates X-Internal-Service against the shared secret,
// so by the time these handlers run the caller is a proven trusted
// service and X-Internal-Service is its identity. The verification JWKS
// is a PUBLIC route — offline verification by any party is the point;
// only non-secret public keys are exposed.

type attestSigningKeyInput struct {
	Workload  string `header:"X-Internal-Service" doc:"Attesting workload (validated by admin auth)"`
	AccountID string `header:"X-Account-ID"`
	ProjectID string `header:"X-Project-ID"`
	Body      struct {
		PublicKey  string `json:"public_key"  doc:"base64url Ed25519 public key (32 bytes)"`
		Algorithm  string `json:"algorithm"   doc:"EdDSA"`
		Purpose    string `json:"purpose"     doc:"receipt | authz_audit"`
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

// registerSigningJWKSRoute is PUBLIC (no auth) — registered on the public
// group so AuthN exposes it unauthenticated for offline verification.
func (a *API) registerSigningJWKSRoute(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "receipt-jwks",
		Method:      http.MethodGet,
		Path:        "/.well-known/highflame-receipt-keys",
		Summary:     "Receipt verification JWKS (non-revoked, audit-retained)",
		Tags:        []string{"Discovery"},
	}, a.signingJWKSOp)
}

func (a *API) attestSigningKeyOp(ctx context.Context, in *attestSigningKeyInput) (*attestSigningKeyOutput, error) {
	res, err := a.signingCredSvc.Attest(ctx, service.AttestRequest{
		Workload:   in.Workload,
		AccountID:  in.AccountID,
		ProjectID:  in.ProjectID,
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
	if in.Workload == "" {
		return nil, huma.Error401Unauthorized("caller is not a trusted internal service")
	}

	revoked, err := a.signingCredSvc.RevokeKID(ctx, in.KID, in.Workload, in.Body.Reason)
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
	set, err := a.signingCredSvc.VerificationJWKS(ctx, "receipt")
	if err != nil {
		return nil, huma.Error500InternalServerError("failed to build receipt JWKS")
	}

	return &signingJWKSOutput{Body: set}, nil
}
