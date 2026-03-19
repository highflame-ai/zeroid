package handler

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/rs/zerolog/log"

	internalMiddleware "github.com/highflame-ai/zeroid/internal/middleware"
	"github.com/highflame-ai/zeroid/internal/service"
)

// ── Proof types ──────────────────────────────────────────────────────────────

type GenerateProofInput struct {
	Body struct {
		IdentityID string `json:"identity_id" required:"true" minLength:"1" doc:"UUID of the agent identity"`
		Audience   string `json:"audience" required:"true" minLength:"1" doc:"Intended audience for the proof token"`
		Nonce      string `json:"nonce,omitempty" doc:"Optional nonce for replay prevention"`
	}
}

type GenerateProofOutput struct {
	Body struct {
		ProofToken string `json:"proof_token" doc:"Signed WIMSE Proof Token (WPT)"`
		TokenType  string `json:"token_type" doc:"Token type identifier"`
		ExpiresIn  int    `json:"expires_in" doc:"Token lifetime in seconds"`
	}
}

type VerifyProofInput struct {
	Body struct {
		ProofToken string `json:"proof_token" required:"true" minLength:"1" doc:"WIMSE Proof Token to verify"`
		Audience   string `json:"audience" required:"true" minLength:"1" doc:"Expected audience"`
	}
}

type VerifyProofOutput struct {
	Body struct {
		Valid   bool   `json:"valid" doc:"Whether the proof token is valid"`
		Subject string `json:"subject" doc:"Subject (WIMSE URI) from the verified token"`
	}
}

// ── Proof routes ─────────────────────────────────────────────────────────────

// registerProofGenerateRoute registers the proof generation endpoint (requires agent-auth).
func (a *API) registerProofGenerateRoute(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "generate-proof",
		Method:      http.MethodPost,
		Path:        "/api/v1/proof/generate",
		Summary:     "Generate a WIMSE Proof Token for an agent identity",
		Tags:        []string{"Proof Tokens"},
	}, a.generateProofOp)
}

// registerProofVerifyRoute registers the proof verification endpoint (management auth).
func (a *API) registerProofVerifyRoute(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "verify-proof",
		Method:      http.MethodPost,
		Path:        "/api/v1/proof/verify",
		Summary:     "Verify a WIMSE Proof Token",
		Tags:        []string{"Proof Tokens"},
	}, a.verifyProofOp)
}

func (a *API) generateProofOp(ctx context.Context, input *GenerateProofInput) (*GenerateProofOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	identity, err := a.identitySvc.GetIdentity(ctx, input.Body.IdentityID, tenant.AccountID, tenant.ProjectID)
	if err != nil {
		return nil, huma.Error404NotFound("identity not found")
	}

	proofToken, err := a.proofSvc.GenerateProofToken(ctx, identity, input.Body.Audience, input.Body.Nonce)
	if err != nil {
		log.Error().Err(err).Str("identity_id", input.Body.IdentityID).Msg("failed to generate proof token")
		return nil, huma.Error500InternalServerError("failed to generate proof token")
	}

	out := &GenerateProofOutput{}
	out.Body.ProofToken = proofToken
	out.Body.TokenType = "WIMSE-Proof"
	out.Body.ExpiresIn = 300
	return out, nil
}

func (a *API) verifyProofOp(ctx context.Context, input *VerifyProofInput) (*VerifyProofOutput, error) {
	token, err := a.proofSvc.VerifyProofToken(ctx, input.Body.ProofToken, input.Body.Audience)
	if err != nil {
		if errors.Is(err, service.ErrNonceReplayed) {
			return nil, huma.Error401Unauthorized("proof token has already been used")
		}
		log.Warn().Err(err).Msg("Proof token verification failed")
		return nil, huma.Error401Unauthorized("proof token verification failed")
	}

	out := &VerifyProofOutput{}
	out.Body.Valid = true
	out.Body.Subject = token.Subject()
	return out, nil
}
