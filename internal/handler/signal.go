package handler

import (
	"context"
	"fmt"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5"
	gojson "github.com/goccy/go-json"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
	internalMiddleware "github.com/highflame-ai/zeroid/internal/middleware"
)

// ── Signal types ────────────────────────────────────────────────────────────

type IngestSignalInput struct {
	Body struct {
		IdentityID string         `json:"identity_id,omitempty" doc:"UUID of the agent identity"`
		SignalType string         `json:"signal_type" required:"true" minLength:"1" doc:"Signal type"`
		Severity   string         `json:"severity,omitempty" enum:"low,medium,high,critical" doc:"Signal severity"`
		Source     string         `json:"source" required:"true" minLength:"1" doc:"Signal source"`
		Payload    map[string]any `json:"payload,omitempty" doc:"Arbitrary signal payload"`
	}
}

type SignalOutput struct {
	Body *domain.CAESignal
}

type SignalListInput struct {
	Limit int `query:"limit" default:"50" minimum:"1" maximum:"500" doc:"Maximum number of signals to return"`
}

type SignalListOutput struct {
	Body struct {
		Signals []*domain.CAESignal `json:"signals"`
		Total   int                 `json:"total"`
	}
}

// ── Signal routes ───────────────────────────────────────────────────────────

func (a *API) registerSignalRoutes(api huma.API, router chi.Router) {
	huma.Register(api, huma.Operation{
		OperationID:   "ingest-signal",
		Method:        http.MethodPost,
		Path:          "/api/v1/signals/ingest",
		Summary:       "Ingest a CAE signal",
		Tags:          []string{"Signals"},
		DefaultStatus: http.StatusCreated,
	}, a.ingestSignalOp)

	huma.Register(api, huma.Operation{
		OperationID: "list-signals",
		Method:      http.MethodGet,
		Path:        "/api/v1/signals",
		Summary:     "List recent signals",
		Tags:        []string{"Signals"},
	}, a.listSignalsOp)

	// SSE streaming stays on raw chi — Huma doesn't support streaming responses.
	router.Get("/api/v1/signals/stream", a.streamSignalsHandler)
}

func (a *API) ingestSignalOp(ctx context.Context, input *IngestSignalInput) (*SignalOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	severity := domain.SignalSeverity(input.Body.Severity)
	if severity == "" {
		severity = domain.SignalSeverityLow
	} else if !severity.Valid() {
		return nil, huma.Error400BadRequest("invalid severity: must be low, medium, high, or critical")
	}

	signalType := domain.SignalType(input.Body.SignalType)
	if !signalType.Valid() {
		return nil, huma.Error400BadRequest("invalid signal_type")
	}

	signal, err := a.signalSvc.IngestSignal(
		ctx,
		tenant.AccountID,
		tenant.ProjectID,
		input.Body.IdentityID,
		signalType,
		severity,
		input.Body.Source,
		input.Body.Payload,
	)
	if err != nil {
		log.Error().Err(err).Str("signal_type", input.Body.SignalType).Msg("failed to ingest signal")
		return nil, huma.Error500InternalServerError("failed to ingest signal")
	}

	return &SignalOutput{Body: signal}, nil
}

func (a *API) listSignalsOp(ctx context.Context, input *SignalListInput) (*SignalListOutput, error) {
	tenant, err := internalMiddleware.GetTenant(ctx)
	if err != nil {
		return nil, huma.Error401Unauthorized("missing tenant context")
	}

	limit := input.Limit
	if limit == 0 {
		limit = 50
	}

	signals, err := a.signalSvc.ListSignals(ctx, tenant.AccountID, tenant.ProjectID, limit)
	if err != nil {
		log.Error().Err(err).Msg("failed to list signals")
		return nil, huma.Error500InternalServerError("failed to list signals")
	}

	if signals == nil {
		signals = []*domain.CAESignal{}
	}
	out := &SignalListOutput{}
	out.Body.Signals = signals
	out.Body.Total = len(signals)
	return out, nil
}

// streamSignalsHandler is a raw chi handler for Server-Sent Events.
func (a *API) streamSignalsHandler(w http.ResponseWriter, r *http.Request) {
	tenant, err := internalMiddleware.GetTenant(r.Context())
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, domain.ErrCodeUnauthorized, "missing tenant context")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	flusher, ok := w.(http.Flusher)
	if !ok {
		respondWithError(w, http.StatusInternalServerError, domain.ErrCodeInternal, "streaming not supported")
		return
	}

	subscriberID := fmt.Sprintf("%s:%s:%s", tenant.AccountID, tenant.ProjectID, uuid.New().String())
	ch := a.signalSvc.Subscribe(subscriberID)
	defer a.signalSvc.Unsubscribe(subscriberID)

	_, _ = fmt.Fprintf(w, "event: connected\ndata: {}\n\n")
	flusher.Flush()

	for {
		select {
		case signal, ok := <-ch:
			if !ok {
				return
			}
			data, err := gojson.Marshal(signal)
			if err != nil {
				log.Error().Err(err).Msg("SSE: failed to marshal signal")
				continue
			}
			_, _ = fmt.Fprintf(w, "event: signal\ndata: %s\n\n", string(data))
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
