package handler

import (
	"net/http"

	gojson "github.com/goccy/go-json"
	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
)

// respondWithJSON writes a JSON-encoded payload with the given HTTP status.
// Used for raw chi endpoints (SSE, well-known) that bypass Huma.
func respondWithJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := gojson.NewEncoder(w).Encode(payload); err != nil {
		log.Error().Err(err).Int("status", status).Msg("Failed to encode JSON response")
	}
}

// respondWithError writes a structured error JSON response.
func respondWithError(w http.ResponseWriter, status int, internalCode, message string) {
	errResp := domain.NewErrorResponse(status, internalCode, message)
	respondWithJSON(w, status, errResp)
}

// respondNotImplemented returns a 501 stub response.
func respondNotImplemented(w http.ResponseWriter) {
	respondWithError(w, http.StatusNotImplemented, domain.ErrCodeNotImplemented, "not yet implemented")
}
