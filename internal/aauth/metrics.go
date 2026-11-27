package aauth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/highflame-ai/zeroid/internal/telemetry"
)

// observed counts every response of an Agent Provider endpoint in
// zeroid.aauth.requests, by outcome and error code, read off the response
// itself so no handler path can be missed.
func observed(endpoint string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rec := &responseRecorder{ResponseWriter: w, status: http.StatusOK}
		h(rec, r)
		outcome, code := classify(rec)
		telemetry.AAuthRequests.Add(r.Context(), 1, metric.WithAttributes(
			attribute.String("endpoint", endpoint),
			attribute.String("outcome", outcome),
			attribute.String("code", code),
		))
	}
}

func classify(rec *responseRecorder) (outcome, code string) {
	switch {
	case rec.status == http.StatusOK:
		return "issued", ""
	case rec.status == http.StatusUnauthorized:
		// Signature-Error: error=<code>[, ...]
		v := rec.Header().Get(HeaderSignatureError)
		if _, after, ok := strings.Cut(v, "error="); ok {
			code, _, _ = strings.Cut(after, ",")
		}
		return "signature_error", strings.TrimSpace(code)
	}
	var body struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(rec.body.Bytes(), &body)
	switch {
	case rec.status == http.StatusTooManyRequests:
		return "rate_limited", body.Error
	case rec.status >= 500:
		return "error", body.Error
	}
	return "refused", body.Error
}

// responseRecorder keeps the status and the start of the body (an error
// body is a few hundred bytes) while writing through.
type responseRecorder struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
}

func (r *responseRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	if room := 4096 - r.body.Len(); room > 0 {
		r.body.Write(b[:min(len(b), room)])
	}
	return r.ResponseWriter.Write(b)
}
