package aauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestObservedClassifiesResponses(t *testing.T) {
	cases := []struct {
		name          string
		write         func(w http.ResponseWriter)
		outcome, code string
	}{
		{"issued", func(w http.ResponseWriter) { writeJSON(w, http.StatusOK, map[string]any{"agent_token": "t"}) }, "issued", ""},
		{"signature", func(w http.ResponseWriter) { WriteSigError(w, sigErr(ErrCodeRevokedJWT, "revoked")) }, "signature_error", "revoked_jwt"},
		{"refused", func(w http.ResponseWriter) { writeError(w, http.StatusForbidden, "denied", "no") }, "refused", "denied"},
		{"rate limited", func(w http.ResponseWriter) { writeError(w, http.StatusTooManyRequests, "rate_limited", "") }, "rate_limited", "rate_limited"},
		{"error", func(w http.ResponseWriter) { writeError(w, http.StatusInternalServerError, "server_error", "") }, "error", "server_error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := httptest.NewRecorder()
			rec := &responseRecorder{ResponseWriter: out, status: http.StatusOK}
			tc.write(rec)
			if outcome, code := classify(rec); outcome != tc.outcome || code != tc.code {
				t.Fatalf("got %s/%q, want %s/%q", outcome, code, tc.outcome, tc.code)
			}
			if out.Code != rec.status || out.Body.Len() == 0 {
				t.Fatalf("the response was not written through: %d %q", out.Code, out.Body.String())
			}
		})
	}
}
