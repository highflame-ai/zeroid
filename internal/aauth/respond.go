package aauth

import (
	"encoding/json"
	"net/http"
)

// writeJSON writes v as JSON with status. Every AAuth response is uncacheable:
// they carry tokens or answer about one request.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError writes an AAuth error response (protocol draft, "Error Response
// Format"): an RFC 9457 problem body whose REQUIRED error member is the code,
// with the explanation in detail. Every /ap/* error uses it. (The bridge
// grant is an OAuth token endpoint and keeps RFC 6749 errors.)
func writeError(w http.ResponseWriter, status int, code, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	body := map[string]any{"error": code}
	if detail != "" {
		body["detail"] = detail
	}
	_ = json.NewEncoder(w).Encode(body)
}
