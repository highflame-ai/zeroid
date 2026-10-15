package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The verify-id-token body carries a person's ID token. huma's schema
// validator echoes the whole body in errors[].value on a missing or unknown
// field, so the route must be on the redaction list, and its body is capped
// before huma reads a megabyte of it. Both refusals happen before the
// handler runs, so the API needs no services.
func postVerifyIDToken(t *testing.T, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	router := chi.NewRouter()
	(&API{}).registerExternalIssuerRoutes(NewHumaAPIAdmin(router))
	req := httptest.NewRequest(http.MethodPost, "/external-issuers/11111111-2222-3333-4444-555555555555/verify-id-token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestVerifyIDTokenSchemaRefusalNeverEchoesTheToken(t *testing.T) {
	const tok = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJvd25lciJ9.c2lnbmF0dXJl"
	for name, body := range map[string]map[string]any{
		"a missing field":  {"id_token": tok, "client_id": "app"},
		"an unknown field": {"id_token": tok, "client_id": "app", "nonce": "n", "binding": "x"},
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := json.Marshal(body)
			require.NoError(t, err)
			rec := postVerifyIDToken(t, raw)
			require.Equal(t, http.StatusUnprocessableEntity, rec.Code, rec.Body.String())
			assert.NotContains(t, rec.Body.String(), tok)
			assert.Contains(t, rec.Body.String(), "[redacted]")
		})
	}
}

// A body that is not JSON is the path where huma copies the raw body
// verbatim into errors[].value.
func TestVerifyIDTokenMalformedBodyNeverEchoesTheToken(t *testing.T) {
	const tok = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJvd25lciJ9.c2lnbmF0dXJl"
	for name, body := range map[string]string{
		"unterminated": `{"id_token":"` + tok + `"`,
		"a bare token": `{"id_token":` + tok + `}`,
	} {
		t.Run(name, func(t *testing.T) {
			rec := postVerifyIDToken(t, []byte(body))
			require.GreaterOrEqual(t, rec.Code, 400, rec.Body.String())
			assert.NotContains(t, rec.Body.String(), tok)
			assert.NotContains(t, rec.Body.String(), "eyJzdWIiOiJvd25lciJ9", "the token's claims segment")
		})
	}
}

func TestVerifyIDTokenBodyIsCapped(t *testing.T) {
	raw, err := json.Marshal(map[string]any{"id_token": strings.Repeat("a", maxVerifyIDTokenBodyBytes), "client_id": "app", "nonce": "n"})
	require.NoError(t, err)
	rec := postVerifyIDToken(t, raw)
	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code, rec.Body.String())
}
