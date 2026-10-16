package service

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureIDJAGLog swaps the global logger for one that writes to a buffer.
func captureIDJAGLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	orig := log.Logger
	log.Logger = zerolog.New(buf)
	t.Cleanup(func() { log.Logger = orig })
	return buf
}

// decodeIDJAGLog decodes the one line logIDJAGRedeemed wrote.
func decodeIDJAGLog(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	var line map[string]any
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &line))
	return line
}

// TestLogIDJAGRedeemed pins the success line of an ID-JAG redemption: it names
// the ID-JAG by its jti and upstream sub, so an operator can match it to the
// identity provider's record of the ID-JAG it issued (zeroid#447).
func TestLogIDJAGRedeemed(t *testing.T) {
	t.Run("names the ID-JAG by its jti and upstream sub", func(t *testing.T) {
		buf := captureIDJAGLog(t)
		logIDJAGRedeemed("https://idp.example", "idjag-jti-1", "00uSUBJECT", "acct", "proj", "user-1",
			[]string{"https://mcp.example/a"})

		line := decodeIDJAGLog(t, buf)
		assert.Equal(t, "ID-JAG jwt-bearer exchange succeeded", line["message"])
		assert.Equal(t, "info", line["level"])
		assert.Equal(t, "https://idp.example", line["upstream_iss"])
		assert.Equal(t, "idjag-jti-1", line["id_jag_jti"])
		assert.Equal(t, "00uSUBJECT", line["upstream_sub"])
		assert.Equal(t, "acct", line["account_id"])
		assert.Equal(t, "proj", line["project_id"])
		assert.Equal(t, "user-1", line["user_id"])
		assert.Equal(t, []any{"https://mcp.example/a"}, line["resources"])
	})

	t.Run("omits upstream_sub when the ID-JAG names its subject only with sub_id", func(t *testing.T) {
		buf := captureIDJAGLog(t)
		logIDJAGRedeemed("https://idp.example", "idjag-jti-2", "", "acct", "proj", "user-2",
			[]string{"https://mcp.example/a"})

		line := decodeIDJAGLog(t, buf)
		assert.Equal(t, "idjag-jti-2", line["id_jag_jti"])
		assert.NotContains(t, line, "upstream_sub")
	})
}
