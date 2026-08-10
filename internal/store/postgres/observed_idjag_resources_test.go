package postgres

import "testing"

// NormalizeResource decides whether two ID-JAG `resource` values name the same
// MCP server. Get it wrong in one direction and one server accumulates several
// inventory rows (and matches no discovered app reliably); get it wrong in the
// other and two genuinely distinct servers collapse into one. Both are silent.
func TestNormalizeResource(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "host case is folded (RFC 3986 §3.2.2)",
			in:   "https://MCP.Acme.COM/tools",
			want: "https://mcp.acme.com/tools",
		},
		{
			name: "scheme case is folded (RFC 3986 §3.1)",
			in:   "HTTPS://mcp.acme.com/tools",
			want: "https://mcp.acme.com/tools",
		},
		{
			name: "a lone trailing slash carries no meaning",
			in:   "https://mcp.acme.com/",
			want: "https://mcp.acme.com",
		},
		{
			name: "a trailing slash on a real path is left alone",
			// /tools/ and /tools can be different resources on a strict server;
			// folding them would merge two entries on our guess, not their fact.
			in:   "https://mcp.acme.com/tools/",
			want: "https://mcp.acme.com/tools/",
		},
		{
			name: "path case is preserved — paths ARE case-sensitive",
			in:   "https://mcp.acme.com/Tools/Search",
			want: "https://mcp.acme.com/Tools/Search",
		},
		{
			name: "surrounding whitespace is trimmed",
			in:   "  https://mcp.acme.com  ",
			want: "https://mcp.acme.com",
		},
		{
			name: "query is preserved",
			in:   "https://MCP.acme.com/mcp?v=2",
			want: "https://mcp.acme.com/mcp?v=2",
		},
		{
			name: "a urn resource indicator survives untouched",
			// RFC 8707 permits any absolute URI, not only https.
			in:   "urn:acme:mcp:search",
			want: "urn:acme:mcp:search",
		},
		{
			name: "a non-URI value is recorded faithfully rather than mangled",
			in:   "not a uri",
			want: "not a uri",
		},
		{
			name: "empty stays empty so the caller can skip it",
			in:   "   ",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeResource(tt.in); got != tt.want {
				t.Errorf("NormalizeResource(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// An RFC 8707 `resource` array can carry values that are distinct on the wire but
// identical after normalization. Postgres rejects a multi-row upsert touching the
// same key twice ("ON CONFLICT DO UPDATE command cannot affect row a second
// time"), so a duplicate that reaches the INSERT fails the whole batch — and
// because Record is best-effort, that failure would be logged and swallowed,
// silently losing the observation.
func TestNormalizeResourceCollapsesWireDuplicates(t *testing.T) {
	a := NormalizeResource("https://mcp.acme.com/")
	b := NormalizeResource("https://MCP.acme.com")
	if a != b {
		t.Fatalf("expected wire-distinct values to normalize equal, got %q and %q", a, b)
	}
}

func TestNormalizeResourceKeepsDistinctServersDistinct(t *testing.T) {
	a := NormalizeResource("https://mcp.acme.com/search")
	b := NormalizeResource("https://mcp.acme.com/files")
	if a == b {
		t.Fatalf("distinct resources collapsed to %q", a)
	}
}
