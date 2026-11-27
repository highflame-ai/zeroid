package postgres

import (
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/migrations"
)

// cascadeFunctions are the SQL functions that revoke a credential's
// delegation subtree by walking parent_jti down from it.
var cascadeFunctions = []string{
	"revoke_credentials_cascade",
	"revoke_credential_cascade",
	"revoke_credentials_by_owner",
}

var cascadeDepthBound = regexp.MustCompile(`chain\.depth\s*<\s*(\d+)`)

// latestFunctionBody returns the body of the last CREATE [OR REPLACE]
// FUNCTION name in the up migrations, in migration order, and the file it is
// in. That definition is the one a migrated database runs.
func latestFunctionBody(t *testing.T, name string) (body, file string) {
	t.Helper()
	files, err := fs.Glob(migrations.FS, "*.up.sql")
	require.NoError(t, err)
	sort.Strings(files)
	// The name may be schema-qualified and either part quoted.
	start := regexp.MustCompile(`(?i)CREATE\s+(OR\s+REPLACE\s+)?FUNCTION\s+(?:"?public"?\s*\.\s*)?"?` + regexp.QuoteMeta(name) + `"?\s*\(`)
	for _, f := range files {
		raw, err := fs.ReadFile(migrations.FS, f)
		require.NoError(t, err)
		src := string(raw)
		locs := start.FindAllStringIndex(src, -1)
		if len(locs) == 0 {
			continue
		}
		rest := src[locs[len(locs)-1][0]:]
		end := strings.Index(strings.ToUpper(rest), "$$ LANGUAGE")
		require.Positive(t, end, "%s: the definition of %s has no end", f, name)
		body, file = rest[:end], f
	}
	require.NotEmpty(t, file, "no migration defines %s", name)
	return body, file
}

// The issuance and introspection lineage check and the cascade revocation
// walk must stop at the same depth, so ZeroID never issues or honours a
// token that revoking its root would not reach. SQL cannot read the Go
// constant, so this reads the depth bound from the latest definition of each
// cascade function. The walk starts at depth 0 and continues while
// chain.depth < MaxLineageDepth, so it reaches MaxLineageDepth+1 credentials;
// CredentialLineage counts from the parent at depth 1 and refuses past
// MaxLineageDepth, so the deepest token issued is the MaxLineageDepth+1th.
func TestMaxLineageDepthMatchesCascadeMigrations(t *testing.T) {
	for _, fn := range cascadeFunctions {
		body, file := latestFunctionBody(t, fn)
		bounds := cascadeDepthBound.FindAllStringSubmatch(body, -1)
		require.NotEmpty(t, bounds, "%s in %s: no chain.depth bound found; update this test if the walk changed shape", fn, file)
		for _, m := range bounds {
			n, err := strconv.Atoi(m[1])
			require.NoError(t, err)
			assert.Equal(t, MaxLineageDepth, n, "%s in %s walks to chain.depth < %d, but MaxLineageDepth is %d", fn, file, n, MaxLineageDepth)
		}
	}
}
