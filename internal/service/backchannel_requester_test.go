package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequestingChainScopes(t *testing.T) {
	chain := []string{"tools:read", "tools:write"}
	cases := []struct {
		name      string
		chain     []string
		requested []string
		want      []string
		refused   string
	}{
		{name: "openid alone keeps the chain's scopes", chain: chain, requested: []string{"openid"}, want: chain},
		{name: "no scope keeps the chain's scopes", chain: chain, requested: nil, want: chain},
		{name: "a held scope narrows", chain: chain, requested: []string{"openid", "tools:read"}, want: []string{"tools:read"}},
		{name: "duplicates collapse", chain: chain, requested: []string{"tools:read", "tools:read"}, want: []string{"tools:read"}},
		{name: "a scope the chain lacks is refused", chain: chain, requested: []string{"openid", "tools:admin"}, refused: "tools:admin"},
		{name: "a scopeless chain keeps the request, as a root grant does", chain: nil, requested: []string{"openid"}, want: []string{"openid"}},
		{name: "a scopeless chain and no request stay scopeless", chain: nil, requested: nil, want: nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := requestingChainScopes(tc.chain, tc.requested)
			if tc.refused != "" {
				require.Error(t, err)
				var oerr *OAuthError
				require.ErrorAs(t, err, &oerr)
				assert.Equal(t, "invalid_scope", oerr.Code)
				assert.Contains(t, oerr.Description, tc.refused)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// The result never aliases the chain's slice, so a caller editing the
// token's scopes cannot alter the credential it was read from.
func TestRequestingChainScopes_DoesNotAliasTheChain(t *testing.T) {
	chain := []string{"tools:read"}
	got, err := requestingChainScopes(chain, []string{"openid"})
	require.NoError(t, err)
	got[0] = "changed"
	assert.Equal(t, "tools:read", chain[0])
}
