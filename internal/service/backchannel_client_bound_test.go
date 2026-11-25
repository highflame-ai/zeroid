package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/domain"
)

func TestRequireCIBAScopeWithinClient(t *testing.T) {
	public := func(scopes ...string) *domain.OAuthClient {
		return &domain.OAuthClient{ClientID: "pub", ClientType: "public", TokenEndpointAuthMethod: "none", Scopes: scopes}
	}
	confidential := func(scopes ...string) *domain.OAuthClient {
		return &domain.OAuthClient{ClientID: "conf", ClientType: "confidential", TokenEndpointAuthMethod: "client_secret_post", Scopes: scopes}
	}
	cases := []struct {
		name    string
		client  *domain.OAuthClient
		scope   string
		refused string
	}{
		{name: "registered scopes are grantable", client: public("openid", "tools:read"), scope: "openid tools:read"},
		{name: "a subset is grantable", client: public("tools:read", "tools:write"), scope: "tools:read"},
		{name: "no scope is grantable", client: public("tools:read"), scope: ""},
		{name: "openid is always grantable", client: public("tools:read"), scope: "openid"},
		{name: "an unregistered scope is refused", client: public("openid", "tools:read"), scope: "openid tools:write", refused: "tools:write"},
		{name: "public, no registration: openid only", client: public(), scope: "openid"},
		{name: "public, no registration: authority refused", client: public(), scope: "openid tools:read", refused: "tools:read"},
		{name: "confidential with registration is bounded", client: confidential("tools:read"), scope: "tools:admin", refused: "tools:admin"},
		{name: "confidential, no registration: no client ceiling", client: confidential(), scope: "openid tools:admin"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := requireCIBAScopeWithinClient(tc.client, tc.scope)
			if tc.refused == "" {
				require.NoError(t, err)
				return
			}
			var oerr *OAuthError
			require.ErrorAs(t, err, &oerr)
			assert.Equal(t, "invalid_scope", oerr.Code)
			assert.Contains(t, oerr.Description, tc.refused)
		})
	}
}

func TestRequireAuthenticatedInitiator(t *testing.T) {
	client := &domain.OAuthClient{ClientID: "pub", ClientType: "public", TokenEndpointAuthMethod: "none"}

	strict := &BackchannelService{cfg: DefaultBackchannelConfig()}
	err := strict.requireAuthenticatedInitiator(client)
	var oerr *OAuthError
	require.ErrorAs(t, err, &oerr, "the default refuses an unauthenticated public initiator")
	assert.Equal(t, "invalid_client", oerr.Code)

	legacyCfg := DefaultBackchannelConfig()
	legacyCfg.AllowUnauthenticatedPublicClients = true
	legacy := &BackchannelService{cfg: legacyCfg}
	require.NoError(t, legacy.requireAuthenticatedInitiator(client), "the migration setting restores the old behaviour")
}

func TestDefaultBackchannelConfigRefusesUnauthenticatedPublicClients(t *testing.T) {
	assert.False(t, DefaultBackchannelConfig().AllowUnauthenticatedPublicClients)
}
