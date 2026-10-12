// token.device_authorization_endpoint — advertising an RFC 8628 device
// authorization endpoint that the embedder serves beside ZeroID.
//
// ZeroID does not implement the device authorization grant. An embedder that
// does wants clients to discover it from AS metadata rather than hardcode the
// path. These tests pin: unset advertises neither the endpoint nor the
// device_code grant; set (via the Server setter or config) advertises both in
// BOTH metadata documents; an invalid value is refused and the previous
// advertisement stays; errors never echo a password.
package integration_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	zeroid "github.com/highflame-ai/zeroid"
)

const (
	externalDeviceAuthorizationEndpoint = "https://login.example.test/oauth2/device_authorization"
	deviceCodeGrant                     = "urn:ietf:params:oauth:grant-type:device_code"
)

// deviceAdvertisement is what one metadata document says about device
// authorization.
type deviceAdvertisement struct {
	endpoint  any
	hasGrant  bool
	hasMember bool
}

func advertisedDeviceAuthorization(t *testing.T, base string) map[string]deviceAdvertisement {
	t.Helper()

	out := map[string]deviceAdvertisement{}

	for _, path := range asMetadataPaths {
		resp, err := http.Get(base + path) //nolint:noctx // test helper against a local httptest server
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode, path)

		doc := decode(t, resp)
		endpoint, hasMember := doc["device_authorization_endpoint"]

		var grants []string
		raw, _ := doc["grant_types_supported"].([]any)
		for _, g := range raw {
			if s, ok := g.(string); ok {
				grants = append(grants, s)
			}
		}

		out[path] = deviceAdvertisement{
			endpoint:  endpoint,
			hasMember: hasMember,
			hasGrant:  slices.Contains(grants, deviceCodeGrant),
		}
	}

	return out
}

func requireDeviceUnadvertised(t *testing.T, base, when string) {
	t.Helper()

	for path, got := range advertisedDeviceAuthorization(t, base) {
		require.False(t, got.hasMember, "%s (%s): device_authorization_endpoint must be absent", path, when)
		require.False(t, got.hasGrant, "%s (%s): device_code grant must not be advertised", path, when)
	}
}

func requireDeviceAdvertised(t *testing.T, base, endpoint string) {
	t.Helper()

	for path, got := range advertisedDeviceAuthorization(t, base) {
		require.Equal(t, endpoint, got.endpoint, "%s must advertise the endpoint", path)
		require.True(t, got.hasGrant, "%s must list the device_code grant while the endpoint is set", path)
	}
}

func TestDeviceAuthorizationEndpoint_DefaultIsUnadvertised(t *testing.T) {
	requireDeviceUnadvertised(t, testServer.URL, "default")
}

func TestDeviceAuthorizationEndpoint_SetterAdvertisesInBothDocuments(t *testing.T) {
	require.NoError(t, testZeroIDServer.SetDeviceAuthorizationEndpoint(externalDeviceAuthorizationEndpoint))
	defer func() { require.NoError(t, testZeroIDServer.SetDeviceAuthorizationEndpoint("")) }()

	requireDeviceAdvertised(t, testServer.URL, externalDeviceAuthorizationEndpoint)

	// Empty unsets both members.
	require.NoError(t, testZeroIDServer.SetDeviceAuthorizationEndpoint(""))
	requireDeviceUnadvertised(t, testServer.URL, "cleared")
}

func TestDeviceAuthorizationEndpoint_SetterRejectsInvalidAndKeepsPrevious(t *testing.T) {
	require.NoError(t, testZeroIDServer.SetDeviceAuthorizationEndpoint(externalDeviceAuthorizationEndpoint))
	defer func() { require.NoError(t, testZeroIDServer.SetDeviceAuthorizationEndpoint("")) }()

	for _, bad := range []string{
		"http://login.example.test/oauth2/device_authorization", // plain http beside an https issuer
		"/oauth2/device_authorization",                          // relative
		"https://login.example.test/d#frag",                     // fragment
		"https://login.example.test/d ",                         // trailing whitespace
		"https://bücher.example/d",                              // non-ASCII host
		"https://login.example.test:0/d",                        // port out of range
		"HTTPS://login.example.test/d",                          // non-canonical scheme
		"https://Login.Example.test/d",                          // non-canonical host
	} {
		err := testZeroIDServer.SetDeviceAuthorizationEndpoint(bad)
		require.Error(t, err, "must reject %q", bad)
		require.Contains(t, err.Error(), "token.device_authorization_endpoint")
	}

	const secret = "hunter2-s3cret"
	for _, bad := range []string{
		"https://admin:" + secret + "@login.example.test/d",
		"https://admin:" + secret + "@login.example.test:abc/d",
	} {
		err := testZeroIDServer.SetDeviceAuthorizationEndpoint(bad)
		require.Error(t, err)
		require.NotContains(t, err.Error(), secret, "the error must not echo the password")
	}

	requireDeviceAdvertised(t, testServer.URL, externalDeviceAuthorizationEndpoint)
}

func TestDeviceAuthorizationEndpoint_ConfigAdvertisesInBothDocuments(t *testing.T) {
	cfg := newRegistrationEndpointConfig(t, "")
	cfg.Token.DeviceAuthorizationEndpoint = externalDeviceAuthorizationEndpoint

	srv, err := zeroid.NewServer(cfg)
	require.NoError(t, err)

	httpSrv := httptest.NewServer(srv.Router())
	t.Cleanup(httpSrv.Close)
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	requireDeviceAdvertised(t, httpSrv.URL, externalDeviceAuthorizationEndpoint)
}

// Beside a plain-http issuer (an in-cluster stack) an http endpoint is accepted,
// from config and through the setter; beside an https issuer it is refused at
// load.
func TestDeviceAuthorizationEndpoint_HTTPAllowedBesideHTTPIssuer(t *testing.T) {
	const (
		httpIssuer   = "http://zeroid-authn.test:8051"
		httpEndpoint = "http://zeroid-authn.test:8051/oauth2/device_authorization"
	)

	cfg := newRegistrationEndpointConfig(t, "")
	cfg.Token.Issuer = httpIssuer
	cfg.Token.DeviceAuthorizationEndpoint = httpEndpoint

	srv, err := zeroid.NewServer(cfg)
	require.NoError(t, err)

	httpSrv := httptest.NewServer(srv.Router())
	t.Cleanup(httpSrv.Close)
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	requireDeviceAdvertised(t, httpSrv.URL, httpEndpoint)

	const other = "http://zeroid-front.test:3000/device"
	require.NoError(t, srv.SetDeviceAuthorizationEndpoint(other))
	requireDeviceAdvertised(t, httpSrv.URL, other)

	cfg.Token.Issuer = testIssuer
	_, err = zeroid.NewServer(cfg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "token.device_authorization_endpoint")
}
