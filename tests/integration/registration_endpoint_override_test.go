// token.registration_endpoint — advertising a registration endpoint hosted
// somewhere other than ZeroID's own /oauth2/register.
//
// RFC 8414 §2 lets registration_endpoint be any URL. ZeroID's own endpoint
// registers machine clients behind an initial access token; a deployment that
// runs registration for other clients elsewhere advertises that URL instead.
// These tests pin: the default is unchanged, the override reaches BOTH AS
// metadata documents (via config and via the Server setter), an invalid value
// is refused rather than advertised, and ZeroID's own endpoint stays mounted.
package integration_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	zeroid "github.com/highflame-ai/zeroid"
)

const externalRegistrationEndpoint = "https://app.example.test/oauth/register"

var asMetadataPaths = []string{
	"/.well-known/oauth-authorization-server",
	"/.well-known/openid-configuration",
}

// advertisedRegistrationEndpoints returns registration_endpoint from each AS
// metadata document served at base, keyed by path.
func advertisedRegistrationEndpoints(t *testing.T, base string) map[string]any {
	t.Helper()

	out := map[string]any{}

	for _, path := range asMetadataPaths {
		resp, err := http.Get(base + path) //nolint:noctx // test helper against a local httptest server
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode, path)

		out[path] = decode(t, resp)["registration_endpoint"]
	}

	return out
}

func TestRegistrationEndpoint_DefaultIsOwnEndpoint(t *testing.T) {
	for path, got := range advertisedRegistrationEndpoints(t, testServer.URL) {
		require.Equal(t, testIssuer+"/oauth2/register", got,
			"%s: with no override the advertised endpoint must be ZeroID's own", path)
	}
}

func TestRegistrationEndpoint_SetterOverridesBothDocuments(t *testing.T) {
	require.NoError(t, testZeroIDServer.SetRegistrationEndpoint(externalRegistrationEndpoint))
	defer func() { require.NoError(t, testZeroIDServer.SetRegistrationEndpoint("")) }()

	for path, got := range advertisedRegistrationEndpoints(t, testServer.URL) {
		require.Equal(t, externalRegistrationEndpoint, got, "%s must advertise the override", path)
	}

	// Only the advertisement moved: ZeroID's own endpoint is still mounted and
	// still gated (a bogus initial access token → 401, not 404).
	resp := post(t, "/oauth2/register", map[string]any{
		"client_name": "should-not-register",
		"grant_types": []string{"client_credentials"},
	}, map[string]string{"Authorization": "Bearer not-a-real-initial-access-token"})
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"/oauth2/register must stay mounted with its initial-access-token gate")

	// Clearing restores the default.
	require.NoError(t, testZeroIDServer.SetRegistrationEndpoint(""))

	for path, got := range advertisedRegistrationEndpoints(t, testServer.URL) {
		require.Equal(t, testIssuer+"/oauth2/register", got, "%s: empty must restore the default", path)
	}
}

func TestRegistrationEndpoint_SetterRejectsInvalidAndKeepsPrevious(t *testing.T) {
	require.NoError(t, testZeroIDServer.SetRegistrationEndpoint(externalRegistrationEndpoint))
	defer func() { require.NoError(t, testZeroIDServer.SetRegistrationEndpoint("")) }()

	for _, bad := range []string{
		"http://app.example.test/oauth/register", // plain http, not loopback
		"/oauth/register",                        // relative
		"https://user:pw@app.example.test/r",     // user-info
		"https://app.example.test/r#frag",        // fragment
		"javascript:alert(1)",                    // not a URL clients can register at
		" https://app.example.test/r",            // leading whitespace
		"https://app.example.test/r\n",           // trailing newline
		"https://app.example.test/a b",           // inner whitespace
		"https://bücher.example/r",               // non-ASCII host (needs xn-- form)
		"https://app.example.test:0/r",           // port out of range
		"https://app.example.test:65536/r",       // port out of range
		"https://app.example.test:abc/r",         // non-numeric port
		"HTTPS://app.example.test/r",             // non-canonical scheme
		"https://App.Example.test/r",             // non-canonical host
	} {
		require.Error(t, testZeroIDServer.SetRegistrationEndpoint(bad), "must reject %q", bad)
	}

	for path, got := range advertisedRegistrationEndpoints(t, testServer.URL) {
		require.Equal(t, externalRegistrationEndpoint, got,
			"%s: a rejected value must leave the previous advertisement in place", path)
	}
}

// The setter runs against the server's configured (https) issuer: plain http
// for a non-loopback host is refused there, and an error never quotes a
// password embedded in the rejected value.
func TestRegistrationEndpoint_SetterRefusesHTTPBesideHTTPSIssuerAndRedacts(t *testing.T) {
	require.NoError(t, testZeroIDServer.SetRegistrationEndpoint(""))

	err := testZeroIDServer.SetRegistrationEndpoint("http://app.example.test:3000/oauth/register")
	require.Error(t, err)
	require.Contains(t, err.Error(), "must use https")

	const secret = "hunter2-s3cret"
	for _, bad := range []string{
		"https://admin:" + secret + "@app.example.test/r",
		"https://admin:" + secret + "@app.example.test:abc/r",
		"http://admin:" + secret + "@app.example.test/r",
	} {
		err := testZeroIDServer.SetRegistrationEndpoint(bad)
		require.Error(t, err)
		require.NotContains(t, err.Error(), secret, "the error must not echo the password")
	}

	for path, got := range advertisedRegistrationEndpoints(t, testServer.URL) {
		require.Equal(t, testIssuer+"/oauth2/register", got, "%s: rejected values must not be advertised", path)
	}
}

// A deployment whose issuer is plain http (an in-cluster test stack) can
// advertise an http registration endpoint on another host, both from config
// and through the setter.
func TestRegistrationEndpoint_HTTPAllowedBesideHTTPIssuer(t *testing.T) {
	const (
		httpIssuer   = "http://zeroid-authn.test:8051"
		httpEndpoint = "http://zeroid-studio.test:3000/oauth/register"
	)
	cfg := newRegistrationEndpointConfig(t, httpEndpoint)
	cfg.Token.Issuer = httpIssuer

	srv, err := zeroid.NewServer(cfg)
	require.NoError(t, err, "an http registration endpoint must be accepted beside an http issuer")

	httpSrv := httptest.NewServer(srv.Router())
	t.Cleanup(httpSrv.Close)
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	for path, got := range advertisedRegistrationEndpoints(t, httpSrv.URL) {
		require.Equal(t, httpEndpoint, got, "%s must advertise the http endpoint", path)
	}

	const other = "http://zeroid-front.test:3000/register"
	require.NoError(t, srv.SetRegistrationEndpoint(other), "the setter must use the server's own http issuer")

	for path, got := range advertisedRegistrationEndpoints(t, httpSrv.URL) {
		require.Equal(t, other, got, path)
	}

	// The same http endpoint beside an https issuer is still refused at load.
	cfg.Token.Issuer = testIssuer
	_, err = zeroid.NewServer(cfg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "token.registration_endpoint")
}

// newRegistrationEndpointConfig is a minimal valid config for a second server
// on the shared database, with the given registration_endpoint.
func newRegistrationEndpointConfig(t *testing.T, endpoint string) zeroid.Config {
	t.Helper()
	require.NoError(t, initFederationKeyMaterial(), "init key material")

	return zeroid.Config{
		Server: zeroid.ServerConfig{Port: "0", Env: "test", ShutdownTimeoutSeconds: 5},
		Database: zeroid.DatabaseConfig{
			URL:          sharedDBURL,
			MaxOpenConns: 5,
			MaxIdleConns: 2,
		},
		Keys: zeroid.KeysConfig{
			PrivateKeyPath:    fedKeyPaths.privPath,
			PublicKeyPath:     fedKeyPaths.pubPath,
			KeyID:             "regendpoint-test-key-1",
			RSAPrivateKeyPath: fedKeyPaths.rsaPriv,
			RSAPublicKeyPath:  fedKeyPaths.rsaPub,
			RSAKeyID:          "regendpoint-test-rsa-1",
		},
		Token: zeroid.TokenConfig{
			Issuer:               testIssuer,
			DefaultTTL:           3600,
			MaxTTL:               90 * 24 * 3600,
			RegistrationEndpoint: endpoint,
		},
		Telemetry:   zeroid.TelemetryConfig{Enabled: false},
		Logging:     zeroid.LoggingConfig{Level: "warn"},
		WIMSEDomain: testWIMSE,
	}
}

func TestRegistrationEndpoint_ConfigOverridesBothDocuments(t *testing.T) {
	srv, err := zeroid.NewServer(newRegistrationEndpointConfig(t, externalRegistrationEndpoint))
	require.NoError(t, err)

	httpSrv := httptest.NewServer(srv.Router())
	t.Cleanup(httpSrv.Close)
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	for path, got := range advertisedRegistrationEndpoints(t, httpSrv.URL) {
		require.Equal(t, externalRegistrationEndpoint, got,
			"%s must advertise token.registration_endpoint", path)
	}
}

func TestRegistrationEndpoint_InvalidConfigRejectedAtLoad(t *testing.T) {
	for _, bad := range []string{
		"http://app.example.test/oauth/register",
		"app.example.test/oauth/register",
		"https://app.example.test/oauth/register#x",
		"https://app.example.test/oauth/register ",
		"https://app.example.test:0/oauth/register",
		"HTTPS://app.example.test/oauth/register",
	} {
		_, err := zeroid.NewServer(newRegistrationEndpointConfig(t, bad))
		require.Error(t, err, "NewServer must refuse token.registration_endpoint=%q", bad)
		require.Contains(t, err.Error(), "token.registration_endpoint")
	}
}
