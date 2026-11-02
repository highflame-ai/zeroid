package service

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/domain"
)

// RATCHET. cloneCIMDClient must leave NO slice field aliasing the original.
//
// The enumeration inside it went stale exactly once already: zeroid#264 added
// `jwks` to the synthesized client without adding it here, so every caller
// resolving a key-based CIMD client shared one backing array for its
// verification key material — with the cache and with each other. Nothing
// mutated it, so nothing broke and -race stayed silent. `metadata` was missing
// for the same reason.
//
// Walking the struct by reflection is what makes the next added field fail here
// instead of shipping. Populating every slice field first is the point: a nil
// field would alias trivially and prove nothing.
func TestCloneCIMDClientCoversEveryReferenceField(t *testing.T) {
	t.Parallel()

	original := &domain.OAuthClient{}
	v := reflect.ValueOf(original).Elem()
	typ := v.Type()

	var sliceFields []int
	for i := range typ.NumField() {
		f := v.Field(i)
		if f.Kind() != reflect.Slice || !f.CanSet() {
			continue
		}
		sliceFields = append(sliceFields, i)
		// Give every slice field two elements so aliasing is observable.
		switch f.Type().Elem().Kind() {
		case reflect.String:
			f.Set(reflect.ValueOf([]string{"a", "b"}).Convert(f.Type()))
		case reflect.Uint8:
			f.Set(reflect.ValueOf([]byte(`{"k":1}`)).Convert(f.Type()))
		default:
			t.Fatalf("field %q has unhandled slice element kind %s — teach this test about it "+
				"rather than skipping, or it stops covering that field",
				typ.Field(i).Name, f.Type().Elem().Kind())
		}
	}
	require.NotEmpty(t, sliceFields, "reflection found no slice fields — the walk is broken, not the clone")

	clone := cloneCIMDClient(original)
	cv := reflect.ValueOf(clone).Elem()

	for _, i := range sliceFields {
		name := typ.Field(i).Name
		o, c := v.Field(i), cv.Field(i)
		require.Equal(t, o.Len(), c.Len(), "%s: clone lost elements", name)
		if o.Len() == 0 {
			continue
		}
		assert.NotEqual(t, o.Index(0).Addr().Pointer(), c.Index(0).Addr().Pointer(),
			"%s is NOT cloned — it aliases the cached entry, so any caller mutating it "+
				"corrupts every other caller's copy. Add it to cloneCIMDClient.", name)
	}
}

// An abandoned request must not deny the client_id to anyone else.
//
// singleflight hands ONE execution to every waiter, so with the first caller's
// raw context a disconnect cancelled the fetch for all of them — and the
// cancellation was then negative-cached, denying the client_id for
// cimdTransientNegativeCacheTTL. Unauthenticated and targeted: resolution runs
// before the principal chain, so opening a request for a victim's client_id and
// aborting it, once per 10 seconds, kept that client unable to log anyone in.
//
// Measured before the fix: the legitimate caller below was refused with
// "context canceled" — an error belonging to a request that no longer existed —
// and the origin was never contacted a second time.
func TestCIMDAbandonedRequestDoesNotPoisonTheCache(t *testing.T) {
	var hits int32
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		time.Sleep(150 * time.Millisecond) // merely slow, not broken
		clientID := "https://" + r.Host + r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"client_id":%q,"client_name":"Victim","redirect_uris":["http://127.0.0.1:9000/cb"]}`, clientID)
	}))
	t.Cleanup(origin.Close)

	svc := NewCIMDService(CIMDConfig{Enabled: true, HTTPClient: origin.Client()})
	id := origin.URL + "/victim.json"

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _, _ = svc.ResolveClient(ctx, id) }()
	time.Sleep(40 * time.Millisecond) // let the flight start and begin fetching
	cancel()

	// The victim's own users, arriving right behind the abandoned request.
	time.Sleep(40 * time.Millisecond)
	client, err := svc.ResolveClient(context.Background(), id)
	require.NoError(t, err,
		"a caller who walked away must not be able to deny this client_id to anyone else")
	assert.Equal(t, "Victim", client.Name)
	assert.Positive(t, atomic.LoadInt32(&hits), "the origin must actually have been consulted")
}

// The same origin spelled with its explicit default port is the same origin.
//
// The same-host rule first landed comparing url.Host, which carries the port, so
// https://app.example.com/client.json publishing keys at
// https://app.example.com:443/jwks was refused as a cross-host reference. Every
// fixture used 127.0.0.1:PORT on both sides, so they matched and the tests could
// not see it. Hostname() is also what domainAllowed compares, so the feature's
// two host checks now agree on what "same host" means.
func TestCIMDSameHostRuleIgnoresPortSpelling(t *testing.T) {
	t.Parallel()

	doc := func(clientID, jwksURI string) *cimdMetadataDocument {
		return &cimdMetadataDocument{
			ClientID: clientID, ClientName: "N",
			RedirectURIs:            []string{"https://app.example.com/cb"},
			TokenEndpointAuthMethod: clientAuthMethodPrivateKeyJWT,
			JWKSURI:                 jwksURI,
		}
	}
	now := time.Unix(1_700_000_000, 0)

	for _, tc := range []struct{ name, clientID, jwksURI string }{
		{"explicit :443 on the jwks_uri", "https://app.example.com/c.json", "https://app.example.com:443/jwks"},
		{"explicit :443 on the client_id", "https://app.example.com:443/c.json", "https://app.example.com/jwks"},
		{"both bare", "https://app.example.com/c.json", "https://app.example.com/jwks"},
		// A different PORT is still the same party: the trust anchor is the DNS
		// name and the TLS identity, neither of which a port changes.
		{"non-default port, same host", "https://app.example.com/c.json", "https://app.example.com:8443/jwks"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := synthesizeCIMDClient(tc.clientID, doc(tc.clientID, tc.jwksURI), now)
			require.NoError(t, err, "same host, different spelling — must be accepted")
		})
	}

	// The rule still bites where it should.
	const id = "https://app.example.com/c.json"
	_, _, err := synthesizeCIMDClient(id, doc(id, "https://keys.elsewhere.example/jwks"), now)
	require.Error(t, err, "a genuinely different host must still be refused")
}
