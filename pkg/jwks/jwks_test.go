package jwks

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
)

func keySetJSON(t *testing.T, kid string) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := jwk.Import[jwk.Key](&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	_ = key.Set(jwk.KeyIDKey, kid)
	set := jwk.NewSet()
	_ = set.AddKey(key)
	raw, _ := json.Marshal(set)
	return raw
}

// TestRefreshIfMissing_RateLimitedAndSingleFlight: unknown kids from
// unverified tokens cannot drive one upstream fetch each.
func TestRefreshIfMissing_RateLimitedAndSingleFlight(t *testing.T) {
	var hits atomic.Int64
	var mu sync.Mutex
	body := keySetJSON(t, "k1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		time.Sleep(20 * time.Millisecond)
		mu.Lock()
		defer mu.Unlock()
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	c, err := New(srv.URL, WithOnDemandRefreshInterval(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := hits.Load()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.RefreshIfMissing(context.Background(), "made-up")
		}()
	}
	wg.Wait()
	if got := hits.Load() - start; got != 1 {
		t.Fatalf("20 concurrent unknown kids caused %d fetches, want 1", got)
	}
	for i := 0; i < 5; i++ {
		c.RefreshIfMissing(context.Background(), "made-up-again")
	}
	if got := hits.Load() - start; got != 1 {
		t.Fatalf("unknown kids inside the interval caused %d fetches, want 1", got)
	}

	t.Run("a rotated kid is found once the interval allows", func(t *testing.T) {
		c2, err := New(srv.URL, WithOnDemandRefreshInterval(0))
		if err != nil {
			t.Fatal(err)
		}
		defer c2.Close()
		mu.Lock()
		body = keySetJSON(t, "k2")
		mu.Unlock()
		if !c2.RefreshIfMissing(context.Background(), "k2") {
			t.Fatal("the new kid should be found and reported")
		}
		if c2.RefreshIfMissing(context.Background(), "k2") {
			t.Fatal("a known kid needs no refresh")
		}
	})
}
