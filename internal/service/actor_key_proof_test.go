package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/pkg/dpop"
)

const (
	testProofAud = "https://auth.example.com/agents/self/public-key"
	testProofSub = "spiffe://example.com/acct-1/proj-1/agent/data-fetcher"
)

// fakeReplay is an in-memory keyProofReplayGuard. A repeated jti returns
// dpop.ErrReplay, mirroring the Postgres unique-constraint behavior.
type fakeReplay struct{ seen map[string]bool }

func newFakeReplay() *fakeReplay { return &fakeReplay{seen: map[string]bool{}} }

func (f *fakeReplay) Insert(_ context.Context, jti string, _ time.Time) error {
	if f.seen[jti] {
		return dpop.ErrReplay
	}
	f.seen[jti] = true
	return nil
}

func newECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return k
}

func spkiPEM(t *testing.T, k *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// mintProof builds and ES256-signs an actor-key proof with the given claims.
func mintProof(t *testing.T, key *ecdsa.PrivateKey, aud, sub, jti string, iat, exp time.Time, nkt string) string {
	t.Helper()
	b := jwt.NewBuilder().
		Audience([]string{aud}).
		Subject(sub).
		JwtID(jti).
		IssuedAt(iat).
		Expiration(exp)
	if nkt != "" {
		b = b.Claim("nkt", nkt)
	}
	tok, err := b.Build()
	require.NoError(t, err)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), key))
	require.NoError(t, err)
	return string(signed)
}

func TestVerifyActorKeyProof_Valid(t *testing.T) {
	key := newECKey(t)
	now := time.Now()
	proof := mintProof(t, key, testProofAud, testProofSub, "jti-1", now, now.Add(time.Minute), "")
	err := verifyActorKeyProof(context.Background(), proof, &key.PublicKey, testProofAud, testProofSub, "", newFakeReplay())
	require.NoError(t, err)
}

func TestVerifyActorKeyProof_WrongSigningKey(t *testing.T) {
	signer, verifier := newECKey(t), newECKey(t)
	now := time.Now()
	proof := mintProof(t, signer, testProofAud, testProofSub, "jti-1", now, now.Add(time.Minute), "")
	// Verify against a different key — must fail at signature validation.
	err := verifyActorKeyProof(context.Background(), proof, &verifier.PublicKey, testProofAud, testProofSub, "", newFakeReplay())
	require.Error(t, err)
}

func TestVerifyActorKeyProof_WrongAudience(t *testing.T) {
	key := newECKey(t)
	now := time.Now()
	proof := mintProof(t, key, "https://evil.example.com/x", testProofSub, "jti-1", now, now.Add(time.Minute), "")
	err := verifyActorKeyProof(context.Background(), proof, &key.PublicKey, testProofAud, testProofSub, "", newFakeReplay())
	require.Error(t, err)
}

func TestVerifyActorKeyProof_WrongSubject(t *testing.T) {
	key := newECKey(t)
	now := time.Now()
	proof := mintProof(t, key, testProofAud, "spiffe://example.com/acct-1/proj-1/agent/someone-else", "jti-1", now, now.Add(time.Minute), "")
	err := verifyActorKeyProof(context.Background(), proof, &key.PublicKey, testProofAud, testProofSub, "", newFakeReplay())
	require.ErrorContains(t, err, "sub")
}

func TestVerifyActorKeyProof_Expired(t *testing.T) {
	key := newECKey(t)
	now := time.Now()
	proof := mintProof(t, key, testProofAud, testProofSub, "jti-1", now.Add(-90*time.Second), now.Add(-30*time.Second), "")
	err := verifyActorKeyProof(context.Background(), proof, &key.PublicKey, testProofAud, testProofSub, "", newFakeReplay())
	require.Error(t, err)
}

func TestVerifyActorKeyProof_LifetimeTooLong(t *testing.T) {
	key := newECKey(t)
	now := time.Now()
	// exp is in the future (passes jwt validation) but the lifetime exceeds the cap.
	proof := mintProof(t, key, testProofAud, testProofSub, "jti-1", now, now.Add(maxKeyProofLifetime+time.Minute), "")
	err := verifyActorKeyProof(context.Background(), proof, &key.PublicKey, testProofAud, testProofSub, "", newFakeReplay())
	require.ErrorContains(t, err, "lifetime")
}

func TestVerifyActorKeyProof_MissingJTI(t *testing.T) {
	key := newECKey(t)
	now := time.Now()
	tok, err := jwt.NewBuilder().
		Audience([]string{testProofAud}).Subject(testProofSub).
		IssuedAt(now).Expiration(now.Add(time.Minute)).Build()
	require.NoError(t, err)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), key))
	require.NoError(t, err)
	err = verifyActorKeyProof(context.Background(), string(signed), &key.PublicKey, testProofAud, testProofSub, "", newFakeReplay())
	require.ErrorContains(t, err, "jti")
}

func TestVerifyActorKeyProof_Replay(t *testing.T) {
	key := newECKey(t)
	now := time.Now()
	replay := newFakeReplay()
	proof := mintProof(t, key, testProofAud, testProofSub, "jti-reused", now, now.Add(time.Minute), "")
	require.NoError(t, verifyActorKeyProof(context.Background(), proof, &key.PublicKey, testProofAud, testProofSub, "", replay))
	// Same jti again → replay.
	err := verifyActorKeyProof(context.Background(), proof, &key.PublicKey, testProofAud, testProofSub, "", replay)
	require.ErrorContains(t, err, "replay")
}

func TestVerifyActorKeyProof_NKTBinding(t *testing.T) {
	currentKey, newKey := newECKey(t), newECKey(t)
	now := time.Now()

	nkt, err := newKeyThumbprint(spkiPEM(t, newKey))
	require.NoError(t, err)

	// Current-key proof bound to the correct new key → ok.
	good := mintProof(t, currentKey, testProofAud, testProofSub, "jti-ok", now, now.Add(time.Minute), nkt)
	require.NoError(t, verifyActorKeyProof(context.Background(), good, &currentKey.PublicKey, testProofAud, testProofSub, nkt, newFakeReplay()))

	// Current-key proof with NO nkt, but a binding is expected → rejected.
	missing := mintProof(t, currentKey, testProofAud, testProofSub, "jti-missing", now, now.Add(time.Minute), "")
	require.ErrorContains(t, verifyActorKeyProof(context.Background(), missing, &currentKey.PublicKey, testProofAud, testProofSub, nkt, newFakeReplay()), "nkt")

	// Current-key proof bound to a DIFFERENT key → rejected (can't repurpose).
	other := mintProof(t, currentKey, testProofAud, testProofSub, "jti-other", now, now.Add(time.Minute), "some-other-thumbprint")
	require.ErrorContains(t, verifyActorKeyProof(context.Background(), other, &currentKey.PublicKey, testProofAud, testProofSub, nkt, newFakeReplay()), "nkt")
}

func TestNewKeyThumbprint(t *testing.T) {
	key := newECKey(t)
	pemStr := spkiPEM(t, key)

	tp1, err := newKeyThumbprint(pemStr)
	require.NoError(t, err)
	require.NotEmpty(t, tp1)

	// Deterministic for the same key.
	tp2, err := newKeyThumbprint(pemStr)
	require.NoError(t, err)
	assert.Equal(t, tp1, tp2)

	// Different key → different thumbprint.
	other, err := newKeyThumbprint(spkiPEM(t, newECKey(t)))
	require.NoError(t, err)
	assert.NotEqual(t, tp1, other)

	// Non-PUBLIC-KEY PEM → error.
	_, err = newKeyThumbprint("-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----")
	require.Error(t, err)
}
