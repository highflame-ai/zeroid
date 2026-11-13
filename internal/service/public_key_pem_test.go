package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func pkixPEM(t *testing.T, pub any) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// badPublicKeyPEMs are inputs every public_key_pem write path must refuse as a
// caller error, each with the reason the message has to name.
func badPublicKeyPEMs(t *testing.T) map[string]struct{ pem, reason string } {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	p256 := newECKey(t)
	privDER, err := x509.MarshalECPrivateKey(p256)
	require.NoError(t, err)

	return map[string]struct{ pem, reason string }{
		"rsa":       {pkixPEM(t, &rsaKey.PublicKey), "key type is RSA, want ECDSA"},
		"p384":      {pkixPEM(t, &p384.PublicKey), "curve is P-384, want P-256"},
		"ed25519":   {pkixPEM(t, edPub), "key type is Ed25519, want ECDSA"},
		"garbage":   {"not a pem at all", "no PEM block found"},
		"private":   {string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})), `PEM block type is "EC PRIVATE KEY"`},
		"bad-bytes": {string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("junk")})), "not a DER-encoded SPKI public key"},
	}
}

func TestValidateECPublicKeyPEM_RejectsAsCallerError(t *testing.T) {
	for name, tc := range badPublicKeyPEMs(t) {
		t.Run(name, func(t *testing.T) {
			err := validateECPublicKeyPEM(tc.pem)
			require.Error(t, err)
			require.True(t, errors.Is(err, ErrInvalidIdentityField), "must wrap ErrInvalidIdentityField so handlers answer 400, got %v", err)
			require.Contains(t, err.Error(), invalidPublicKeyPEM)
			require.Contains(t, err.Error(), tc.reason)
		})
	}
}

func TestValidateECPublicKeyPEM_AcceptsP256AndEmpty(t *testing.T) {
	require.NoError(t, validateECPublicKeyPEM(spkiPEM(t, newECKey(t))))
	require.NoError(t, validateECPublicKeyPEM(""), "empty means no key and stays optional")
}

// The register and update paths must reject a bad key before touching the
// store: a bare IdentityService has no repo, so reaching it would panic.
func TestRegisterAndUpdateIdentity_RejectBadPublicKeyBeforeStore(t *testing.T) {
	svc := &IdentityService{}
	for name, tc := range badPublicKeyPEMs(t) {
		t.Run(name, func(t *testing.T) {
			_, err := svc.RegisterIdentity(context.Background(), RegisterIdentityRequest{
				AccountID:    "acct",
				ProjectID:    "proj",
				ExternalID:   "agent-1",
				OwnerUserID:  "user-1",
				PublicKeyPEM: tc.pem,
			})
			require.True(t, errors.Is(err, ErrInvalidIdentityField), "RegisterIdentity: %v", err)
			require.True(t, strings.Contains(err.Error(), tc.reason), "RegisterIdentity: %v", err)

			_, err = svc.UpdateIdentity(context.Background(), "id-1", "acct", "proj", UpdateIdentityRequest{
				PublicKeyPEM: tc.pem,
			})
			require.True(t, errors.Is(err, ErrInvalidIdentityField), "UpdateIdentity: %v", err)

			_, err = svc.SetPublicKey(context.Background(), "id-1", "acct", "proj", tc.pem)
			require.True(t, errors.Is(err, ErrInvalidIdentityField), "SetPublicKey: %v", err)
			require.Equal(t, 1, strings.Count(err.Error(), ErrInvalidIdentityField.Error()), "sentinel must not be wrapped twice: %v", err)
		})
	}
}
