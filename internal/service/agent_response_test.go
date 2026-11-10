package service

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/domain"
)

// TestIdentityToAgentResponse_SurfacesOwner is a regression guard: the agent DTO
// must surface the identity's owner_user_id. It was previously omitted, so an
// adopted agent (which has an owner but no creator) rendered as "ownerless" in
// downstream UIs even though an accountable owner was assigned.
func TestIdentityToAgentResponse_SurfacesOwner(t *testing.T) {
	resp := identityToAgentResponse(&domain.Identity{
		ID:          "id-1",
		OwnerUserID: "user_123",
		CreatedBy:   "user_creator",
	}, "hf_sk_prefix")

	if resp.OwnerUserID != "user_123" {
		t.Errorf("AgentResponse.OwnerUserID = %q, want %q", resp.OwnerUserID, "user_123")
	}
	// created_by stays populated too — the two are distinct (creator vs owner).
	if resp.CreatedBy != "user_creator" {
		t.Errorf("AgentResponse.CreatedBy = %q, want %q", resp.CreatedBy, "user_creator")
	}
}

// rfc7638ECThumbprint is an independent RFC 7638 §3 computation for a P-256
// key: SHA-256 over the required members in lexicographic order, no
// whitespace, coordinates as fixed 32-byte big-endian values.
func rfc7638ECThumbprint(t *testing.T, k *ecdsa.PrivateKey) string {
	t.Helper()
	// Uncompressed point: 0x04 || X (32 bytes) || Y (32 bytes).
	b, err := k.PublicKey.Bytes()
	if err != nil {
		t.Fatalf("encode public key: %v", err)
	}
	x, y := b[1:33], b[33:65]
	canonical := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`,
		base64.RawURLEncoding.EncodeToString(x), base64.RawURLEncoding.EncodeToString(y))
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestIdentityToAgentResponse_PublicKeyPresence(t *testing.T) {
	t.Run("no key", func(t *testing.T) {
		resp := identityToAgentResponse(&domain.Identity{ID: "id-1"}, "")
		require.False(t, resp.HasPublicKey)
		require.Empty(t, resp.PublicKeyThumbprint)

		raw, err := json.Marshal(resp)
		require.NoError(t, err)
		var m map[string]any
		require.NoError(t, json.Unmarshal(raw, &m))
		require.Equal(t, false, m["has_public_key"], "has_public_key is always present")
		require.NotContains(t, m, "public_key_thumbprint", "thumbprint is omitted when no key is enrolled")
	})

	t.Run("enrolled key", func(t *testing.T) {
		k := newECKey(t)
		pemStr := spkiPEM(t, k)
		resp := identityToAgentResponse(&domain.Identity{ID: "id-2", PublicKeyPEM: pemStr}, "")
		require.True(t, resp.HasPublicKey)
		require.Equal(t, rfc7638ECThumbprint(t, k), resp.PublicKeyThumbprint)
		require.NotContains(t, resp.PublicKeyThumbprint, "=", "base64url without padding")

		raw, err := json.Marshal(resp)
		require.NoError(t, err)
		require.NotContains(t, string(raw), "BEGIN PUBLIC KEY", "the agent registry never returns the PEM")
		require.NotContains(t, string(raw), "public_key_pem")
	})

	// A row written before validation existed can hold an unusable key: it is
	// still reported as enrolled, just without a thumbprint.
	t.Run("unparseable stored key", func(t *testing.T) {
		resp := identityToAgentResponse(&domain.Identity{ID: "id-3", PublicKeyPEM: "legacy junk"}, "")
		require.True(t, resp.HasPublicKey)
		require.Empty(t, resp.PublicKeyThumbprint)
	})
}
