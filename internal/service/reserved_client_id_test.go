package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsReservedClientID(t *testing.T) {
	s := &OAuthClientService{}
	assert.False(t, s.IsReservedClientID("billing"), "nothing is reserved by default")

	s.SetReservedClientIDs([]string{"billing", "Gateway"}, []string{"svc-"})
	for _, id := range []string{"billing", "BILLING", "gateway", "svc-", "svc-anything", "SVC-x"} {
		assert.True(t, s.IsReservedClientID(id), id)
	}
	for _, id := range []string{"billing2", "my-billing", "svc", "service-x", ""} {
		assert.False(t, s.IsReservedClientID(id), id)
	}

	// A second call replaces the set rather than adding to it.
	s.SetReservedClientIDs(nil, nil)
	assert.False(t, s.IsReservedClientID("billing"))
	assert.False(t, s.IsReservedClientID("svc-x"))
}

// RegisterClient refuses a reserved id before touching the store, so the
// refusal does not depend on the row being absent.
func TestRegisterClient_RefusesReservedClientID(t *testing.T) {
	s := &OAuthClientService{}
	s.SetReservedClientIDs([]string{"billing"}, nil)
	_, _, err := s.RegisterClient(context.Background(), RegisterClientRequest{ClientID: "Billing", Name: "x"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrReservedClientID))
	assert.True(t, errors.Is(err, ErrInvalidClientMetadata), "handlers map it to 400 like other bad metadata")
}
