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

// Configured values are trimmed, so a stray space in config does not leave the
// intended id unreserved.
func TestSetReservedClientIDs_Trims(t *testing.T) {
	s := &OAuthClientService{}
	s.SetReservedClientIDs([]string{" billing "}, []string{" svc-"})
	assert.True(t, s.IsReservedClientID("billing"))
	assert.True(t, s.IsReservedClientID("svc-x"))
	assert.True(t, s.IsReservedClientID(" billing "), "surrounding space does not escape the reservation")
}

// Ids that differ from a reserved one only in Unicode compatibility forms or
// invisible characters are reserved too. Letters of another script that only
// look alike are not: a resource server compares client_id byte for byte.
func TestIsReservedClientID_UnicodeForms(t *testing.T) {
	s := &OAuthClientService{}
	s.SetReservedClientIDs([]string{"billing"}, []string{"svc-"})
	for _, id := range []string{
		"\uff42\uff49\uff4c\uff4c\uff49\uff4e\uff47", // fullwidth "billing"
		"bil\u200bling",        // zero-width space
		"\u200dbilling",        // zero-width joiner
		"billing\u00ad",        // soft hyphen
		"\u00a0billing\u3000",  // no-break and ideographic space
		"\uff53\uff56\uff43-x", // fullwidth "svc" then "-x"
		"s\u200bvc-x",
	} {
		assert.True(t, s.IsReservedClientID(id), "%q", id)
	}
	for _, id := range []string{
		"bi\u043bling", // Cyrillic el: another script, not a compatibility form
		"\u0431illing", // Cyrillic be
		"billing-x",
	} {
		assert.False(t, s.IsReservedClientID(id), "%q", id)
	}

	// Configured values go through the same normalisation.
	s.SetReservedClientIDs([]string{"\uff42illing"}, nil)
	assert.True(t, s.IsReservedClientID("billing"))
}

// An entry that normalises to nothing reserves nothing, rather than (as a
// prefix) every id.
func TestSetReservedClientIDs_SkipsEntriesThatNormaliseToNothing(t *testing.T) {
	s := &OAuthClientService{}
	s.SetReservedClientIDs([]string{"\u200b"}, []string{"\u200b", " "})
	assert.False(t, s.IsReservedClientID("anything"))
	assert.False(t, s.IsReservedClientID(""))
}
