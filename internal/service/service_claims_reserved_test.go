package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestReservedServiceClaims is a tripwire, like TestClientIDIsReserved. A
// receiver identifies an internal service token from these claims, so each
// is worth something only while additional_claims cannot set it.
func TestReservedServiceClaims(t *testing.T) {
	for _, claim := range []string{"tenant_source", "resolved_user_id", "resolved_user_source", "act", "client_id"} {
		assert.True(t, reservedClaims[claim], "%s must be reserved: receivers trust it to be ZeroID's own", claim)
	}
}
