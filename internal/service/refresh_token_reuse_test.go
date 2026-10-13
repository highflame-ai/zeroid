package service

import (
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/internal/oautherror"
)

// The refresh grant recognises reuse with errors.As, so the family id must
// survive any wrapping a later edit puts between RotateRefreshToken and the
// grant.
func TestRefreshTokenReuseError_SurvivesWrapping(t *testing.T) {
	familyID := NewRefreshFamilyID()
	err := fmt.Errorf("rotate: %w", &RefreshTokenReuseError{FamilyID: familyID})

	var reuse *RefreshTokenReuseError
	require.ErrorAs(t, err, &reuse)
	assert.Equal(t, familyID, reuse.FamilyID)
}

// The reuse error is mapped to the same invalid_grant as any other unusable
// refresh token. Its message is a cause for logs, never the client-facing
// description, so it must not carry the family id either.
func TestRefreshTokenReuseError_MapsToGenericInvalidGrant(t *testing.T) {
	familyID := NewRefreshFamilyID()
	reuse := oauthBadRequestCause(oautherror.InvalidGrant, "invalid or expired refresh token",
		&RefreshTokenReuseError{FamilyID: familyID})
	unknown := oauthBadRequestCause(oautherror.InvalidGrant, "invalid or expired refresh token",
		errors.New("refresh token not found"))

	assert.Equal(t, unknown.Error(), reuse.Error(),
		"a detected reuse must be indistinguishable from an unknown token to the caller")
	assert.NotContains(t, (&RefreshTokenReuseError{FamilyID: familyID}).Error(), familyID)
}

func TestNewRefreshFamilyID_IsAFreshUUID(t *testing.T) {
	a, b := NewRefreshFamilyID(), NewRefreshFamilyID()
	_, err := uuid.Parse(a)
	require.NoError(t, err, "refresh_tokens.family_id and issued_credentials.refresh_family_id are UUID columns")
	assert.NotEqual(t, a, b)
}
