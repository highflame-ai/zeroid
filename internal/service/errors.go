package service

import (
	"errors"
	"fmt"

	"github.com/uptrace/bun/driver/pgdriver"
)

// isDuplicateKeyError returns true if err is a PostgreSQL unique constraint violation (SQLSTATE 23505).
// Uses errors.As to handle wrapped errors from bun/pgdriver.
func isDuplicateKeyError(err error) bool {
	var pgErr pgdriver.Error
	return errors.As(err, &pgErr) && pgErr.Field('C') == "23505"
}

// IdentityDeactivatedConflictError is returned by RegisterIdentity when the
// external_id collides with an existing identity that is DEACTIVATED (soft
// deleted). Because deletes are soft, the deactivated row keeps the
// UNIQUE(account_id, project_id, external_id) slot, so registration can't reuse
// the external_id. Rather than an opaque "already exists" 409 — confusing
// because the conflicting identity is hidden from the default (active-only)
// registry view — this carries the existing identity's id so the caller can
// reactivate it (or knowingly choose a different external_id).
type IdentityDeactivatedConflictError struct {
	ExternalID string
	ExistingID string
}

func (e *IdentityDeactivatedConflictError) Error() string {
	return fmt.Sprintf(
		"an identity with external_id %q already exists but is deactivated (id: %s); reactivate it or register with a different external_id",
		e.ExternalID, e.ExistingID,
	)
}
