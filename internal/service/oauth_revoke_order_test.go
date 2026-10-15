package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// RFC 7009 §2.1: the hint only orders the search; both token types are always
// tried. §2.2: an unknown hint is ignored.
func TestRevocationLookupOrder(t *testing.T) {
	both := []revocationKind{revocationKindAccess, revocationKindRefresh}
	assert.Equal(t, []revocationKind{revocationKindRefresh, revocationKindAccess}, revocationLookupOrder("refresh_token"))
	for _, hint := range []string{"", "access_token", "Refresh_Token", "id_token", "garbage"} {
		assert.Equal(t, both, revocationLookupOrder(hint), "hint %q", hint)
	}
	for _, hint := range []string{"", "refresh_token", "access_token", "garbage"} {
		assert.ElementsMatch(t, both, revocationLookupOrder(hint), "every type is searched for hint %q", hint)
	}
}
