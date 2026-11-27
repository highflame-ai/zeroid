package handler

import (
	"reflect"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/highflame-ai/zeroid/domain"
)

// The OpenAPI description of max_delegation_depth states its range, which a
// struct tag can only spell as a literal: keep it equal to the limit the
// service enforces.
func TestCredentialPolicyDocs_StateDelegationDepthRange(t *testing.T) {
	limit := strconv.Itoa(domain.MaxDelegationDepthLimit)
	for name, body := range map[string]reflect.Type{
		"create": reflect.TypeFor[CreatePolicyInput]().Field(0).Type,
		"update": reflect.TypeFor[UpdatePolicyInput]().Field(1).Type,
	} {
		field, ok := body.FieldByName("MaxDelegationDepth")
		if assert.True(t, ok, name) {
			assert.Contains(t, field.Tag.Get("doc"), "from 0 (no delegation", name)
			assert.Contains(t, field.Tag.Get("doc"), "to "+limit, name)
		}
	}
}
