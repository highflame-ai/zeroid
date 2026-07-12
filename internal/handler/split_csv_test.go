package handler

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSplitCSV_SingleValue(t *testing.T) {
	got := splitCSV([]string{"active"})
	assert.Equal(t, []string{"active"}, got)
}

func TestSplitCSV_CommaSeparated(t *testing.T) {
	got := splitCSV([]string{"active,pending"})
	assert.Equal(t, []string{"active", "pending"}, got)
}

func TestSplitCSV_RepeatedQueryParam(t *testing.T) {
	got := splitCSV([]string{"active", "pending"})
	assert.Equal(t, []string{"active", "pending"}, got)
}

func TestSplitCSV_MixedCommaSeparatedAndRepeated(t *testing.T) {
	got := splitCSV([]string{"active,pending", "suspended"})
	assert.Equal(t, []string{"active", "pending", "suspended"}, got)
}

func TestSplitCSV_TrimsWhitespace(t *testing.T) {
	got := splitCSV([]string{" active , pending "})
	assert.Equal(t, []string{"active", "pending"}, got)
}

func TestSplitCSV_SkipsEmptySegments(t *testing.T) {
	got := splitCSV([]string{"active,,pending"})
	assert.Equal(t, []string{"active", "pending"}, got)
}

func TestSplitCSV_TrailingComma(t *testing.T) {
	got := splitCSV([]string{"active,"})
	assert.Equal(t, []string{"active"}, got)
}

func TestSplitCSV_EmptyInput(t *testing.T) {
	got := splitCSV([]string{})
	assert.Nil(t, got)
}

func TestSplitCSV_EmptyString(t *testing.T) {
	got := splitCSV([]string{""})
	assert.Nil(t, got)
}
