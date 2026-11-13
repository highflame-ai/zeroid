package service

import (
	"context"
	"errors"
)

// ErrManagementKeyWriteNotTrusted is returned when a create-key request asks
// for the management mark and the request was not marked with
// WithManagementKeyWrite. Handlers map it to 403.
var ErrManagementKeyWriteNotTrusted = errors.New(
	"marking an API key for management requires a trusted management-key write")

type managementKeyWriteKey struct{}

// WithManagementKeyWrite marks ctx as coming from the caller the deployer
// trusts to mark API keys for management (ADR 0053 D3: Admin's internal path,
// after it has checked the person's role).
func WithManagementKeyWrite(ctx context.Context) context.Context {
	return context.WithValue(ctx, managementKeyWriteKey{}, true)
}

// ManagementKeyWrite reports whether ctx carries the mark set by
// WithManagementKeyWrite.
func ManagementKeyWrite(ctx context.Context) bool {
	v, _ := ctx.Value(managementKeyWriteKey{}).(bool)
	return v
}
