package service

import (
	"context"
	"errors"
	"slices"

	"github.com/highflame-ai/zeroid/domain"
)

// ErrApprovalChannelWriteNotTrusted is returned when a write would set the
// approval_channel sub-type or put the ciba:approve scope on an identity, a
// credential policy or an API key, and the request was not marked with
// WithTrustedApprovalChannelWrite. Handlers map it to 403.
var ErrApprovalChannelWriteNotTrusted = errors.New(
	"setting sub_type approval_channel or the ciba:approve scope requires a trusted approval-channel write")

type trustedApprovalChannelWriteKey struct{}

// WithTrustedApprovalChannelWrite marks ctx as coming from a caller the
// deployer trusts to create and manage approval channels.
func WithTrustedApprovalChannelWrite(ctx context.Context) context.Context {
	return context.WithValue(ctx, trustedApprovalChannelWriteKey{}, true)
}

// TrustedApprovalChannelWrite reports whether ctx carries the mark set by
// WithTrustedApprovalChannelWrite.
func TrustedApprovalChannelWrite(ctx context.Context) bool {
	v, _ := ctx.Value(trustedApprovalChannelWriteKey{}).(bool)
	return v
}

// grantsApprovalChannel reports whether a write sets the approval_channel
// sub-type or lists ciba:approve.
func grantsApprovalChannel(subType domain.SubType, scopes []string) bool {
	return subType == domain.SubTypeApprovalChannel || slices.Contains(scopes, domain.ScopeCIBAApprove)
}

// requireTrustedApprovalChannelWrite refuses a write that sets the
// approval_channel sub-type or lists ciba:approve unless ctx is trusted.
func requireTrustedApprovalChannelWrite(ctx context.Context, subType domain.SubType, scopes []string) error {
	if grantsApprovalChannel(subType, scopes) && !TrustedApprovalChannelWrite(ctx) {
		return ErrApprovalChannelWriteNotTrusted
	}
	return nil
}

// requireTrustedPolicyAttachment refuses attaching a credential policy that
// lists ciba:approve unless ctx is trusted. A policy that cannot be loaded is
// left to the caller's own lookup to report.
func requireTrustedPolicyAttachment(ctx context.Context, policySvc *CredentialPolicyService, policyID, accountID, projectID string) error {
	if policyID == "" || policySvc == nil || TrustedApprovalChannelWrite(ctx) {
		return nil
	}
	policy, err := policySvc.GetPolicy(ctx, policyID, accountID, projectID)
	if err != nil || policy == nil {
		return nil
	}
	if slices.Contains(policy.AllowedScopes, domain.ScopeCIBAApprove) {
		return ErrApprovalChannelWriteNotTrusted
	}
	return nil
}
