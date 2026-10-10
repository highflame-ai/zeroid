package service

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/highflame-ai/zeroid/domain"
)

// ErrApprovalChannelWriteNotTrusted is returned when a write would set the
// approval_channel sub-type or put the ciba:approve scope on an identity, a
// credential policy or an API key, or would issue a credential (API key,
// public key, OAuth client or client secret) for an approval channel, and the
// request was not marked with WithTrustedApprovalChannelWrite. Handlers map
// it to 403.
var ErrApprovalChannelWriteNotTrusted = errors.New(
	"setting sub_type approval_channel or the ciba:approve scope, or issuing a credential for an approval channel, requires a trusted approval-channel write")

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

// IsApprovalChannel reports whether identity is an approval channel: its
// sub_type is approval_channel, or its scope ceiling (its own allowed_scopes,
// or its credential policy, the tenant default when it has none) lists
// ciba:approve. A policy lookup failure is returned as an error.
func (s *IdentityService) IsApprovalChannel(ctx context.Context, identity *domain.Identity) (bool, error) {
	if identity == nil {
		return false, nil
	}
	if grantsApprovalChannel(identity.SubType, identity.AllowedScopes) {
		return true, nil
	}
	policy, err := s.ResolveCredentialPolicy(ctx, identity)
	if err != nil {
		return false, fmt.Errorf("resolve credential policy for approval-channel check: %w", err)
	}
	return policy != nil && slices.Contains(policy.AllowedScopes, domain.ScopeCIBAApprove), nil
}

// RequireTrustedCredentialWrite refuses issuing a credential for identity
// (an API key, a public key, an OAuth client bound to it) when identity is an
// approval channel and ctx is not marked with WithTrustedApprovalChannelWrite.
// It fails closed when the identity's policy cannot be loaded.
func (s *IdentityService) RequireTrustedCredentialWrite(ctx context.Context, identity *domain.Identity) error {
	if TrustedApprovalChannelWrite(ctx) {
		return nil
	}
	channel, err := s.IsApprovalChannel(ctx, identity)
	if err != nil {
		return err
	}
	if channel {
		return ErrApprovalChannelWriteNotTrusted
	}
	return nil
}
