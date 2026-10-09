package integration_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"

	zeroid "github.com/highflame-ai/zeroid"
	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/oautherror"
	"github.com/highflame-ai/zeroid/internal/service"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// Approver binding for CIBA approve/deny: the approver identity is taken from
// the authenticated request context (zeroid.WithApproverIdentity), checked
// against the request's login_hint / group_hint / four_eyes parameters under
// backchannel.enforce_hints, and recorded on the row.
//
// Most subtests drive BackchannelService directly so each can pick its own
// RequireApproverIdentity / EnforceHints posture without touching the shared
// server; the HTTP subtests at the bottom pin the status codes and error
// envelope the admin endpoints return.

const testApproverIssuer = "https://idp.example.test"

// recordingAuthorizer is a test ApproverAuthorizer that records every call
// and returns a canned decision.
type recordingAuthorizer struct {
	mu       sync.Mutex
	calls    []zeroid.ApprovalRequestView
	decision zeroid.ApproverDecision
	err      error
	panics   bool
}

func (a *recordingAuthorizer) AuthorizeApprover(_ context.Context, req zeroid.ApprovalRequestView, _ zeroid.ApproverIdentity) (zeroid.ApproverDecision, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, req)
	if a.panics {
		panic("authorizer failure")
	}
	return a.decision, a.err
}

func (a *recordingAuthorizer) lastCall() *zeroid.ApprovalRequestView {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.calls) == 0 {
		return nil
	}
	c := a.calls[len(a.calls)-1]
	return &c
}

type approverSvcOpts struct {
	requireIdentity bool
	enforceHints    string
	authorizer      zeroid.ApproverAuthorizer
}

func newApproverBackchannelSvc(t *testing.T, o approverSvcOpts) (*service.BackchannelService, *postgres.BackchannelRequestRepository) {
	t.Helper()
	cfg := service.DefaultBackchannelConfig()
	cfg.RequireApproverIdentity = o.requireIdentity
	cfg.EnforceHints = o.enforceHints
	repo := postgres.NewBackchannelRequestRepository(testDB)
	svc := service.NewBackchannelService(repo, service.NewOAuthClientService(postgres.NewOAuthClientRepository(testDB)), nil, nil, cfg)
	if o.authorizer != nil {
		svc.SetApproverAuthorizer(o.authorizer)
	}
	return svc, repo
}

func createApproverTestRequest(t *testing.T, svc *service.BackchannelService, mutate func(in *service.CreateAuthRequestInput)) string {
	t.Helper()
	clientID := uid("ciba-approver")
	registerTestOAuthClient(clientID, []string{"client_credentials"})
	in := service.CreateAuthRequestInput{
		ClientID:  clientID,
		AccountID: testAccountID,
		ProjectID: testProjectID,
		Scope:     "openid",
	}
	mutate(&in)
	out, err := svc.CreateAuthRequest(context.Background(), in)
	require.NoError(t, err)
	return out.AuthReqID
}

func approverCtx(sub string) context.Context {
	return zeroid.WithApproverIdentity(context.Background(), zeroid.ApproverIdentity{
		Subject: sub,
		Issuer:  testApproverIssuer,
		Auth:    zeroid.ApproverAuthSession,
		Email:   sub + "@example.test",
		Name:    "Approver " + sub,
	})
}

func approveIn(authReqID string) service.ApproveInput {
	return service.ApproveInput{AuthReqID: authReqID, AccountID: testAccountID, ProjectID: testProjectID}
}

func denyIn(authReqID string) service.DenyInput {
	return service.DenyInput{AuthReqID: authReqID, AccountID: testAccountID, ProjectID: testProjectID}
}

func requireOAuthStatus(t *testing.T, err error, wantCode string, wantStatus int) *service.OAuthError {
	t.Helper()
	require.Error(t, err)
	var oe *service.OAuthError
	require.True(t, errors.As(err, &oe), "expected *service.OAuthError, got %T: %v", err, err)
	require.Equal(t, wantCode, oe.Code, "OAuth error code (err=%v)", err)
	require.Equal(t, wantStatus, oe.HTTPStatus, "HTTP status (err=%v)", err)
	return oe
}

func loadBackchannelRow(t *testing.T, repo *postgres.BackchannelRequestRepository, id string) *domain.BackchannelAuthRequest {
	t.Helper()
	row, err := repo.GetByAuthReqID(context.Background(), id)
	require.NoError(t, err)
	return row
}

func TestCIBAApproverIdentity(t *testing.T) {
	t.Run("ContextHelpers_RoundTrip", func(t *testing.T) {
		_, ok := zeroid.ApproverIdentityFromContext(context.Background())
		require.False(t, ok)
		got, ok := zeroid.ApproverIdentityFromContext(approverCtx("user-rt"))
		require.True(t, ok)
		require.Equal(t, "user-rt", got.Subject)
		require.Equal(t, testApproverIssuer, got.Issuer)
		require.Equal(t, zeroid.ApproverAuthSession, got.Auth)
	})

	t.Run("Required_MissingIdentity_ApproveRefused", func(t *testing.T) {
		svc, repo := newApproverBackchannelSvc(t, approverSvcOpts{requireIdentity: true})
		id := createApproverTestRequest(t, svc, func(in *service.CreateAuthRequestInput) { in.LoginHint = "user-a" })

		in := approveIn(id)
		in.SubjectID = "user-a" // a body subject alone is not enough
		oe := requireOAuthStatus(t, svc.Approve(context.Background(), in), oautherror.InvalidClient, http.StatusUnauthorized)
		require.Equal(t, "approver identity required", oe.Description)
		require.Equal(t, domain.BackchannelStatusPending, loadBackchannelRow(t, repo, id).Status)
	})

	t.Run("Required_MissingIdentity_DenyRefused", func(t *testing.T) {
		svc, repo := newApproverBackchannelSvc(t, approverSvcOpts{requireIdentity: true})
		id := createApproverTestRequest(t, svc, func(in *service.CreateAuthRequestInput) { in.LoginHint = "user-a" })

		oe := requireOAuthStatus(t, svc.Deny(context.Background(), denyIn(id)), oautherror.InvalidClient, http.StatusUnauthorized)
		require.Equal(t, "approver identity required", oe.Description)
		require.Equal(t, domain.BackchannelStatusPending, loadBackchannelRow(t, repo, id).Status)
	})

	t.Run("BodySubjectMismatch_Refused", func(t *testing.T) {
		svc, repo := newApproverBackchannelSvc(t, approverSvcOpts{requireIdentity: true})
		id := createApproverTestRequest(t, svc, func(in *service.CreateAuthRequestInput) { in.LoginHint = "user-a" })

		in := approveIn(id)
		in.SubjectID = "someone-else"
		oe := requireOAuthStatus(t, svc.Approve(approverCtx("user-a"), in), oautherror.InvalidRequest, http.StatusBadRequest)
		require.Equal(t, "subject_id does not match the authenticated approver", oe.Description)
		require.Equal(t, domain.BackchannelStatusPending, loadBackchannelRow(t, repo, id).Status)
	})

	t.Run("BodySubjectMismatch_RefusedEvenWhenNotRequired", func(t *testing.T) {
		svc, _ := newApproverBackchannelSvc(t, approverSvcOpts{})
		id := createApproverTestRequest(t, svc, func(in *service.CreateAuthRequestInput) { in.LoginHint = "user-a" })

		in := approveIn(id)
		in.SubjectID = "someone-else"
		requireOAuthStatus(t, svc.Approve(approverCtx("user-a"), in), oautherror.InvalidRequest, http.StatusBadRequest)
	})

	t.Run("ContextIdentity_RecordedOnApprove", func(t *testing.T) {
		svc, repo := newApproverBackchannelSvc(t, approverSvcOpts{requireIdentity: true})
		id := createApproverTestRequest(t, svc, func(in *service.CreateAuthRequestInput) { in.LoginHint = "user-a" })

		// Body subject equal to the context subject is accepted; body
		// display fields are ignored in favour of the context's.
		in := approveIn(id)
		in.SubjectID = "user-a"
		in.SubjectEmail = "body@example.test"
		require.NoError(t, svc.Approve(approverCtx("user-a"), in))

		row := loadBackchannelRow(t, repo, id)
		require.Equal(t, domain.BackchannelStatusApproved, row.Status)
		require.Equal(t, "user-a", row.ApprovedSubjectID)
		require.Equal(t, "user-a@example.test", row.ApprovedSubjectEmail)
		require.Equal(t, "Approver user-a", row.ApprovedSubjectName)
		require.Equal(t, testApproverIssuer, row.ApproverIss)
		require.Equal(t, "session", row.ApproverAuth)
		require.Empty(t, row.ChannelClientID)
	})

	t.Run("ChannelAttestedIdentity_Recorded", func(t *testing.T) {
		svc, repo := newApproverBackchannelSvc(t, approverSvcOpts{requireIdentity: true})
		id := createApproverTestRequest(t, svc, func(in *service.CreateAuthRequestInput) { in.LoginHint = "user-c" })

		ctx := zeroid.WithApproverIdentity(context.Background(), zeroid.ApproverIdentity{
			Subject:         "user-c",
			Issuer:          "https://slack.example.test",
			Auth:            zeroid.ApproverAuthChannelAttested,
			ChannelClientID: "approval-channel-1",
		})
		require.NoError(t, svc.Approve(ctx, approveIn(id)))

		row := loadBackchannelRow(t, repo, id)
		require.Equal(t, "user-c", row.ApprovedSubjectID)
		require.Equal(t, "channel_attested", row.ApproverAuth)
		require.Equal(t, "approval-channel-1", row.ChannelClientID)
		require.Equal(t, "https://slack.example.test", row.ApproverIss)
	})

	t.Run("NotRequired_BodySubjectStillAccepted", func(t *testing.T) {
		svc, repo := newApproverBackchannelSvc(t, approverSvcOpts{})
		id := createApproverTestRequest(t, svc, func(in *service.CreateAuthRequestInput) { in.LoginHint = "user-a" })

		in := approveIn(id)
		in.SubjectID = "user-body"
		in.SubjectEmail = "body@example.test"
		require.NoError(t, svc.Approve(context.Background(), in))

		row := loadBackchannelRow(t, repo, id)
		require.Equal(t, "user-body", row.ApprovedSubjectID)
		require.Equal(t, "body@example.test", row.ApprovedSubjectEmail)
		require.Empty(t, row.ApproverIss)
		require.Empty(t, row.ApproverAuth)
		require.Empty(t, row.HintSatisfied)
		require.False(t, row.ShadowWouldDeny)
	})

	t.Run("NotRequired_DenyWithoutIdentityUnchanged", func(t *testing.T) {
		svc, repo := newApproverBackchannelSvc(t, approverSvcOpts{})
		id := createApproverTestRequest(t, svc, func(in *service.CreateAuthRequestInput) { in.LoginHint = "user-a" })
		require.NoError(t, svc.Deny(context.Background(), denyIn(id)))
		require.Equal(t, domain.BackchannelStatusDenied, loadBackchannelRow(t, repo, id).Status)
	})
}

func TestCIBAApproverBinding(t *testing.T) {
	// The approver comes from the request context in every subtest, so these
	// run with RequireApproverIdentity off: a group_hint-only request then
	// needs no requesting_token (see TestCIBARequestingToken).
	t.Run("On_LoginHintMismatch_Forbidden", func(t *testing.T) {
		svc, repo := newApproverBackchannelSvc(t, approverSvcOpts{enforceHints: "on"})
		id := createApproverTestRequest(t, svc, func(in *service.CreateAuthRequestInput) { in.LoginHint = "user-a" })

		oe := requireOAuthStatus(t, svc.Approve(approverCtx("user-b"), approveIn(id)), oautherror.AccessDenied, http.StatusForbidden)
		require.Contains(t, oe.Description, "login_hint")
		require.Equal(t, domain.BackchannelStatusPending, loadBackchannelRow(t, repo, id).Status)
	})

	t.Run("On_LoginHintMatch_ApprovedAndRecorded", func(t *testing.T) {
		svc, repo := newApproverBackchannelSvc(t, approverSvcOpts{enforceHints: "on"})
		id := createApproverTestRequest(t, svc, func(in *service.CreateAuthRequestInput) { in.LoginHint = "user-a" })

		require.NoError(t, svc.Approve(approverCtx("user-a"), approveIn(id)))
		row := loadBackchannelRow(t, repo, id)
		require.Equal(t, domain.BackchannelStatusApproved, row.Status)
		require.Equal(t, "login_hint", row.HintSatisfied)
		require.NotNil(t, row.ApprovedAt)
		require.Nil(t, row.DeniedAt)
		require.False(t, row.ShadowWouldDeny)
	})

	t.Run("On_FourEyes_RequesterOwnerCannotApprove", func(t *testing.T) {
		authz := &recordingAuthorizer{decision: zeroid.ApproverDecision{Allowed: true, SatisfiedHint: "group_hint"}}
		svc, repo := newApproverBackchannelSvc(t, approverSvcOpts{enforceHints: "on", authorizer: authz})
		id := createApproverTestRequest(t, svc, func(in *service.CreateAuthRequestInput) {
			in.GroupHint = "highflame:role:admin"
			in.FourEyes = true
			in.RequesterOwner = "user-owner"
		})

		oe := requireOAuthStatus(t, svc.Approve(approverCtx("user-owner"), approveIn(id)), oautherror.AccessDenied, http.StatusForbidden)
		require.Contains(t, oe.Description, "other than the requester owner")
		require.Equal(t, domain.BackchannelStatusPending, loadBackchannelRow(t, repo, id).Status)

		// A different eligible approver succeeds.
		require.NoError(t, svc.Approve(approverCtx("user-admin"), approveIn(id)))
		row := loadBackchannelRow(t, repo, id)
		require.Equal(t, domain.BackchannelStatusApproved, row.Status)
		require.Equal(t, "group_hint", row.HintSatisfied)
	})

	t.Run("On_FourEyesWithoutFlag_RequesterOwnerMayApprove", func(t *testing.T) {
		svc, _ := newApproverBackchannelSvc(t, approverSvcOpts{enforceHints: "on"})
		id := createApproverTestRequest(t, svc, func(in *service.CreateAuthRequestInput) {
			in.LoginHint = "user-owner"
			in.RequesterOwner = "user-owner"
		})
		require.NoError(t, svc.Approve(approverCtx("user-owner"), approveIn(id)))
	})

	t.Run("On_GroupHint_NoAuthorizer_Forbidden", func(t *testing.T) {
		svc, _ := newApproverBackchannelSvc(t, approverSvcOpts{enforceHints: "on"})
		id := createApproverTestRequest(t, svc, func(in *service.CreateAuthRequestInput) { in.GroupHint = "highflame:role:admin" })

		oe := requireOAuthStatus(t, svc.Approve(approverCtx("user-a"), approveIn(id)), oautherror.AccessDenied, http.StatusForbidden)
		require.Equal(t, "no approver authorizer configured", oe.Description)
	})

	t.Run("On_GroupHint_AuthorizerDenies_ReasonSurfaced", func(t *testing.T) {
		authz := &recordingAuthorizer{decision: zeroid.ApproverDecision{Allowed: false, Reason: "approval requires role admin"}}
		svc, repo := newApproverBackchannelSvc(t, approverSvcOpts{enforceHints: "on", authorizer: authz})
		id := createApproverTestRequest(t, svc, func(in *service.CreateAuthRequestInput) {
			in.GroupHint = "highflame:role:admin"
			in.FourEyes = true
			in.RequesterOwner = "user-owner"
		})

		oe := requireOAuthStatus(t, svc.Approve(approverCtx("user-a"), approveIn(id)), oautherror.AccessDenied, http.StatusForbidden)
		require.Equal(t, "approval requires role admin", oe.Description)
		require.Equal(t, domain.BackchannelStatusPending, loadBackchannelRow(t, repo, id).Status)

		call := authz.lastCall()
		require.NotNil(t, call)
		require.Equal(t, id, call.AuthReqID)
		require.Equal(t, testAccountID, call.AccountID)
		require.Equal(t, testProjectID, call.ProjectID)
		require.Equal(t, "highflame:role:admin", call.GroupHint)
		require.True(t, call.FourEyes)
		require.Equal(t, "user-owner", call.RequesterOwner)
	})

	t.Run("On_GroupHint_AuthorizerAllows", func(t *testing.T) {
		authz := &recordingAuthorizer{decision: zeroid.ApproverDecision{Allowed: true, SatisfiedHint: "group_hint"}}
		svc, repo := newApproverBackchannelSvc(t, approverSvcOpts{enforceHints: "on", authorizer: authz})
		id := createApproverTestRequest(t, svc, func(in *service.CreateAuthRequestInput) { in.GroupHint = "highflame:role:admin" })

		require.NoError(t, svc.Approve(approverCtx("user-admin"), approveIn(id)))
		require.Equal(t, "group_hint", loadBackchannelRow(t, repo, id).HintSatisfied)
	})

	t.Run("On_LoginHintOnly_AuthorizerNotConsulted", func(t *testing.T) {
		authz := &recordingAuthorizer{decision: zeroid.ApproverDecision{Allowed: false, Reason: "unused"}}
		svc, _ := newApproverBackchannelSvc(t, approverSvcOpts{enforceHints: "on", authorizer: authz})
		id := createApproverTestRequest(t, svc, func(in *service.CreateAuthRequestInput) { in.LoginHint = "user-a" })

		require.NoError(t, svc.Approve(approverCtx("user-a"), approveIn(id)))
		require.Nil(t, authz.lastCall())
	})

	t.Run("On_BothHints_BothMustPass", func(t *testing.T) {
		authz := &recordingAuthorizer{decision: zeroid.ApproverDecision{Allowed: true, SatisfiedHint: "group_hint"}}
		svc, _ := newApproverBackchannelSvc(t, approverSvcOpts{enforceHints: "on", authorizer: authz})
		id := createApproverTestRequest(t, svc, func(in *service.CreateAuthRequestInput) {
			in.LoginHint = "user-a"
			in.GroupHint = "highflame:role:admin"
		})
		requireOAuthStatus(t, svc.Approve(approverCtx("user-b"), approveIn(id)), oautherror.AccessDenied, http.StatusForbidden)
	})

	t.Run("On_AuthorizerError_FailsClosed", func(t *testing.T) {
		authz := &recordingAuthorizer{err: errors.New("membership lookup unavailable")}
		svc, _ := newApproverBackchannelSvc(t, approverSvcOpts{enforceHints: "on", authorizer: authz})
		id := createApproverTestRequest(t, svc, func(in *service.CreateAuthRequestInput) { in.GroupHint = "highflame:role:admin" })

		oe := requireOAuthStatus(t, svc.Approve(approverCtx("user-a"), approveIn(id)), oautherror.AccessDenied, http.StatusForbidden)
		require.NotContains(t, oe.Description, "membership lookup unavailable", "authorizer error detail must not reach the caller")
	})

	t.Run("On_AuthorizerPanic_FailsClosed", func(t *testing.T) {
		authz := &recordingAuthorizer{panics: true}
		svc, _ := newApproverBackchannelSvc(t, approverSvcOpts{enforceHints: "on", authorizer: authz})
		id := createApproverTestRequest(t, svc, func(in *service.CreateAuthRequestInput) { in.GroupHint = "highflame:role:admin" })

		requireOAuthStatus(t, svc.Approve(approverCtx("user-a"), approveIn(id)), oautherror.AccessDenied, http.StatusForbidden)
	})

	t.Run("On_UnknownApprover_NotRequired_Unauthorized", func(t *testing.T) {
		// Hints are enforced but the deployment does not supply an approver
		// identity: a deny has no subject to check, so it is refused.
		svc, _ := newApproverBackchannelSvc(t, approverSvcOpts{enforceHints: "on"})
		id := createApproverTestRequest(t, svc, func(in *service.CreateAuthRequestInput) { in.LoginHint = "user-a" })
		requireOAuthStatus(t, svc.Deny(context.Background(), denyIn(id)), oautherror.InvalidClient, http.StatusUnauthorized)

		// The legacy body subject is checked against login_hint.
		in := approveIn(id)
		in.SubjectID = "user-b"
		requireOAuthStatus(t, svc.Approve(context.Background(), in), oautherror.AccessDenied, http.StatusForbidden)
		in.SubjectID = "user-a"
		require.NoError(t, svc.Approve(context.Background(), in))
	})

	t.Run("Shadow_IneligibleApprover_AllowedAndRecorded", func(t *testing.T) {
		svc, repo := newApproverBackchannelSvc(t, approverSvcOpts{enforceHints: "shadow"})
		id := createApproverTestRequest(t, svc, func(in *service.CreateAuthRequestInput) { in.LoginHint = "user-a" })

		require.NoError(t, svc.Approve(approverCtx("user-b"), approveIn(id)))
		row := loadBackchannelRow(t, repo, id)
		require.Equal(t, domain.BackchannelStatusApproved, row.Status)
		require.Equal(t, "user-b", row.ApprovedSubjectID)
		require.True(t, row.ShadowWouldDeny)
		require.Contains(t, row.ShadowReason, "login_hint")
		require.Empty(t, row.HintSatisfied)
	})

	t.Run("Shadow_GroupHintWithoutAuthorizer_AllowedAndRecorded", func(t *testing.T) {
		svc, repo := newApproverBackchannelSvc(t, approverSvcOpts{enforceHints: "shadow"})
		id := createApproverTestRequest(t, svc, func(in *service.CreateAuthRequestInput) { in.GroupHint = "highflame:role:admin" })

		require.NoError(t, svc.Approve(approverCtx("user-b"), approveIn(id)))
		row := loadBackchannelRow(t, repo, id)
		require.True(t, row.ShadowWouldDeny)
		require.Equal(t, "no approver authorizer configured", row.ShadowReason)
	})

	t.Run("Shadow_EligibleApprover_NoWouldDeny", func(t *testing.T) {
		svc, repo := newApproverBackchannelSvc(t, approverSvcOpts{enforceHints: "shadow"})
		id := createApproverTestRequest(t, svc, func(in *service.CreateAuthRequestInput) { in.LoginHint = "user-a" })

		require.NoError(t, svc.Approve(approverCtx("user-a"), approveIn(id)))
		row := loadBackchannelRow(t, repo, id)
		require.False(t, row.ShadowWouldDeny)
		require.Empty(t, row.ShadowReason)
		require.Equal(t, "login_hint", row.HintSatisfied)
	})

	t.Run("Off_IneligibleApprover_AllowedWithoutChecks", func(t *testing.T) {
		authz := &recordingAuthorizer{decision: zeroid.ApproverDecision{Allowed: false}}
		svc, repo := newApproverBackchannelSvc(t, approverSvcOpts{enforceHints: "off", authorizer: authz})
		id := createApproverTestRequest(t, svc, func(in *service.CreateAuthRequestInput) { in.GroupHint = "highflame:role:admin" })

		require.NoError(t, svc.Approve(approverCtx("user-b"), approveIn(id)))
		row := loadBackchannelRow(t, repo, id)
		require.Equal(t, domain.BackchannelStatusApproved, row.Status)
		require.False(t, row.ShadowWouldDeny)
		require.Empty(t, row.HintSatisfied)
		require.Nil(t, authz.lastCall(), "off must not consult the authorizer")
	})

	t.Run("Deny_SameRules_On", func(t *testing.T) {
		svc, repo := newApproverBackchannelSvc(t, approverSvcOpts{enforceHints: "on"})
		id := createApproverTestRequest(t, svc, func(in *service.CreateAuthRequestInput) { in.LoginHint = "user-a" })

		oe := requireOAuthStatus(t, svc.Deny(approverCtx("user-b"), denyIn(id)), oautherror.AccessDenied, http.StatusForbidden)
		require.Contains(t, oe.Description, "login_hint")
		require.Equal(t, domain.BackchannelStatusPending, loadBackchannelRow(t, repo, id).Status)

		require.NoError(t, svc.Deny(approverCtx("user-a"), denyIn(id)))
		row := loadBackchannelRow(t, repo, id)
		require.Equal(t, domain.BackchannelStatusDenied, row.Status)
		require.Equal(t, "user-a", row.ApprovedSubjectID, "the resolving user is recorded on deny")
		require.NotNil(t, row.DeniedAt, "deny records when the request was resolved")
		require.Nil(t, row.ApprovedAt)
		require.Equal(t, testApproverIssuer, row.ApproverIss)
		require.Equal(t, "session", row.ApproverAuth)
		require.Equal(t, "login_hint", row.HintSatisfied)
	})

	t.Run("Deny_SameRules_FourEyes", func(t *testing.T) {
		svc, _ := newApproverBackchannelSvc(t, approverSvcOpts{enforceHints: "on"})
		id := createApproverTestRequest(t, svc, func(in *service.CreateAuthRequestInput) {
			in.LoginHint = "user-owner"
			in.FourEyes = true
			in.RequesterOwner = "user-owner"
		})
		requireOAuthStatus(t, svc.Deny(approverCtx("user-owner"), denyIn(id)), oautherror.AccessDenied, http.StatusForbidden)
	})

	t.Run("Deny_Shadow_RecordsWouldDeny", func(t *testing.T) {
		svc, repo := newApproverBackchannelSvc(t, approverSvcOpts{enforceHints: "shadow"})
		id := createApproverTestRequest(t, svc, func(in *service.CreateAuthRequestInput) { in.LoginHint = "user-a" })

		require.NoError(t, svc.Deny(approverCtx("user-b"), denyIn(id)))
		row := loadBackchannelRow(t, repo, id)
		require.Equal(t, domain.BackchannelStatusDenied, row.Status)
		require.True(t, row.ShadowWouldDeny)
		require.Contains(t, row.ShadowReason, "login_hint")
	})
}

func TestCIBAFourEyesParameters(t *testing.T) {
	t.Run("Service_PersistedAndNotified", func(t *testing.T) {
		svc, repo := newApproverBackchannelSvc(t, approverSvcOpts{})
		var got service.BackchannelNotification
		svc.SetNotifyDispatchSync(true)
		svc.SetNotifier(func(_ context.Context, n service.BackchannelNotification) error {
			got = n
			return nil
		})
		id := createApproverTestRequest(t, svc, func(in *service.CreateAuthRequestInput) {
			in.GroupHint = "highflame:role:admin"
			in.FourEyes = true
			in.RequesterOwner = "user-owner"
		})
		row := loadBackchannelRow(t, repo, id)
		require.True(t, row.FourEyes)
		require.Equal(t, "user-owner", row.RequesterOwner)
		require.True(t, got.FourEyes)
		require.Equal(t, "user-owner", got.RequesterOwner)
	})

	t.Run("Service_FourEyesRequiresRequesterOwner", func(t *testing.T) {
		svc, _ := newApproverBackchannelSvc(t, approverSvcOpts{})
		clientID := uid("ciba-4eyes")
		registerTestOAuthClient(clientID, []string{"client_credentials"})
		_, err := svc.CreateAuthRequest(context.Background(), service.CreateAuthRequestInput{
			ClientID: clientID, AccountID: testAccountID, ProjectID: testProjectID,
			GroupHint: "highflame:role:admin", FourEyes: true,
		})
		requireOAuthStatus(t, err, oautherror.InvalidRequest, http.StatusBadRequest)
	})

	t.Run("HTTP_ParamsPersisted", func(t *testing.T) {
		clientID := uid("ciba-4eyes-http")
		registerTestOAuthClient(clientID, []string{"client_credentials"})
		notifier := newRecordingNotifier()
		testZeroIDServer.SetBackchannelNotifier(notifier.notify)
		testZeroIDServer.SetBackchannelNotifyDispatchSync(true)
		t.Cleanup(func() {
			testZeroIDServer.SetBackchannelNotifyDispatchSync(false)
			testZeroIDServer.SetBackchannelNotifier(nil)
		})

		resp := post(t, "/oauth2/bc-authorize", map[string]any{
			"client_id": clientID, "account_id": testAccountID, "project_id": testProjectID,
			"group_hint": "highflame:role:admin", "four_eyes": "true", "requester_owner": "user-owner",
		}, nil)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		id, _ := decode(t, resp)["auth_req_id"].(string)

		row := loadBackchannelRow(t, postgres.NewBackchannelRequestRepository(testDB), id)
		require.True(t, row.FourEyes)
		require.Equal(t, "user-owner", row.RequesterOwner)
		n := notifier.last()
		require.NotNil(t, n)
		require.True(t, n.FourEyes)
		require.Equal(t, "user-owner", n.RequesterOwner)
	})

	t.Run("HTTP_FourEyesFalseAccepted", func(t *testing.T) {
		clientID := uid("ciba-4eyes-false")
		registerTestOAuthClient(clientID, []string{"client_credentials"})
		resp := post(t, "/oauth2/bc-authorize", map[string]any{
			"client_id": clientID, "account_id": testAccountID, "project_id": testProjectID,
			"login_hint": "user-a", "four_eyes": "false",
		}, nil)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		id, _ := decode(t, resp)["auth_req_id"].(string)
		require.False(t, loadBackchannelRow(t, postgres.NewBackchannelRequestRepository(testDB), id).FourEyes)
	})

	t.Run("HTTP_FourEyesInvalidValue", func(t *testing.T) {
		clientID := uid("ciba-4eyes-bad")
		registerTestOAuthClient(clientID, []string{"client_credentials"})
		resp := post(t, "/oauth2/bc-authorize", map[string]any{
			"client_id": clientID, "account_id": testAccountID, "project_id": testProjectID,
			"login_hint": "user-a", "four_eyes": "maybe",
		}, nil)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		require.Equal(t, "invalid_request", decode(t, resp)["error"])
	})
}

// TestCIBAApproverHTTP pins the admin endpoints' status codes and OAuth error
// envelope. The shared server's posture is toggled for the duration of the
// test and restored afterwards; the approver identity is injected by the test
// middleware installed in TestMain (testApproverSubHeader).
func TestCIBAApproverHTTP(t *testing.T) {
	testZeroIDServer.SetBackchannelNotifyDispatchSync(true)
	t.Cleanup(func() {
		testZeroIDServer.SetBackchannelNotifyDispatchSync(false)
		require.NoError(t, testZeroIDServer.SetBackchannelEnforceHints("off"))
		require.NoError(t, testZeroIDServer.SetBackchannelRequireApproverIdentity(false))
	})
	require.Error(t, testZeroIDServer.SetBackchannelEnforceHints("on"), "enforce_hints needs require_approver_identity")
	require.NoError(t, testZeroIDServer.SetBackchannelRequireApproverIdentity(true))
	require.NoError(t, testZeroIDServer.SetBackchannelEnforceHints("on"))
	require.Error(t, testZeroIDServer.SetBackchannelEnforceHints("strict"), "unknown modes are rejected")
	require.Error(t, testZeroIDServer.SetBackchannelRequireApproverIdentity(false), "require_approver_identity stays on while enforce_hints is on")

	newRequest := func(t *testing.T, loginHint string) string {
		t.Helper()
		clientID := uid("ciba-approver-http")
		registerTestOAuthClient(clientID, []string{"client_credentials"})
		resp := post(t, "/oauth2/bc-authorize", map[string]any{
			"client_id": clientID, "account_id": testAccountID, "project_id": testProjectID,
			"login_hint": loginHint,
		}, nil)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		id, _ := decode(t, resp)["auth_req_id"].(string)
		return id
	}
	headersAs := func(sub string) map[string]string {
		h := adminHeaders()
		if sub != "" {
			h[testApproverSubHeader] = sub
		}
		return h
	}

	t.Run("MissingIdentity_401", func(t *testing.T) {
		id := newRequest(t, "user-a")
		resp := post(t, adminPath("/oauth2/bc-authorize/"+id+"/approve"), map[string]any{"subject_id": "user-a"}, headersAs(""))
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		body := decode(t, resp)
		require.Equal(t, "invalid_client", body["error"])
		require.Equal(t, "approver identity required", body["error_description"])

		resp = post(t, adminPath("/oauth2/bc-authorize/"+id+"/deny"), nil, headersAs(""))
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		_ = resp.Body.Close()
	})

	t.Run("BodySubjectMismatch_400", func(t *testing.T) {
		id := newRequest(t, "user-a")
		resp := post(t, adminPath("/oauth2/bc-authorize/"+id+"/approve"), map[string]any{"subject_id": "user-z"}, headersAs("user-a"))
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		body := decode(t, resp)
		require.Equal(t, "invalid_request", body["error"])
		require.Equal(t, "subject_id does not match the authenticated approver", body["error_description"])
	})

	t.Run("IneligibleApprover_403", func(t *testing.T) {
		id := newRequest(t, "user-a")
		resp := post(t, adminPath("/oauth2/bc-authorize/"+id+"/approve"), map[string]any{}, headersAs("user-b"))
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
		body := decode(t, resp)
		require.Equal(t, "access_denied", body["error"])
		require.Contains(t, body["error_description"], "login_hint")

		resp = post(t, adminPath("/oauth2/bc-authorize/"+id+"/deny"), nil, headersAs("user-b"))
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
		_ = resp.Body.Close()
	})

	t.Run("EligibleApprover_NoBodySubject_200", func(t *testing.T) {
		id := newRequest(t, "user-a")
		resp := post(t, adminPath("/oauth2/bc-authorize/"+id+"/approve"), map[string]any{}, headersAs("user-a"))
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, "approved", decode(t, resp)["status"])

		row := loadBackchannelRow(t, postgres.NewBackchannelRequestRepository(testDB), id)
		require.Equal(t, "user-a", row.ApprovedSubjectID)
		require.Equal(t, testApproverIssuer, row.ApproverIss)
		require.Equal(t, "login_hint", row.HintSatisfied)
	})

	t.Run("EligibleDenier_200", func(t *testing.T) {
		id := newRequest(t, "user-a")
		resp := post(t, adminPath("/oauth2/bc-authorize/"+id+"/deny"), nil, headersAs("user-a"))
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, "denied", decode(t, resp)["status"])
	})
}

// TestCIBAApproverMigration applies the approver-binding migration's down and
// up scripts inside a transaction that is rolled back, so the shared schema
// is left untouched.
func TestCIBAApproverMigration(t *testing.T) {
	ctx := context.Background()
	const name = "051_ciba_approver_binding"
	up, err := fs.ReadFile(zeroid.MigrationFiles(), name+".up.sql")
	require.NoError(t, err)
	down, err := fs.ReadFile(zeroid.MigrationFiles(), name+".down.sql")
	require.NoError(t, err)

	columns := []string{
		"four_eyes", "requester_owner", "requester_sub", "requester_actor",
		"requesting_jti", "requesting_act", "approver_iss", "approver_auth",
		"channel_client_id", "hint_satisfied", "shadow_would_deny", "shadow_reason", "denied_at",
	}
	countColumns := func(tx bun.Tx) int {
		var n int
		require.NoError(t, tx.QueryRowContext(ctx,
			`SELECT count(*) FROM information_schema.columns
			 WHERE table_name = 'backchannel_auth_requests' AND column_name IN (?)`,
			bun.In(columns)).Scan(&n))
		return n
	}

	tx, err := testDB.BeginTx(ctx, &sql.TxOptions{})
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()

	require.Equal(t, len(columns), countColumns(tx), "migration must be applied by the suite")
	_, err = tx.ExecContext(ctx, string(down))
	require.NoError(t, err)
	require.Equal(t, 0, countColumns(tx), "down must drop every column")
	_, err = tx.ExecContext(ctx, string(up))
	require.NoError(t, err)
	require.Equal(t, len(columns), countColumns(tx), "up must add every column")
}

// TestCIBAApproveScopeRefusedForAgentIdentity pins that the ciba:approve
// scope is never minted for an agent identity, even when its ceiling lists it.
func TestCIBAApproveScopeRefusedForAgentIdentity(t *testing.T) {
	externalID := uid("agent-ciba-approve")
	resp := post(t, adminPath("/agents/register"), map[string]any{
		"name":           externalID,
		"external_id":    externalID,
		"sub_type":       "tool_agent",
		"trust_level":    "first_party",
		"created_by":     "test-user",
		"allowed_scopes": []string{"tools:read", "ciba:approve"},
	}, channelWriteHeaders())
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	apiKey, _ := decode(t, resp)["api_key"].(string)
	require.NotEmpty(t, apiKey)

	tokenResp := post(t, "/oauth2/token", map[string]any{
		"grant_type": "api_key",
		"api_key":    apiKey,
		"scope":      "ciba:approve",
	}, nil)
	require.Equal(t, http.StatusBadRequest, tokenResp.StatusCode)
	body := decode(t, tokenResp)
	require.NotEmpty(t, body["error"])

	// Other scopes on the same ceiling still mint.
	ok := post(t, "/oauth2/token", map[string]any{
		"grant_type": "api_key",
		"api_key":    apiKey,
		"scope":      "tools:read",
	}, nil)
	require.Equal(t, http.StatusOK, ok.StatusCode)
	_ = ok.Body.Close()
}

// registerServiceIdentity registers a service identity through the admin API,
// as a trusted approval-channel write, and returns its bootstrap API key.
func registerServiceIdentity(t *testing.T, identityType, subType string, allowedScopes []string, policyID string) string {
	t.Helper()
	externalID := uid("svc-ciba-approve")
	body := map[string]any{
		"name":          externalID,
		"external_id":   externalID,
		"identity_type": identityType,
		"created_by":    "test-user",
	}
	if subType != "" {
		body["sub_type"] = subType
	}
	if allowedScopes != nil {
		body["allowed_scopes"] = allowedScopes
	}
	if policyID != "" {
		body["credential_policy_id"] = policyID
	}
	resp := post(t, adminPath("/agents/register"), body, channelWriteHeaders())
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	apiKey, _ := decode(t, resp)["api_key"].(string)
	require.NotEmpty(t, apiKey)
	return apiKey
}

func mintAPIKeyScope(t *testing.T, apiKey, scope string) *http.Response {
	t.Helper()
	return post(t, "/oauth2/token", map[string]any{
		"grant_type": "api_key",
		"api_key":    apiKey,
		"scope":      scope,
	}, nil)
}

// TestCIBAApproveScopeRequiresExplicitListing pins that ciba:approve is issued
// only to identities that list it explicitly: an empty scope ceiling never
// yields it, and MCP server identities never receive it.
func TestCIBAApproveScopeRequiresExplicitListing(t *testing.T) {
	t.Run("service identity without a listing is refused", func(t *testing.T) {
		apiKey := registerServiceIdentity(t, "service", "", nil, "")
		resp := mintAPIKeyScope(t, apiKey, "ciba:approve")
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		require.NotEmpty(t, decode(t, resp)["error"])
	})

	t.Run("mcp_server identity listing it is refused", func(t *testing.T) {
		apiKey := registerServiceIdentity(t, "mcp_server", "", []string{"ciba:approve"}, "")
		resp := mintAPIKeyScope(t, apiKey, "ciba:approve")
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		_ = resp.Body.Close()
	})

	t.Run("approval channel listing it on the identity is issued", func(t *testing.T) {
		apiKey := registerServiceIdentity(t, "service", "approval_channel", []string{"ciba:approve"}, "")
		resp := mintAPIKeyScope(t, apiKey, "ciba:approve")
		require.Equal(t, http.StatusOK, resp.StatusCode)
		tok, _ := decode(t, resp)["access_token"].(string)
		claims := decodeJWTPayload(t, tok)
		require.Equal(t, "approval_channel", claims["sub_type"])
		require.Equal(t, "service", claims["identity_type"])
	})

	t.Run("listing on the credential policy is honoured", func(t *testing.T) {
		pol := post(t, adminPath("/credential-policies"), map[string]any{
			"name":                uid("ciba-approve-policy"),
			"max_ttl_seconds":     3600,
			"allowed_grant_types": []string{"api_key"},
			"allowed_scopes":      []string{"ciba:approve"},
		}, channelWriteHeaders())
		require.Equal(t, http.StatusCreated, pol.StatusCode)
		policyID, _ := decode(t, pol)["id"].(string)
		require.NotEmpty(t, policyID)

		apiKey := registerServiceIdentity(t, "service", "approval_channel", nil, policyID)
		resp := mintAPIKeyScope(t, apiKey, "ciba:approve")
		require.Equal(t, http.StatusOK, resp.StatusCode)
		_ = resp.Body.Close()
	})

	t.Run("approval_channel is not a valid agent sub_type", func(t *testing.T) {
		externalID := uid("agent-channel")
		resp := post(t, adminPath("/agents/register"), map[string]any{
			"name": externalID, "external_id": externalID,
			"identity_type": "agent", "sub_type": "approval_channel", "created_by": "test-user",
		}, channelWriteHeaders())
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		_ = resp.Body.Close()
	})
}

// ── requesting chain ─────────────────────────────────────────────────────────

// externalPrincipalToken mints a token whose sub is userID via the trusted
// external-principal exchange.
func externalPrincipalToken(t *testing.T, accountID, projectID, userID string) string {
	t.Helper()
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": "external-principal-assertion",
		"account_id":    accountID,
		"project_id":    projectID,
		"user_id":       userID,
	}, map[string]string{testTrustedServiceHeader: "trusted-service"})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	tok, _ := decode(t, resp)["access_token"].(string)
	require.NotEmpty(t, tok)
	return tok
}

// cibaClient is a confidential OAuth client registered for the CIBA grant.
type cibaClient struct{ ID, Secret string }

func newConfidentialCIBAClient(t *testing.T) cibaClient {
	t.Helper()
	id := uid("ciba-conf")
	resp := post(t, adminPath("/oauth/clients"), map[string]any{
		"client_id": id, "name": id, "confidential": true,
		"grant_types": []string{zeroidGrantTypeCIBA},
	}, adminHeaders())
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	secret, _ := decode(t, resp)["client_secret"].(string)
	require.NotEmpty(t, secret)
	return cibaClient{ID: id, Secret: secret}
}

// bcAuthorizeAs posts bc-authorize for c in the test tenant.
func bcAuthorizeAs(t *testing.T, c cibaClient, body map[string]any) *http.Response {
	t.Helper()
	body["client_id"] = c.ID
	body["client_secret"] = c.Secret
	body["account_id"] = testAccountID
	body["project_id"] = testProjectID
	return post(t, "/oauth2/bc-authorize", body, nil)
}

// pollCIBARaw polls the token endpoint for authReqID. requestingToken, when
// given, is sent as the requesting_token parameter, which a request made with
// a requesting_token must present to be redeemed.
func pollCIBARaw(t *testing.T, c cibaClient, authReqID string, requestingToken ...string) (int, map[string]any) {
	t.Helper()
	return pollCIBAWithHeaders(t, c, authReqID, nil, requestingToken...)
}

func pollCIBAWithHeaders(t *testing.T, c cibaClient, authReqID string, headers map[string]string, requestingToken ...string) (int, map[string]any) {
	t.Helper()
	body := map[string]any{
		"grant_type":    zeroidGrantTypeCIBA,
		"auth_req_id":   authReqID,
		"client_id":     c.ID,
		"client_secret": c.Secret,
	}
	if len(requestingToken) > 0 {
		body["requesting_token"] = requestingToken[0]
	}
	resp := post(t, "/oauth2/token", body, headers)
	return resp.StatusCode, decode(t, resp)
}

func pollCIBA(t *testing.T, c cibaClient, authReqID string, requestingToken ...string) map[string]any {
	t.Helper()
	status, body := pollCIBARaw(t, c, authReqID, requestingToken...)
	require.Equal(t, http.StatusOK, status, "poll: %v", body)
	return body
}

func TestCIBARequestingToken(t *testing.T) {
	bcAuthorize := func(t *testing.T, body map[string]any) (*http.Response, cibaClient) {
		t.Helper()
		c := newConfidentialCIBAClient(t)
		return bcAuthorizeAs(t, c, body), c
	}

	t.Run("Invalid_400", func(t *testing.T) {
		resp, _ := bcAuthorize(t, map[string]any{"login_hint": "user-a", "requesting_token": "not-a-token"})
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		require.Equal(t, "invalid_request", decode(t, resp)["error"])
	})

	t.Run("OtherTenant_400", func(t *testing.T) {
		tok := externalPrincipalToken(t, "acct-other-chain", "proj-other-chain", "alice")
		resp, _ := bcAuthorize(t, map[string]any{"login_hint": "user-a", "requesting_token": tok})
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		require.Equal(t, "invalid_request", decode(t, resp)["error"])
	})

	t.Run("Revoked_400", func(t *testing.T) {
		tok := externalPrincipalToken(t, testAccountID, testProjectID, "alice")
		rv := post(t, "/oauth2/token/revoke", map[string]string{"token": tok}, nil)
		require.Equal(t, http.StatusOK, rv.StatusCode)
		_ = rv.Body.Close()
		resp, _ := bcAuthorize(t, map[string]any{"login_hint": "user-a", "requesting_token": tok})
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		require.Equal(t, "invalid_request", decode(t, resp)["error"])
	})

	t.Run("Valid_RequesterRecordedAndNotified", func(t *testing.T) {
		notifier := newRecordingNotifier()
		testZeroIDServer.SetBackchannelNotifier(notifier.notify)
		testZeroIDServer.SetBackchannelNotifyDispatchSync(true)
		t.Cleanup(func() {
			testZeroIDServer.SetBackchannelNotifyDispatchSync(false)
			testZeroIDServer.SetBackchannelNotifier(nil)
		})
		tok := externalPrincipalToken(t, testAccountID, testProjectID, "alice")
		resp, _ := bcAuthorize(t, map[string]any{"group_hint": "highflame:role:admin", "requesting_token": tok})
		require.Equal(t, http.StatusOK, resp.StatusCode)
		id, _ := decode(t, resp)["auth_req_id"].(string)

		row := loadBackchannelRow(t, postgres.NewBackchannelRequestRepository(testDB), id)
		require.Equal(t, "alice", row.RequesterSub)
		require.NotEmpty(t, row.RequesterActor)
		n := notifier.last()
		require.NotNil(t, n)
		require.Equal(t, "alice", n.RequesterSub)
		require.Equal(t, row.RequesterActor, n.RequesterActor)
	})

	t.Run("GroupHintOnlyRoot_RefusedWhenIdentityRequired", func(t *testing.T) {
		svc, _ := newApproverBackchannelSvc(t, approverSvcOpts{requireIdentity: true})
		clientID := uid("ciba-root-group")
		registerTestOAuthClient(clientID, []string{"client_credentials"})
		in := service.CreateAuthRequestInput{
			ClientID: clientID, AccountID: testAccountID, ProjectID: testProjectID,
			GroupHint: "highflame:role:admin",
		}
		_, err := svc.CreateAuthRequest(context.Background(), in)
		oe := requireOAuthStatus(t, err, oautherror.InvalidRequest, http.StatusBadRequest)
		require.Equal(t, "group_hint requires requesting_token", oe.Description)

		// login_hint alongside group_hint names the subject, so it is accepted.
		in.LoginHint = "user-a"
		_, err = svc.CreateAuthRequest(context.Background(), in)
		require.NoError(t, err)

		// Unchanged when the approver identity is not required.
		plain, _ := newApproverBackchannelSvc(t, approverSvcOpts{})
		in.LoginHint = ""
		_, err = plain.CreateAuthRequest(context.Background(), in)
		require.NoError(t, err)
	})
}

// TestCIBAApprovalKeepsRequestingSubject: a group_hint approval by an admin on
// a requesting token whose sub is alice mints a token with sub=alice; the
// admin appears only in the approval record. Each approved
// authorization_details entry carries approval_id and approver_auth.
func TestCIBAApprovalKeepsRequestingSubject(t *testing.T) {
	authz := &recordingAuthorizer{decision: zeroid.ApproverDecision{Allowed: true, SatisfiedHint: "group_hint"}}
	require.NoError(t, testZeroIDServer.SetBackchannelRequireApproverIdentity(true))
	require.NoError(t, testZeroIDServer.SetBackchannelEnforceHints("on"))
	testZeroIDServer.SetApproverAuthorizer(authz)
	t.Cleanup(func() {
		require.NoError(t, testZeroIDServer.SetBackchannelEnforceHints("off"))
		require.NoError(t, testZeroIDServer.SetBackchannelRequireApproverIdentity(false))
		testZeroIDServer.SetApproverAuthorizer(nil)
	})

	aliceToken := externalPrincipalToken(t, testAccountID, testProjectID, "alice")
	aliceClaims := decodeJWTPayload(t, aliceToken)

	client := newConfidentialCIBAClient(t)
	resp := bcAuthorizeAs(t, client, map[string]any{
		"group_hint":            "highflame:role:admin",
		"requesting_token":      aliceToken,
		"authorization_details": []map[string]any{{"type": "tool_call", "tool": "transfer_funds"}},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	id, _ := decode(t, resp)["auth_req_id"].(string)

	h := adminHeaders()
	h[testApproverSubHeader] = "admin"
	ap := post(t, adminPath("/oauth2/bc-authorize/"+id+"/approve"), map[string]any{}, h)
	require.Equal(t, http.StatusOK, ap.StatusCode)
	_ = ap.Body.Close()

	body := pollCIBA(t, client, id, aliceToken)
	claims := decodeJWTPayload(t, body["access_token"].(string))
	require.Equal(t, "alice", claims["sub"], "the approval must not change the chain's subject")
	for _, k := range []string{"user_email", "user_name", "name"} {
		v, _ := claims[k].(string)
		require.NotContains(t, v, "admin", "approver must not appear in claim %s", k)
	}
	for _, k := range []string{"identity_type", "external_id", "owner_user_id"} {
		require.Equal(t, aliceClaims[k], claims[k], "identity claim %s carried from the requesting token", k)
	}

	rar, ok := claims["authorization_details"].([]any)
	require.True(t, ok, "authorization_details claim: %v", claims["authorization_details"])
	require.Len(t, rar, 1)
	entry := rar[0].(map[string]any)
	require.Equal(t, "tool_call", entry["type"])
	require.Equal(t, "transfer_funds", entry["tool"])
	require.Equal(t, id, entry["approval_id"])
	require.Equal(t, "session", entry["approver_auth"])

	row := loadBackchannelRow(t, postgres.NewBackchannelRequestRepository(testDB), id)
	require.Equal(t, "admin", row.ApprovedSubjectID)
	require.Equal(t, "alice", row.RequesterSub)
	require.Equal(t, "group_hint", row.HintSatisfied)
}

// TestCIBAApprovalKeepsAgentChainClaims: with an agent's token as the
// requesting token, the minted token keeps the agent's subject and identity
// claims.
func TestCIBAApprovalKeepsAgentChainClaims(t *testing.T) {
	externalID := uid("ciba-chain-agent")
	reg := post(t, adminPath("/agents/register"), map[string]any{
		"name": externalID, "external_id": externalID, "sub_type": "tool_agent",
		"trust_level": "first_party", "created_by": "user-owner-1",
	}, adminHeaders())
	require.Equal(t, http.StatusCreated, reg.StatusCode)
	apiKey, _ := decode(t, reg)["api_key"].(string)
	tr := post(t, "/oauth2/token", map[string]any{"grant_type": "api_key", "api_key": apiKey}, nil)
	require.Equal(t, http.StatusOK, tr.StatusCode)
	agentToken, _ := decode(t, tr)["access_token"].(string)
	agentClaims := decodeJWTPayload(t, agentToken)

	client := newConfidentialCIBAClient(t)
	resp := bcAuthorizeAs(t, client, map[string]any{
		"login_hint": "user-a", "requesting_token": agentToken,
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	id, _ := decode(t, resp)["auth_req_id"].(string)

	ap := post(t, adminPath("/oauth2/bc-authorize/"+id+"/approve"), map[string]any{"subject_id": "user-a"}, adminHeaders())
	require.Equal(t, http.StatusOK, ap.StatusCode)
	_ = ap.Body.Close()

	claims := decodeJWTPayload(t, pollCIBA(t, client, id, agentToken)["access_token"].(string))
	require.Equal(t, agentClaims["sub"], claims["sub"])
	for _, k := range []string{"identity_type", "external_id", "owner_user_id", "agent_id"} {
		require.Equal(t, agentClaims[k], claims[k], "claim %s", k)
	}
	require.Nil(t, claims["user_email"])

	row := loadBackchannelRow(t, postgres.NewBackchannelRequestRepository(testDB), id)
	require.Equal(t, agentClaims["sub"], row.RequesterSub)
	require.Equal(t, "user-a", row.ApprovedSubjectID)
}

// TestCIBARequestingTokenClientAuth: requesting_token is considered only for
// an authenticated confidential client, and only after client authentication.
func TestCIBARequestingTokenClientAuth(t *testing.T) {
	valid := externalPrincipalToken(t, testAccountID, testProjectID, "alice")

	t.Run("PublicClient_400", func(t *testing.T) {
		clientID := uid("ciba-public-chain")
		registerTestOAuthClient(clientID, []string{"client_credentials"})
		resp := post(t, "/oauth2/bc-authorize", map[string]any{
			"client_id": clientID, "account_id": testAccountID, "project_id": testProjectID,
			"login_hint": "user-a", "requesting_token": valid,
		}, nil)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		body := decode(t, resp)
		require.Equal(t, "invalid_request", body["error"])
		require.Equal(t, "requesting_token requires an authenticated client", body["error_description"])
	})

	t.Run("FailedClientAuth_SameErrorForValidAndInvalidToken", func(t *testing.T) {
		c := newConfidentialCIBAClient(t)
		attempt := func(tok, account, project string) (int, map[string]any) {
			resp := post(t, "/oauth2/bc-authorize", map[string]any{
				"client_id": c.ID, "client_secret": "wrong-secret",
				"account_id": account, "project_id": project,
				"login_hint": "user-a", "requesting_token": tok,
			}, nil)
			return resp.StatusCode, decode(t, resp)
		}
		validStatus, validBody := attempt(valid, testAccountID, testProjectID)
		invalidStatus, invalidBody := attempt("not-a-token", testAccountID, testProjectID)
		otherStatus, otherBody := attempt(valid, "acct-elsewhere", "proj-elsewhere")
		require.Equal(t, invalidStatus, validStatus)
		require.Equal(t, invalidBody, validBody)
		require.Equal(t, invalidStatus, otherStatus)
		require.Equal(t, invalidBody, otherBody)
		require.Equal(t, "invalid_client", validBody["error"])
	})
}

func approveAs(t *testing.T, authReqID, sub string) {
	t.Helper()
	ap := post(t, adminPath("/oauth2/bc-authorize/"+authReqID+"/approve"), map[string]any{"subject_id": sub}, adminHeaders())
	require.Equal(t, http.StatusOK, ap.StatusCode)
	_ = ap.Body.Close()
}

func numClaim(t *testing.T, claims map[string]any, k string) int64 {
	t.Helper()
	v, ok := claims[k].(float64)
	require.True(t, ok, "claim %s: %v", k, claims[k])
	return int64(v)
}

// TestCIBARequestingIdentityPolicy: the requesting identity's credential
// policy bounds the approved token's scopes, and a refusal does not consume
// the approval.
func TestCIBARequestingIdentityPolicy(t *testing.T) {
	policyID := createRichCredentialPolicy(t, map[string]any{
		"name":                 uid("ciba-chain-policy"),
		"allowed_grant_types":  []string{"client_credentials", "token_exchange"},
		"allowed_scopes":       []string{"tools:read", "tools:write"},
		"max_delegation_depth": 5,
		"max_ttl_seconds":      3600,
	}, adminHeaders())
	// The identity's own allowed_scopes include tools:admin; its credential
	// policy does not, so the policy is what refuses it.
	extID := uid("ciba-chain-root")
	registerIdentityWithPolicy(t, extID, policyID, "", []string{"tools:read", "tools:write", "tools:admin"}, adminHeaders())
	rootClient := registerOAuthClient(t, extID, []string{"tools:read"})
	rr := post(t, "/oauth2/token", map[string]any{
		"grant_type": "client_credentials", "account_id": testAccountID, "project_id": testProjectID,
		"client_id": rootClient.ClientID, "client_secret": rootClient.ClientSecret, "scope": "tools:read",
	}, nil)
	require.Equal(t, http.StatusOK, rr.StatusCode)
	rootToken, _ := decode(t, rr)["access_token"].(string)
	rootClaims := decodeJWTPayload(t, rootToken)

	t.Run("ScopeOutsidePolicy_RefusedWithoutConsumingApproval", func(t *testing.T) {
		c := newConfidentialCIBAClient(t)
		resp := bcAuthorizeAs(t, c, map[string]any{
			"login_hint": "user-a", "requesting_token": rootToken, "scope": "tools:admin",
		})
		require.Equal(t, http.StatusOK, resp.StatusCode)
		id, _ := decode(t, resp)["auth_req_id"].(string)
		approveAs(t, id, "user-a")

		status, body := pollCIBARaw(t, c, id, rootToken)
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "invalid_scope", body["error"])
		row := loadBackchannelRow(t, postgres.NewBackchannelRequestRepository(testDB), id)
		require.Equal(t, domain.BackchannelStatusApproved, row.Status, "a refusal must not consume the approval")
	})

	t.Run("ScopeWithinPolicy_Minted", func(t *testing.T) {
		c := newConfidentialCIBAClient(t)
		resp := bcAuthorizeAs(t, c, map[string]any{
			"login_hint": "user-a", "requesting_token": rootToken, "scope": "tools:write",
		})
		require.Equal(t, http.StatusOK, resp.StatusCode)
		id, _ := decode(t, resp)["auth_req_id"].(string)
		approveAs(t, id, "user-a")

		claims := decodeJWTPayload(t, pollCIBA(t, c, id, rootToken)["access_token"].(string))
		require.Equal(t, rootClaims["sub"], claims["sub"])
		require.LessOrEqual(t, numClaim(t, claims, "exp"), numClaim(t, rootClaims, "exp"),
			"the approved token must not outlive the requesting token")
	})
}

// TestCIBAApprovedTokenExpiryBoundedByChain: a requesting token with a short
// remaining life bounds the approved token's exp.
func TestCIBAApprovedTokenExpiryBoundedByChain(t *testing.T) {
	tok := externalPrincipalToken(t, testAccountID, testProjectID, "alice")
	reqClaims := decodeJWTPayload(t, tok)

	short := time.Now().Add(60 * time.Second)
	_, err := testDB.NewUpdate().Model((*domain.IssuedCredential)(nil)).
		Set("expires_at = ?", short).Where("jti = ?", reqClaims["jti"]).Exec(context.Background())
	require.NoError(t, err)

	c := newConfidentialCIBAClient(t)
	resp := bcAuthorizeAs(t, c, map[string]any{"login_hint": "user-a", "requesting_token": tok})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	id, _ := decode(t, resp)["auth_req_id"].(string)
	approveAs(t, id, "user-a")

	claims := decodeJWTPayload(t, pollCIBA(t, c, id, tok)["access_token"].(string))
	require.LessOrEqual(t, numClaim(t, claims, "exp"), short.Unix()+1)
}

// TestCIBAApprovedTokenKeepsActClaim: the requesting token's act claim is
// carried over exactly as issued.
func TestCIBAApprovedTokenKeepsActClaim(t *testing.T) {
	policyID := delegationPolicy(t, uid("ciba-act-policy"), []string{"tools:read"})
	_, _, rootToken := issueRootCredential(t, policyID, "ciba-act-root", []string{"tools:read"})
	_, _, childToken := exchangeToken(t, policyID, "ciba-act-child", []string{"tools:read"}, []string{"tools:read"}, rootToken)
	childClaims := decodeJWTPayload(t, childToken)
	require.NotNil(t, childClaims["act"], "a delegated token carries act")

	t.Run("Delegated", func(t *testing.T) {
		c := newConfidentialCIBAClient(t)
		resp := bcAuthorizeAs(t, c, map[string]any{"login_hint": "user-a", "requesting_token": childToken, "scope": "tools:read"})
		require.Equal(t, http.StatusOK, resp.StatusCode)
		id, _ := decode(t, resp)["auth_req_id"].(string)
		approveAs(t, id, "user-a")

		claims := decodeJWTPayload(t, pollCIBA(t, c, id, childToken)["access_token"].(string))
		require.Equal(t, childClaims["sub"], claims["sub"])
		require.Equal(t, childClaims["act"], claims["act"])
	})

	t.Run("NestedActors", func(t *testing.T) {
		c := newConfidentialCIBAClient(t)
		resp := bcAuthorizeAs(t, c, map[string]any{"login_hint": "user-a", "requesting_token": childToken, "scope": "tools:read"})
		require.Equal(t, http.StatusOK, resp.StatusCode)
		id, _ := decode(t, resp)["auth_req_id"].(string)

		// A chain recorded with nested actors (act.act) is reproduced as is.
		nested := map[string]any{
			"sub": childClaims["act"].(map[string]any)["sub"],
			"act": map[string]any{"sub": "spiffe://upstream.example.test/orchestrator", "act": map[string]any{"sub": "user-origin"}},
		}
		raw, err := json.Marshal(nested)
		require.NoError(t, err)
		_, err = testDB.NewUpdate().Model((*domain.BackchannelAuthRequest)(nil)).
			Set("requesting_act = ?", string(raw)).Where("auth_req_id = ?", id).Exec(context.Background())
		require.NoError(t, err)
		approveAs(t, id, "user-a")

		claims := decodeJWTPayload(t, pollCIBA(t, c, id, childToken)["access_token"].(string))
		require.Equal(t, nested, claims["act"])
	})
}

// TestCIBADeniedAtExposed: a denied request records and exposes when it was
// denied.
func TestCIBADeniedAtExposed(t *testing.T) {
	clientID := uid("ciba-denied-at")
	registerTestOAuthClient(clientID, []string{"client_credentials"})
	resp := post(t, "/oauth2/bc-authorize", map[string]any{
		"client_id": clientID, "account_id": testAccountID, "project_id": testProjectID, "login_hint": "user-a",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	id, _ := decode(t, resp)["auth_req_id"].(string)

	before := time.Now().Add(-time.Second)
	dr := post(t, adminPath("/oauth2/bc-authorize/"+id+"/deny"), nil, adminHeaders())
	require.Equal(t, http.StatusOK, dr.StatusCode)
	_ = dr.Body.Close()

	row := loadBackchannelRow(t, postgres.NewBackchannelRequestRepository(testDB), id)
	require.NotNil(t, row.DeniedAt)
	require.True(t, row.DeniedAt.After(before))
	raw, err := json.Marshal(row)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	require.NotEmpty(t, m["denied_at"], "denied_at is part of the row's JSON read model")
}

// TestCIBARequestingTokenTrustedService: a caller accepted by the deployer's
// TrustedServiceValidator may send requesting_token through a public client.
func TestCIBARequestingTokenTrustedService(t *testing.T) {
	tok := externalPrincipalToken(t, testAccountID, testProjectID, "alice")
	clientID := uid("ciba-trusted-public")
	registerTestOAuthClient(clientID, []string{"client_credentials"})
	body := func() map[string]any {
		return map[string]any{
			"client_id": clientID, "account_id": testAccountID, "project_id": testProjectID,
			"login_hint": "user-a", "requesting_token": tok,
		}
	}

	resp := post(t, "/oauth2/bc-authorize", body(), map[string]string{testTrustedServiceHeader: "step-up-service"})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	id, _ := decode(t, resp)["auth_req_id"].(string)
	require.Equal(t, "alice", loadBackchannelRow(t, postgres.NewBackchannelRequestRepository(testDB), id).RequesterSub)

	resp = post(t, "/oauth2/bc-authorize", body(), nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Equal(t, "invalid_request", decode(t, resp)["error"])
}

// TestCIBAResolvedRetention pins the reaping rules: unresolved rows go at
// expiry, resolved rows stay for the retention window, and a retained row is
// never redeemable again.
func TestCIBAResolvedRetention(t *testing.T) {
	ctx := context.Background()
	repo := postgres.NewBackchannelRequestRepository(testDB)
	repo.SetResolvedRetention(time.Hour)
	svc := service.NewBackchannelService(repo, service.NewOAuthClientService(postgres.NewOAuthClientRepository(testDB)), nil, nil, service.DefaultBackchannelConfig())

	clientID := uid("ciba-retention")
	registerTestOAuthClient(clientID, []string{"client_credentials"})
	now := time.Now()
	ago := func(d time.Duration) *time.Time { t := now.Add(-d); return &t }

	type fixture struct {
		name       string
		status     domain.BackchannelStatus
		expiresAt  time.Time
		approvedAt *time.Time
		deniedAt   *time.Time
		kept       bool
	}
	fixtures := []fixture{
		{name: "pending-expired", status: domain.BackchannelStatusPending, expiresAt: now.Add(-time.Minute), kept: false},
		{name: "pending-live", status: domain.BackchannelStatusPending, expiresAt: now.Add(time.Minute), kept: true},
		{name: "expired", status: domain.BackchannelStatusExpired, expiresAt: now.Add(-time.Minute), kept: false},
		{name: "denied-recent", status: domain.BackchannelStatusDenied, expiresAt: now.Add(-time.Minute), deniedAt: ago(5 * time.Minute), kept: true},
		{name: "denied-old", status: domain.BackchannelStatusDenied, expiresAt: now.Add(-time.Minute), deniedAt: ago(2 * time.Hour), kept: false},
		{name: "denied-legacy", status: domain.BackchannelStatusDenied, expiresAt: now.Add(-2 * time.Hour), kept: false},
		{name: "approved-recent", status: domain.BackchannelStatusApproved, expiresAt: now.Add(-30 * time.Minute), approvedAt: ago(30 * time.Minute), kept: true},
		{name: "approved-old", status: domain.BackchannelStatusApproved, expiresAt: now.Add(-2 * time.Hour), approvedAt: ago(2 * time.Hour), kept: false},
		{name: "issued-recent", status: domain.BackchannelStatusIssued, expiresAt: now.Add(-30 * time.Minute), approvedAt: ago(30 * time.Minute), kept: true},
		{name: "issued-old", status: domain.BackchannelStatusIssued, expiresAt: now.Add(-2 * time.Hour), approvedAt: ago(2 * time.Hour), kept: false},
	}
	ids := map[string]string{}
	for _, f := range fixtures {
		id := uid("ret-" + f.name)
		ids[f.name] = id
		require.NoError(t, repo.Create(ctx, &domain.BackchannelAuthRequest{
			AuthReqID: id, AccountID: testAccountID, ProjectID: testProjectID, ClientID: clientID,
			LoginHint: "user-a", AuthorizationDetailsRaw: json.RawMessage("[]"),
			NotificationMode: domain.BackchannelNotificationPoll, Status: f.status, IntervalSeconds: 5,
			ExpiresAt: f.expiresAt, CreatedAt: now.Add(-3 * time.Hour), ApprovedAt: f.approvedAt, DeniedAt: f.deniedAt,
		}))
	}

	_, err := svc.DeleteExpired(ctx, now)
	require.NoError(t, err)
	for _, f := range fixtures {
		_, gerr := repo.GetByAuthReqID(ctx, ids[f.name])
		if f.kept {
			require.NoError(t, gerr, "%s must be kept", f.name)
		} else {
			require.ErrorIs(t, gerr, postgres.ErrBackchannelRequestNotFound, "%s must be reaped", f.name)
		}
	}

	// Retained resolved rows cannot be redeemed.
	_, rerr := svc.Redeem(ctx, service.RedeemInput{AuthReqID: ids["issued-recent"], ClientID: clientID})
	requireOAuthError(t, rerr, oautherror.AccessDenied)
	_, rerr = svc.Redeem(ctx, service.RedeemInput{AuthReqID: ids["approved-recent"], ClientID: clientID})
	requireOAuthError(t, rerr, oautherror.ExpiredToken)
	_, rerr = svc.Redeem(ctx, service.RedeemInput{AuthReqID: ids["denied-recent"], ClientID: clientID})
	requireOAuthError(t, rerr, oautherror.AccessDenied)
	affected, merr := repo.MarkIssued(ctx, ids["approved-recent"], now)
	require.NoError(t, merr)
	require.Zero(t, affected, "a retained approval past its redemption window is not issuable")
}

// TestCIBARequesterOwnerFromRequestingToken pins that when bc-authorize
// carries a requesting_token for a registered identity, requester_owner is
// that identity's owner_user_id: a differing request parameter is ignored,
// and four_eyes needs no explicit requester_owner.
func TestCIBARequesterOwnerFromRequestingToken(t *testing.T) {
	const owner = "user-owner-l1"
	externalID := uid("ciba-owner-agent")
	reg := post(t, adminPath("/agents/register"), map[string]any{
		"name": externalID, "external_id": externalID, "sub_type": "tool_agent",
		"trust_level": "first_party", "created_by": owner,
	}, adminHeaders())
	require.Equal(t, http.StatusCreated, reg.StatusCode)
	apiKey, _ := decode(t, reg)["api_key"].(string)
	tr := post(t, "/oauth2/token", map[string]any{"grant_type": "api_key", "api_key": apiKey}, nil)
	require.Equal(t, http.StatusOK, tr.StatusCode)
	agentToken, _ := decode(t, tr)["access_token"].(string)
	repo := postgres.NewBackchannelRequestRepository(testDB)

	t.Run("MismatchingParameterIgnored", func(t *testing.T) {
		c := newConfidentialCIBAClient(t)
		resp := bcAuthorizeAs(t, c, map[string]any{
			"login_hint": owner, "requesting_token": agentToken,
			"four_eyes": "true", "requester_owner": "someone-else",
		})
		require.Equal(t, http.StatusOK, resp.StatusCode)
		id, _ := decode(t, resp)["auth_req_id"].(string)
		row := loadBackchannelRow(t, repo, id)
		require.Equal(t, owner, row.RequesterOwner)
		require.True(t, row.FourEyes)

		require.NoError(t, testZeroIDServer.SetBackchannelRequireApproverIdentity(true))
		require.NoError(t, testZeroIDServer.SetBackchannelEnforceHints("on"))
		t.Cleanup(func() {
			require.NoError(t, testZeroIDServer.SetBackchannelEnforceHints("off"))
			require.NoError(t, testZeroIDServer.SetBackchannelRequireApproverIdentity(false))
		})
		h := adminHeaders()
		h[testApproverSubHeader] = owner
		ap := post(t, adminPath("/oauth2/bc-authorize/"+id+"/approve"), map[string]any{}, h)
		require.Equal(t, http.StatusForbidden, ap.StatusCode, "%v", decode(t, ap))
	})

	t.Run("OmittedParameterDerived", func(t *testing.T) {
		c := newConfidentialCIBAClient(t)
		resp := bcAuthorizeAs(t, c, map[string]any{
			"login_hint": "user-a", "requesting_token": agentToken, "four_eyes": "true",
		})
		require.Equal(t, http.StatusOK, resp.StatusCode)
		id, _ := decode(t, resp)["auth_req_id"].(string)
		require.Equal(t, owner, loadBackchannelRow(t, repo, id).RequesterOwner)
	})
}
