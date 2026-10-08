package integration_test

import (
	"context"
	"database/sql"
	"errors"
	"io/fs"
	"net/http"
	"sync"
	"testing"

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
		testZeroIDServer.SetBackchannelRequireApproverIdentity(false)
		require.NoError(t, testZeroIDServer.SetBackchannelEnforceHints("off"))
	})
	testZeroIDServer.SetBackchannelRequireApproverIdentity(true)
	require.NoError(t, testZeroIDServer.SetBackchannelEnforceHints("on"))
	require.Error(t, testZeroIDServer.SetBackchannelEnforceHints("strict"), "unknown modes are rejected")

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
	const name = "048_ciba_approver_binding"
	up, err := fs.ReadFile(zeroid.MigrationFiles(), name+".up.sql")
	require.NoError(t, err)
	down, err := fs.ReadFile(zeroid.MigrationFiles(), name+".down.sql")
	require.NoError(t, err)

	columns := []string{
		"four_eyes", "requester_owner", "requester_sub", "requester_actor",
		"requesting_jti", "requester_act_sub", "approver_iss", "approver_auth",
		"channel_client_id", "hint_satisfied", "shadow_would_deny", "shadow_reason",
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
	}, adminHeaders())
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

func pollCIBA(t *testing.T, clientID, authReqID string) map[string]any {
	t.Helper()
	resp := post(t, "/oauth2/token", map[string]any{
		"grant_type":  zeroidGrantTypeCIBA,
		"auth_req_id": authReqID,
		"client_id":   clientID,
	}, nil)
	body := decode(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode, "poll: %v", body)
	return body
}

func TestCIBARequestingToken(t *testing.T) {
	bcAuthorize := func(t *testing.T, body map[string]any) (*http.Response, string) {
		t.Helper()
		clientID := uid("ciba-chain")
		registerTestOAuthClient(clientID, []string{"client_credentials"})
		body["client_id"] = clientID
		body["account_id"] = testAccountID
		body["project_id"] = testProjectID
		return post(t, "/oauth2/bc-authorize", body, nil), clientID
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
	testZeroIDServer.SetBackchannelRequireApproverIdentity(true)
	require.NoError(t, testZeroIDServer.SetBackchannelEnforceHints("on"))
	testZeroIDServer.SetApproverAuthorizer(authz)
	t.Cleanup(func() {
		testZeroIDServer.SetBackchannelRequireApproverIdentity(false)
		require.NoError(t, testZeroIDServer.SetBackchannelEnforceHints("off"))
		testZeroIDServer.SetApproverAuthorizer(nil)
	})

	aliceToken := externalPrincipalToken(t, testAccountID, testProjectID, "alice")
	aliceClaims := decodeJWTPayload(t, aliceToken)

	clientID := uid("ciba-keep-sub")
	registerTestOAuthClient(clientID, []string{"client_credentials"})
	resp := post(t, "/oauth2/bc-authorize", map[string]any{
		"client_id": clientID, "account_id": testAccountID, "project_id": testProjectID,
		"group_hint":            "highflame:role:admin",
		"requesting_token":      aliceToken,
		"authorization_details": []map[string]any{{"type": "tool_call", "tool": "transfer_funds"}},
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	id, _ := decode(t, resp)["auth_req_id"].(string)

	h := adminHeaders()
	h[testApproverSubHeader] = "admin"
	ap := post(t, adminPath("/oauth2/bc-authorize/"+id+"/approve"), map[string]any{}, h)
	require.Equal(t, http.StatusOK, ap.StatusCode)
	_ = ap.Body.Close()

	body := pollCIBA(t, clientID, id)
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

	clientID := uid("ciba-chain-agent-client")
	registerTestOAuthClient(clientID, []string{"client_credentials"})
	resp := post(t, "/oauth2/bc-authorize", map[string]any{
		"client_id": clientID, "account_id": testAccountID, "project_id": testProjectID,
		"login_hint": "user-a", "requesting_token": agentToken,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	id, _ := decode(t, resp)["auth_req_id"].(string)

	ap := post(t, adminPath("/oauth2/bc-authorize/"+id+"/approve"), map[string]any{"subject_id": "user-a"}, adminHeaders())
	require.Equal(t, http.StatusOK, ap.StatusCode)
	_ = ap.Body.Close()

	claims := decodeJWTPayload(t, pollCIBA(t, clientID, id)["access_token"].(string))
	require.Equal(t, agentClaims["sub"], claims["sub"])
	for _, k := range []string{"identity_type", "external_id", "owner_user_id", "agent_id"} {
		require.Equal(t, agentClaims[k], claims[k], "claim %s", k)
	}
	require.Nil(t, claims["user_email"])

	row := loadBackchannelRow(t, postgres.NewBackchannelRequestRepository(testDB), id)
	require.Equal(t, agentClaims["sub"], row.RequesterSub)
	require.Equal(t, "user-a", row.ApprovedSubjectID)
}
