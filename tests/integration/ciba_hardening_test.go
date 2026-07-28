package integration_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/oautherror"
	"github.com/highflame-ai/zeroid/internal/service"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// TestCIBAHardening pins the security fixes in the CIBA flow. Each subtest is
// written so it FAILS if its fix is reverted (the assertion comments call out
// the pre-fix behaviour).
//
// The subtests drive the service layer directly (constructed over the shared
// testDB) rather than through HTTP: the expiry subtests need to backdate
// expires_at / approved_at, which HTTP cannot do. (The bc-authorize handler
// does forward client_secret — BcAuthorizeInput in internal/handler/oauth.go —
// so the confidential path is also reachable over HTTP; these tests predate
// that wiring and exercising the fix where it lives is still the tighter
// loop.)
//
// The fixes live in internal/service/backchannel.go and
// internal/store/postgres/backchannel_request.go.
func TestCIBAHardening(t *testing.T) {
	ctx := context.Background()

	// Build the backchannel service over the same Postgres the rest of the
	// suite uses. credentialSvc is nil: none of the paths these subtests
	// exercise reach token issuance (Redeem returns its error before
	// issueTokenForApprovedRow, and CreateAuthRequest never touches the
	// credential service).
	bcRepo := postgres.NewBackchannelRequestRepository(testDB)
	oauthClientRepo := postgres.NewOAuthClientRepository(testDB)
	oauthClientSvc := service.NewOAuthClientService(oauthClientRepo)
	bcSvc := service.NewBackchannelService(bcRepo, oauthClientSvc, nil, service.DefaultBackchannelConfig())

	t.Run("Redeem_OmittedClientID_Refused", func(t *testing.T) {
		// FIX #1: Redeem must require a non-empty client_id and always compare
		// it to the row. Pre-fix, the ownership comparison was skipped when
		// client_id was empty, so a polling caller could redeem ANY approved
		// auth_req_id by simply omitting client_id.
		clientID := uid("ciba-hard-omit")
		registerTestOAuthClient(clientID, []string{"client_credentials"})

		out, err := bcSvc.CreateAuthRequest(ctx, service.CreateAuthRequestInput{
			ClientID:  clientID,
			AccountID: testAccountID,
			ProjectID: testProjectID,
			LoginHint: "alice@example.com",
			Scope:     "openid",
		})
		require.NoError(t, err)
		require.NotEmpty(t, out.AuthReqID)

		// Approve it so the row is in a redeemable state — proving the refusal
		// is the missing-client_id guard, not just "not yet approved".
		require.NoError(t, bcSvc.Approve(ctx, service.ApproveInput{
			AuthReqID: out.AuthReqID,
			AccountID: testAccountID,
			ProjectID: testProjectID,
			SubjectID: "user-omit-001",
		}))

		// Redeem with an EMPTY client_id → must be refused. Pre-fix this would
		// have skipped the ownership check and minted a token.
		_, rerr := bcSvc.Redeem(ctx, service.RedeemInput{
			AuthReqID: out.AuthReqID,
			ClientID:  "", // omitted
		})
		requireOAuthError(t, rerr, oautherror.InvalidGrant)

		// Sanity: a DIFFERENT (non-empty) client_id is also refused.
		_, rerr2 := bcSvc.Redeem(ctx, service.RedeemInput{
			AuthReqID: out.AuthReqID,
			ClientID:  "some-other-client",
		})
		requireOAuthError(t, rerr2, oautherror.InvalidGrant)
		// (The legitimate owner passing the ownership gate is covered by the
		// end-to-end TestCIBA_PollingLifecycle, which redeems with the matching
		// client_id and gets a token. Here credentialSvc is nil, so we stop at
		// the ownership refusal and don't exercise issuance.)
	})

	t.Run("Redeem_ApprovedPastExpiryAndGrace_NotRedeemable", func(t *testing.T) {
		// FIX #2: an APPROVED row that has outlived both expires_at and the
		// post-approval grace window must surface expired_token, not mint a
		// token. Pre-fix, the expiry guard only applied to PENDING rows, so an
		// approved-but-unredeemed (leaked) auth_req_id was redeemable forever.
		clientID := uid("ciba-hard-exp")
		registerTestOAuthClient(clientID, []string{"client_credentials"})

		out, err := bcSvc.CreateAuthRequest(ctx, service.CreateAuthRequestInput{
			ClientID:  clientID,
			AccountID: testAccountID,
			ProjectID: testProjectID,
			LoginHint: "bob@example.com",
			Scope:     "openid",
		})
		require.NoError(t, err)

		require.NoError(t, bcSvc.Approve(ctx, service.ApproveInput{
			AuthReqID: out.AuthReqID,
			AccountID: testAccountID,
			ProjectID: testProjectID,
			SubjectID: "user-exp-001",
		}))

		// Backdate the row well past expires_at AND past approved_at + grace so
		// neither the expires_at branch nor the grace branch keeps it alive.
		stale := time.Now().Add(-2 * postgres.ApprovedRedemptionGrace)
		_, uerr := testDB.NewUpdate().
			Model((*domain.BackchannelAuthRequest)(nil)).
			Set("expires_at = ?", stale).
			Set("approved_at = ?", stale).
			Where("auth_req_id = ?", out.AuthReqID).
			Exec(ctx)
		require.NoError(t, uerr)

		// Redeem by the legitimate owner → expired_token. Pre-fix this approved
		// row would have minted a token regardless of how old it was.
		_, rerr := bcSvc.Redeem(ctx, service.RedeemInput{
			AuthReqID: out.AuthReqID,
			ClientID:  clientID,
		})
		requireOAuthError(t, rerr, oautherror.ExpiredToken)

		// The cleanup sweep must now reap this approved-but-dead row. Pre-fix
		// DeleteExpired excluded approved rows entirely, so it lived forever.
		_, derr := bcSvc.DeleteExpired(ctx, time.Now())
		require.NoError(t, derr)
		_, gerr := bcRepo.GetByAuthReqID(ctx, out.AuthReqID)
		require.ErrorIs(t, gerr, postgres.ErrBackchannelRequestNotFound,
			"approved-but-dead row must be reaped by DeleteExpired")
	})

	t.Run("Redeem_ApprovedWithinGrace_StillRedeemable", func(t *testing.T) {
		// Guardrail for FIX #2: an honest slow poll whose approval landed just
		// before expiry must STILL be redeemable inside the grace window — the
		// bound must not make approvals instantly un-redeemable. We assert the
		// row is NOT reaped by DeleteExpired and that MarkIssued (the DB-layer
		// redeemability guard Redeem relies on) admits it. Redeem itself isn't
		// called here: past this guard it proceeds to token issuance, which
		// needs a credential service this harness deliberately leaves nil.
		clientID := uid("ciba-hard-grace")
		registerTestOAuthClient(clientID, []string{"client_credentials"})

		out, err := bcSvc.CreateAuthRequest(ctx, service.CreateAuthRequestInput{
			ClientID:  clientID,
			AccountID: testAccountID,
			ProjectID: testProjectID,
			LoginHint: "carol@example.com",
			Scope:     "openid",
		})
		require.NoError(t, err)
		require.NoError(t, bcSvc.Approve(ctx, service.ApproveInput{
			AuthReqID: out.AuthReqID,
			AccountID: testAccountID,
			ProjectID: testProjectID,
			SubjectID: "user-grace-001",
		}))

		// Past expires_at, but approved_at is recent → inside the grace window.
		_, uerr := testDB.NewUpdate().
			Model((*domain.BackchannelAuthRequest)(nil)).
			Set("expires_at = ?", time.Now().Add(-1*time.Minute)).
			Set("approved_at = ?", time.Now()).
			Where("auth_req_id = ?", out.AuthReqID).
			Exec(ctx)
		require.NoError(t, uerr)

		// DeleteExpired must NOT reap it (still inside grace).
		_, derr := bcSvc.DeleteExpired(ctx, time.Now())
		require.NoError(t, derr)
		_, gerr := bcRepo.GetByAuthReqID(ctx, out.AuthReqID)
		require.NoError(t, gerr, "row inside grace window must survive the sweep")

		// MarkIssued must admit it (the DB-layer guard sees it as redeemable).
		affected, mierr := bcRepo.MarkIssued(ctx, out.AuthReqID, time.Now())
		require.NoError(t, mierr)
		require.EqualValues(t, 1, affected,
			"approved row inside grace window must be issuable")
	})

	t.Run("BcAuthorize_ConfidentialClientAuth", func(t *testing.T) {
		// FIX #3: bc-authorize must authenticate confidential clients. Pre-fix
		// it only checked the client existed and trusted the body — letting an
		// unauthenticated party fire the deployer's notifier at arbitrary users.
		confClient := registerOAuthClient(t, uid("ciba-hard-conf"), []string{"openid"})

		base := service.CreateAuthRequestInput{
			ClientID:  confClient.ClientID,
			AccountID: testAccountID,
			ProjectID: testProjectID,
			LoginHint: "dave@example.com",
			Scope:     "openid",
		}

		// Missing secret → rejected (invalid_client). Pre-fix: accepted.
		noSecret := base
		_, e1 := bcSvc.CreateAuthRequest(ctx, noSecret)
		requireOAuthError(t, e1, oautherror.InvalidClient)

		// Wrong secret → rejected (invalid_client).
		wrongSecret := base
		wrongSecret.ClientSecret = "definitely-not-the-secret"
		_, e2 := bcSvc.CreateAuthRequest(ctx, wrongSecret)
		requireOAuthError(t, e2, oautherror.InvalidClient)

		// Correct secret → accepted.
		good := base
		good.ClientSecret = confClient.ClientSecret
		out, e3 := bcSvc.CreateAuthRequest(ctx, good)
		require.NoError(t, e3, "confidential client with correct secret must be accepted")
		require.NotEmpty(t, out.AuthReqID)

		// Public clients per CIBA may remain unauthenticated — confirm the
		// enforcement is scoped to confidential clients only.
		pubClientID := uid("ciba-hard-pub")
		registerTestOAuthClient(pubClientID, []string{"client_credentials"})
		pubOut, e4 := bcSvc.CreateAuthRequest(ctx, service.CreateAuthRequestInput{
			ClientID:  pubClientID,
			AccountID: testAccountID,
			ProjectID: testProjectID,
			LoginHint: "erin@example.com",
			Scope:     "openid",
			// no client_secret
		})
		require.NoError(t, e4, "public client must remain unauthenticated at bc-authorize")
		require.NotEmpty(t, pubOut.AuthReqID)
	})

	t.Run("Redeem_ConfidentialClientAuth", func(t *testing.T) {
		// FIX #4: token-endpoint redemption must authenticate confidential
		// clients (CIBA Core §10.2), symmetric with the bc-authorize check —
		// otherwise a leaked auth_req_id alone mints the token for a
		// confidential client. Pre-fix, Redeem checked only client_id
		// ownership; the no-secret call below would have returned
		// authorization_pending instead of invalid_client.
		confClient := registerOAuthClient(t, uid("ciba-hard-redeem"), []string{"openid"})

		out, err := bcSvc.CreateAuthRequest(ctx, service.CreateAuthRequestInput{
			ClientID:     confClient.ClientID,
			ClientSecret: confClient.ClientSecret,
			AccountID:    testAccountID,
			ProjectID:    testProjectID,
			LoginHint:    "frank@example.com",
			Scope:        "openid",
		})
		require.NoError(t, err)

		// The row stays PENDING on purpose: a correct-secret Redeem then stops
		// at authorization_pending, proving client auth passed and the polling
		// state machine was reached — without needing the (nil) credential
		// service that token issuance would require.

		// Missing secret → invalid_client (NOT authorization_pending).
		_, e1 := bcSvc.Redeem(ctx, service.RedeemInput{
			AuthReqID: out.AuthReqID,
			ClientID:  confClient.ClientID,
		})
		requireOAuthError(t, e1, oautherror.InvalidClient)

		// Wrong secret → invalid_client.
		_, e2 := bcSvc.Redeem(ctx, service.RedeemInput{
			AuthReqID:    out.AuthReqID,
			ClientID:     confClient.ClientID,
			ClientSecret: "definitely-not-the-secret",
		})
		requireOAuthError(t, e2, oautherror.InvalidClient)

		// Correct secret → past client auth, into the polling state machine.
		_, e3 := bcSvc.Redeem(ctx, service.RedeemInput{
			AuthReqID:    out.AuthReqID,
			ClientID:     confClient.ClientID,
			ClientSecret: confClient.ClientSecret,
		})
		requireOAuthError(t, e3, oautherror.AuthorizationPending)
	})
}

// requireOAuthError asserts that err is a *service.OAuthError carrying the
// expected RFC 6749 error code (the codes are the string constants in
// internal/oautherror).
func requireOAuthError(t *testing.T, err error, wantCode string) {
	t.Helper()
	require.Error(t, err)
	var oe *service.OAuthError
	require.True(t, errors.As(err, &oe), "expected a *service.OAuthError, got %T: %v", err, err)
	require.Equal(t, wantCode, oe.Code, "OAuth error code mismatch (err=%v)", err)
}
