package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/store/postgres"
)

// ErrInvalidBindingMessage is the sentinel returned when binding_message
// fails validation (currently: exceeds MaxBindingMessageBytes). Service-layer
// validation errors are wrapped via %w so handlers can use errors.Is to map
// to 400 Bad Request consistently — see the convention used for other
// service-layer validation sentinels (e.g. credential policy).
var ErrInvalidBindingMessage = errors.New("invalid binding_message")

// BackchannelService implements OpenID CIBA Core 1.0 server-side flow:
// request creation, user approval / denial, polling-based token redemption.
//
// Ping mode (server POSTs to client_notification_endpoint on resolution) lands
// in PR 2; the column is already present so PR 2 needs no schema change.
// Push mode (server delivers the access token directly to the client callback)
// is deferred — it sits behind the same notifier plumbing but with additional
// payload security requirements.
type BackchannelService struct {
	repo                *postgres.BackchannelRequestRepository
	oauthClientSvc      *OAuthClientService
	credentialSvc       *CredentialService
	cfg                 BackchannelServiceConfig
	mu                  sync.RWMutex
	notifier            BackchannelNotifierFunc
	notifyDispatchAsync bool // overridable for tests

	// svcCtx is the long-lived context used by detached notifier goroutines.
	// Server.Shutdown cancels it via Stop() so in-flight notifier deliveries
	// can wind down on graceful shutdown instead of leaking past the server's
	// HTTP listener close. Initialised by Start(); ctx.Background-derived
	// until Start is invoked so that test harnesses that never call Start
	// still get a working notifier path.
	svcCtx    context.Context
	svcCancel context.CancelFunc
}

// BackchannelNotifierFunc is the internal alias for the public
// zeroid.BackchannelNotifier signature. Kept service-package-local so
// that internal callers don't need to import the top-level package.
type BackchannelNotifierFunc func(ctx context.Context, n BackchannelNotification) error

// BackchannelNotification is the payload delivered to the notifier.
// Mirrors the public zeroid.BackchannelNotification shape — the top-level
// Server.SetBackchannelNotifier hook wraps the public type into this one.
type BackchannelNotification struct {
	AuthReqID      string
	AccountID      string
	ProjectID      string
	ClientID       string
	LoginHint      string
	Scope          string
	BindingMessage string
	ExpiresAt      time.Time
}

// BackchannelServiceConfig bounds the request lifecycle.
//
//   - DefaultExpiry is used when the client omits requested_expiry; capped at MaxExpiry.
//   - MaxBindingMessageBytes caps binding_message at insertion to prevent
//     unbounded notifier payloads (binding_message is user-supplied PII-ish
//     text). 0 disables the cap.
//   - MinPollInterval is the floor for the slow_down enforcement window —
//     clients polling faster than this get slow_down even if their per-request
//     interval permits it.
type BackchannelServiceConfig struct {
	DefaultExpiry          time.Duration
	MaxExpiry              time.Duration
	MinPollInterval        time.Duration
	DefaultPollInterval    int
	MaxBindingMessageBytes int
}

// DefaultBackchannelConfig returns sensible defaults for production deployments.
func DefaultBackchannelConfig() BackchannelServiceConfig {
	return BackchannelServiceConfig{
		DefaultExpiry:          5 * time.Minute,
		MaxExpiry:              15 * time.Minute,
		MinPollInterval:        2 * time.Second,
		DefaultPollInterval:    5,
		MaxBindingMessageBytes: 280,
	}
}

// NewBackchannelService constructs the service.
func NewBackchannelService(
	repo *postgres.BackchannelRequestRepository,
	oauthClientSvc *OAuthClientService,
	credentialSvc *CredentialService,
	cfg BackchannelServiceConfig,
) *BackchannelService {
	if cfg.DefaultExpiry == 0 {
		cfg.DefaultExpiry = 5 * time.Minute
	}
	if cfg.MaxExpiry == 0 {
		cfg.MaxExpiry = 15 * time.Minute
	}
	if cfg.MinPollInterval == 0 {
		cfg.MinPollInterval = 2 * time.Second
	}
	if cfg.DefaultPollInterval == 0 {
		cfg.DefaultPollInterval = 5
	}
	if cfg.MaxBindingMessageBytes == 0 {
		cfg.MaxBindingMessageBytes = 280
	}
	svcCtx, svcCancel := context.WithCancel(context.Background())
	return &BackchannelService{
		repo:                repo,
		oauthClientSvc:      oauthClientSvc,
		credentialSvc:       credentialSvc,
		cfg:                 cfg,
		notifyDispatchAsync: true,
		svcCtx:              svcCtx,
		svcCancel:           svcCancel,
	}
}

// Stop cancels the service's lifecycle context, signalling in-flight detached
// notifier goroutines to wind down. Idempotent. Server.Shutdown calls this so
// graceful shutdown does not leak goroutines past the HTTP listener close.
// After Stop, new notifier dispatches no-op rather than launching goroutines
// against a cancelled context.
func (s *BackchannelService) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.svcCancel != nil {
		s.svcCancel()
		s.svcCancel = nil
		s.svcCtx = nil
	}
}

// SetNotifier wires the deployer's BackchannelNotifier. Safe to call any time
// after construction; concurrent reads use RLock so request handlers don't
// serialise behind notifier installation.
func (s *BackchannelService) SetNotifier(fn BackchannelNotifierFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.notifier = fn
}

// SetNotifyDispatchSync forces synchronous notifier dispatch. Tests use this
// so they can deterministically assert on the notification payload without
// goroutine races. Production must keep this false (the default) so
// notifier latency cannot block the bc-authorize response.
func (s *BackchannelService) SetNotifyDispatchSync(sync bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.notifyDispatchAsync = !sync
}

// CreateAuthRequest input for POST /oauth2/bc-authorize.
type CreateAuthRequestInput struct {
	ClientID        string
	AccountID       string
	ProjectID       string
	LoginHint       string
	Scope           string
	BindingMessage  string
	RequestedExpiry int // seconds; 0 → DefaultExpiry
}

// CreateAuthRequestOutput is returned to the client on success.
type CreateAuthRequestOutput struct {
	AuthReqID string `json:"auth_req_id"`
	ExpiresIn int    `json:"expires_in"`
	Interval  int    `json:"interval"`
}

// CreateAuthRequest validates the inbound request, mints an unguessable
// auth_req_id, persists the row, fires the notifier, and returns the polling
// parameters to the client.
//
// Errors are *OAuthError so the handler can map them straight to RFC 6749
// error responses without re-classification.
func (s *BackchannelService) CreateAuthRequest(ctx context.Context, in CreateAuthRequestInput) (*CreateAuthRequestOutput, error) {
	if in.ClientID == "" {
		return nil, oauthBadRequest("invalid_request", "client_id is required for bc-authorize")
	}
	if in.AccountID == "" || in.ProjectID == "" {
		return nil, oauthBadRequest("invalid_request", "account_id and project_id are required for bc-authorize")
	}
	if in.LoginHint == "" {
		// CIBA Core §7.1: at least one of login_hint / login_hint_token / id_token_hint
		// MUST be supplied. PR 1 supports login_hint only.
		return nil, oauthBadRequest("invalid_request", "login_hint is required")
	}

	// Validate client exists in the tenant scope. We don't enforce a
	// client_secret check here: CIBA Core §7.1 allows public clients to
	// initiate the flow, and the trust anchor for token issuance is the
	// user's approval, not the client credential.
	client, err := s.oauthClientSvc.GetClientByClientID(ctx, in.ClientID)
	if err != nil {
		return nil, oauthBadRequestCause("invalid_client", fmt.Sprintf("unknown client %s", in.ClientID), err)
	}
	_ = client // reserved for ping-mode allowlist read in PR 2

	// Reject oversized binding_message rather than silently truncating.
	// Silent truncation produced confusing UX (the prompt the user saw didn't
	// match what the client asked for) and risked invalid UTF-8 from cutting
	// mid-codepoint. The wrapped sentinel lets the handler map this to 400
	// via errors.Is.
	bindingMsg := in.BindingMessage
	if s.cfg.MaxBindingMessageBytes > 0 && len(bindingMsg) > s.cfg.MaxBindingMessageBytes {
		return nil, oauthBadRequestCause(
			"invalid_request",
			fmt.Sprintf("binding_message exceeds maximum length of %d bytes", s.cfg.MaxBindingMessageBytes),
			fmt.Errorf("%w: length %d > max %d", ErrInvalidBindingMessage, len(bindingMsg), s.cfg.MaxBindingMessageBytes),
		)
	}

	expiry := time.Duration(in.RequestedExpiry) * time.Second
	if expiry <= 0 {
		expiry = s.cfg.DefaultExpiry
	}
	if expiry > s.cfg.MaxExpiry {
		expiry = s.cfg.MaxExpiry
	}

	authReqID, err := mintAuthReqID()
	if err != nil {
		return nil, oauthServerError("failed to mint auth_req_id", err)
	}

	now := time.Now()
	row := &domain.BackchannelAuthRequest{
		AuthReqID:        authReqID,
		AccountID:        in.AccountID,
		ProjectID:        in.ProjectID,
		ClientID:         in.ClientID,
		LoginHint:        in.LoginHint,
		Scope:            in.Scope,
		BindingMessage:   bindingMsg,
		NotificationMode: domain.BackchannelNotificationPoll,
		Status:           domain.BackchannelStatusPending,
		IntervalSeconds:  s.cfg.DefaultPollInterval,
		ExpiresAt:        now.Add(expiry),
		CreatedAt:        now,
	}
	if err := s.repo.Create(ctx, row); err != nil {
		return nil, oauthServerError("failed to persist backchannel auth request", err)
	}

	s.dispatchNotifier(ctx, row)

	return &CreateAuthRequestOutput{
		AuthReqID: authReqID,
		ExpiresIn: int(expiry.Seconds()),
		Interval:  s.cfg.DefaultPollInterval,
	}, nil
}

// ApproveInput resolves a pending request positively.
type ApproveInput struct {
	AuthReqID    string
	AccountID    string
	ProjectID    string
	SubjectID    string // the approved end user — becomes JWT `sub`
	SubjectEmail string
	SubjectName  string
}

// Approve transitions the request to approved and stamps the resolved subject.
// Tenant isolation is enforced by re-loading the row and comparing
// account_id/project_id — never trust the URL handle alone.
//
// Errors:
//   - invalid_request: missing fields, tenant mismatch
//   - access_denied: row already in a terminal state, expired, or wrong tenant
func (s *BackchannelService) Approve(ctx context.Context, in ApproveInput) error {
	if in.AuthReqID == "" || in.AccountID == "" || in.ProjectID == "" || in.SubjectID == "" {
		return oauthBadRequest("invalid_request", "auth_req_id, account_id, project_id, subject_id are required to approve")
	}
	row, err := s.repo.GetByAuthReqID(ctx, in.AuthReqID)
	if err != nil {
		if errors.Is(err, postgres.ErrBackchannelRequestNotFound) {
			return oauthBadRequest("invalid_request", "unknown auth_req_id")
		}
		return oauthServerError("failed to load backchannel auth request", err)
	}
	if row.AccountID != in.AccountID || row.ProjectID != in.ProjectID {
		// Don't leak existence across tenants — same opaque error as "unknown".
		return oauthBadRequest("invalid_request", "unknown auth_req_id")
	}
	if row.Status != domain.BackchannelStatusPending {
		return oauthBadRequest("access_denied", fmt.Sprintf("request is in status %q and cannot be approved", row.Status))
	}
	if time.Now().After(row.ExpiresAt) {
		return oauthBadRequest("access_denied", "request has expired")
	}

	affected, err := s.repo.MarkApproved(ctx, in.AuthReqID, in.SubjectID, in.SubjectEmail, in.SubjectName)
	if err != nil {
		return oauthServerError("failed to mark backchannel auth request approved", err)
	}
	if affected == 0 {
		// Lost a race against expiry sweep or a concurrent deny.
		return oauthBadRequest("access_denied", "request could not be approved (concurrent modification or expiry)")
	}
	return nil
}

// DenyInput resolves a pending request negatively.
type DenyInput struct {
	AuthReqID string
	AccountID string
	ProjectID string
}

// Deny transitions the request to denied. Same tenant-isolation guarantees as Approve.
func (s *BackchannelService) Deny(ctx context.Context, in DenyInput) error {
	if in.AuthReqID == "" || in.AccountID == "" || in.ProjectID == "" {
		return oauthBadRequest("invalid_request", "auth_req_id, account_id, project_id are required to deny")
	}
	row, err := s.repo.GetByAuthReqID(ctx, in.AuthReqID)
	if err != nil {
		if errors.Is(err, postgres.ErrBackchannelRequestNotFound) {
			return oauthBadRequest("invalid_request", "unknown auth_req_id")
		}
		return oauthServerError("failed to load backchannel auth request", err)
	}
	if row.AccountID != in.AccountID || row.ProjectID != in.ProjectID {
		return oauthBadRequest("invalid_request", "unknown auth_req_id")
	}
	if row.Status != domain.BackchannelStatusPending {
		return oauthBadRequest("access_denied", fmt.Sprintf("request is in status %q and cannot be denied", row.Status))
	}
	affected, err := s.repo.MarkDenied(ctx, in.AuthReqID)
	if err != nil {
		return oauthServerError("failed to mark backchannel auth request denied", err)
	}
	if affected == 0 {
		return oauthBadRequest("access_denied", "request could not be denied (concurrent modification or expiry)")
	}
	return nil
}

// RedeemInput is the polling-side input the CIBA grant handler hands over.
type RedeemInput struct {
	AuthReqID string
	ClientID  string
}

// Redeem implements the polling response state machine per CIBA Core §11.
// Returns the access token on success, or an *OAuthError carrying one of:
// authorization_pending, slow_down, access_denied, expired_token, invalid_grant.
func (s *BackchannelService) Redeem(ctx context.Context, in RedeemInput) (*domain.AccessToken, error) {
	if in.AuthReqID == "" {
		return nil, oauthBadRequest("invalid_grant", "auth_req_id is required for grant_type=urn:openid:params:grant-type:ciba")
	}
	row, err := s.repo.GetByAuthReqID(ctx, in.AuthReqID)
	if err != nil {
		if errors.Is(err, postgres.ErrBackchannelRequestNotFound) {
			return nil, oauthBadRequest("invalid_grant", "unknown auth_req_id")
		}
		return nil, oauthServerError("failed to load backchannel auth request", err)
	}
	if in.ClientID != "" && row.ClientID != in.ClientID {
		// Mismatch means a different client is polling — refuse without leaking detail.
		return nil, oauthBadRequest("invalid_grant", "auth_req_id was not issued to this client")
	}

	now := time.Now()
	if now.After(row.ExpiresAt) && row.Status == domain.BackchannelStatusPending {
		// Race against the sweep: surface expired_token immediately.
		return nil, oauthBadRequest("expired_token", "the backchannel authentication request has expired")
	}

	switch row.Status {
	case domain.BackchannelStatusPending:
		// Enforce the slow_down floor — clients that poll faster than
		// MinPollInterval get a 400 even if their previous response said they could.
		if row.LastPolledAt != nil && now.Sub(*row.LastPolledAt) < s.cfg.MinPollInterval {
			return nil, oauthBadRequest("slow_down", "polling interval must be at least the value returned by the bc-authorize response")
		}
		if err := s.repo.TouchPoll(ctx, in.AuthReqID, now); err != nil {
			log.Warn().Err(err).Str("auth_req_id", in.AuthReqID).Msg("failed to record poll timestamp")
		}
		return nil, oauthBadRequest("authorization_pending", "the user has not yet acted on the authentication request")

	case domain.BackchannelStatusDenied:
		return nil, oauthBadRequest("access_denied", "the user denied the authentication request")

	case domain.BackchannelStatusExpired:
		return nil, oauthBadRequest("expired_token", "the backchannel authentication request has expired")

	case domain.BackchannelStatusIssued:
		// A successful token was already minted for this auth_req_id. Refuse
		// re-redemption — auth codes / auth_req_ids are single-use.
		return nil, oauthBadRequest("access_denied", "auth_req_id has already been redeemed")

	case domain.BackchannelStatusApproved:
		// Claim-first: flip approved → issued BEFORE minting the token so
		// only one polling thread can ever reach IssueCredential. The
		// conditional UPDATE in MarkIssued (status='approved' guard) is the
		// at-most-once invariant; a concurrent caller gets affected=0 and
		// is rejected with access_denied. This matches the CIBA Core
		// "auth_req_id is single-use" requirement and prevents the
		// previously-documented double-mint window.
		//
		// Trade-off: if IssueCredential fails after the row has been
		// flipped to "issued", the user is locked out of retrying this
		// auth_req_id and must initiate a new bc-authorize. That's
		// preferable to silently minting two tokens — the failure is
		// loud (HTTP 500) and the client's retry-with-new-auth-req-id
		// path handles it cleanly.
		affected, mErr := s.repo.MarkIssued(ctx, in.AuthReqID)
		if mErr != nil {
			return nil, oauthServerError("failed to mark backchannel request issued", mErr)
		}
		if affected == 0 {
			return nil, oauthBadRequest("access_denied", "auth_req_id has already been redeemed")
		}

		// Synthesise an identity for the approved user. CIBA Core §10.1.2
		// requires the issued token to identify the user; we mirror the
		// pattern used by ExternalPrincipalExchange (the human-token path).
		identity := &domain.Identity{
			AccountID:    row.AccountID,
			ProjectID:    row.ProjectID,
			IdentityType: domain.IdentityTypeService,
			Status:       domain.IdentityStatusActive,
		}
		customClaims := map[string]any{
			"token_exchange":        "ciba",
			"backchannel_client_id": row.ClientID,
		}
		if row.BindingMessage != "" {
			customClaims["binding_message"] = row.BindingMessage
		}

		accessToken, _, err := s.credentialSvc.IssueCredential(ctx, IssueRequest{
			Identity:        identity,
			Scopes:          parseScopeString(row.Scope),
			GrantType:       domain.GrantTypeCIBA,
			TTL:             900, // 15 minutes — short-lived; matches ExternalPrincipalExchange
			UseRS256:        true,
			SubjectOverride: row.ApprovedSubjectID,
			UserEmail:       row.ApprovedSubjectEmail,
			UserName:        row.ApprovedSubjectName,
			CustomClaims:    customClaims,
		})
		if err != nil {
			return nil, oauthServerError("failed to issue CIBA-grant token", err)
		}

		accessToken.AccountID = row.AccountID
		accessToken.ProjectID = row.ProjectID
		return accessToken, nil

	default:
		return nil, oauthBadRequest("invalid_grant", fmt.Sprintf("unexpected request status %q", row.Status))
	}
}

// SweepExpired and DeleteExpired are wired by the cleanup worker; surfaced
// here as thin facades so the worker doesn't have to import the postgres
// package directly. Returning (int64, error) preserves observability.
func (s *BackchannelService) SweepExpired(ctx context.Context, now time.Time) (int64, error) {
	return s.repo.SweepExpired(ctx, now)
}
func (s *BackchannelService) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	return s.repo.DeleteExpired(ctx, now)
}

// dispatchNotifier fires the notifier hook on a goroutine so notifier latency
// (third-party push providers, SMS APIs) does not block the bc-authorize
// response. Failures are recorded on the row's last_notify_error for
// operator debugging — the request remains valid because the user may
// approve through another channel.
//
// Tests can flip dispatch to synchronous via SetNotifyDispatchSync(true).
func (s *BackchannelService) dispatchNotifier(ctx context.Context, row *domain.BackchannelAuthRequest) {
	s.mu.RLock()
	fn := s.notifier
	async := s.notifyDispatchAsync
	s.mu.RUnlock()
	if fn == nil {
		return
	}

	payload := BackchannelNotification{
		AuthReqID:      row.AuthReqID,
		AccountID:      row.AccountID,
		ProjectID:      row.ProjectID,
		ClientID:       row.ClientID,
		LoginHint:      row.LoginHint,
		Scope:          row.Scope,
		BindingMessage: row.BindingMessage,
		ExpiresAt:      row.ExpiresAt,
	}

	// Parent the detached context on svcCtx (cancelled by Server.Shutdown via
	// BackchannelService.Stop) instead of context.Background — that way a
	// graceful shutdown cancels in-flight notifier deliveries instead of
	// letting them outlive the server. We still detach from the inbound
	// request's ctx so a client disconnect doesn't kill the notification.
	s.mu.RLock()
	parent := s.svcCtx
	s.mu.RUnlock()
	if parent == nil {
		// Stop() has been called; service is shutting down — drop the
		// notification rather than firing into the void.
		return
	}

	deliver := func() {
		dctx, cancel := context.WithTimeout(parent, 10*time.Second)
		defer cancel()
		if err := fn(dctx, payload); err != nil {
			log.Warn().Err(err).Str("auth_req_id", row.AuthReqID).Msg("backchannel notifier returned error")
			if rerr := s.repo.SetLastNotifyError(dctx, row.AuthReqID, err.Error()); rerr != nil {
				log.Warn().Err(rerr).Str("auth_req_id", row.AuthReqID).Msg("failed to record last_notify_error")
			}
		}
	}

	if async {
		go deliver()
		return
	}
	deliver()
}

// mintAuthReqID returns a 32-byte URL-safe random handle. 256 bits of entropy
// makes guessing infeasible; the value is opaque to clients.
func mintAuthReqID() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
