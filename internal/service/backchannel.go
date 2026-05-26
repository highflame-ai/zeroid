package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
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

	// rarValidators is the deployer-supplied per-type validator registry
	// for RFC 9396 authorization_details. Guarded by mu (the same lock
	// that protects notifier) so a concurrent Register/Unregister cannot
	// race with a bc-authorize handler reading the map. Map writes are
	// rare (deployer-side at server-init); reads are per-request — but
	// the map is small (single-digit entries in practice) so RLock + map
	// lookup is well under microsecond cost.
	rarValidators map[string]AuthorizationDetailValidator

	// svcCtx is the long-lived context used by detached notifier goroutines.
	// Server.Shutdown cancels it via Stop() so in-flight notifier deliveries
	// can wind down on graceful shutdown instead of leaking past the server's
	// HTTP listener close. Initialised by Start(); ctx.Background-derived
	// until Start is invoked so that test harnesses that never call Start
	// still get a working notifier path.
	svcCtx    context.Context
	svcCancel context.CancelFunc

	// Ping mode (PR 2) — bounded outbound HTTP client. The RoundTripper is
	// swappable so tests can capture POSTs without standing up an httptest
	// listener; production should leave it nil (uses http.DefaultTransport
	// with a 10-second timeout enforced by pingClient.Timeout).
	pingClient        *http.Client
	pingDispatchAsync bool // overridable for tests
}

// BackchannelNotifierFunc is the internal alias for the public
// zeroid.BackchannelNotifier signature. Kept service-package-local so
// that internal callers don't need to import the top-level package.
type BackchannelNotifierFunc func(ctx context.Context, n BackchannelNotification) error

// AuthorizationDetailValidator is the internal alias for the public
// zeroid.AuthorizationDetailValidator. See the top-level package's doc
// for semantics; the wrapper in server.go bridges the two type names so
// internal callers don't reach across packages.
type AuthorizationDetailValidator func(raw json.RawMessage) error

// BackchannelNotification is the payload delivered to the notifier.
// Mirrors the public zeroid.BackchannelNotification shape — the top-level
// Server.SetBackchannelNotifier hook wraps the public type into this one.
type BackchannelNotification struct {
	AuthReqID            string
	AccountID            string
	ProjectID            string
	ClientID             string
	LoginHint            string
	Scope                string
	BindingMessage       string
	ExpiresAt            time.Time
	AuthorizationDetails domain.AuthorizationDetails
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
	// Ping-mode tunables (PR 2).
	PingTimeout    time.Duration // per-attempt HTTP timeout
	PingMaxRetries int           // additional attempts on transient failure; 0 → no retries
	PingBaseDelay  time.Duration // first-retry backoff; doubled per attempt with jitter

	// AllowPrivateNotificationEndpoints relaxes the SSRF guard on
	// outbound CIBA notification destinations when true. Defaults to false
	// (production-safe). Production deployments must keep this false — see
	// GHSA-599q-j34m-33vc. Flip to true ONLY in single-tenant test/dev
	// environments that need to register loopback-style endpoints like
	// https://localhost:9000/. Mirrors OAuthClientService's same-named
	// setter; both should be set from the same source in the deployer's
	// server construction code.
	AllowPrivateNotificationEndpoints bool
}

// DefaultBackchannelConfig returns sensible defaults for production deployments.
func DefaultBackchannelConfig() BackchannelServiceConfig {
	return BackchannelServiceConfig{
		DefaultExpiry:          5 * time.Minute,
		MaxExpiry:              15 * time.Minute,
		MinPollInterval:        2 * time.Second,
		DefaultPollInterval:    5,
		MaxBindingMessageBytes: 280,
		PingTimeout:            10 * time.Second,
		PingMaxRetries:         3,
		PingBaseDelay:          500 * time.Millisecond,
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
	if cfg.PingTimeout == 0 {
		cfg.PingTimeout = 10 * time.Second
	}
	if cfg.PingBaseDelay == 0 {
		cfg.PingBaseDelay = 500 * time.Millisecond
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
		pingClient:          &http.Client{Timeout: cfg.PingTimeout},
		pingDispatchAsync:   true,
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

// RegisterAuthorizationDetailValidator wires a deployer-supplied validator
// for the named RAR `type` discriminator. Replaces any prior validator for
// the same type. Safe to call concurrently with bc-authorize handling —
// the registry is read under RLock per request.
func (s *BackchannelService) RegisterAuthorizationDetailValidator(typ string, fn AuthorizationDetailValidator) {
	if typ == "" || fn == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.rarValidators == nil {
		s.rarValidators = make(map[string]AuthorizationDetailValidator)
	}

	s.rarValidators[typ] = fn
}

// UnregisterAuthorizationDetailValidator removes the validator for typ if
// one was registered. No-op when no validator is registered.
func (s *BackchannelService) UnregisterAuthorizationDetailValidator(typ string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.rarValidators, typ)
}

// rarValidatorFor returns the registered validator for typ, or nil if none.
// Reads under RLock so concurrent bc-authorize handlers don't serialise.
func (s *BackchannelService) rarValidatorFor(typ string) AuthorizationDetailValidator {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.rarValidators[typ]
}

// SetPingTransport overrides the outbound HTTP transport used for CIBA ping
// dispatch. Tests inject a capturing RoundTripper here so they don't have to
// stand up a real httptest listener. Pass nil to restore the default
// http.Transport.
func (s *BackchannelService) SetPingTransport(rt http.RoundTripper) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pingClient = &http.Client{Timeout: s.cfg.PingTimeout, Transport: rt}
}

// SetPingDispatchSync forces synchronous ping dispatch — test-only.
func (s *BackchannelService) SetPingDispatchSync(sync bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pingDispatchAsync = !sync
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
	// ClientNotificationToken triggers ping-mode dispatch when non-empty.
	// CIBA Core §7.1: the server includes this verbatim as the bearer
	// credential in the ping callback's Authorization header. The client
	// uses it to authenticate the inbound notification.
	ClientNotificationToken string
	// AuthorizationDetailsRaw is the RFC 9396 `authorization_details` JSON
	// array as supplied on the bc-authorize form, before parsing or
	// validation. Empty when the client omits the parameter (legacy CIBA
	// behavior unchanged). The service validates outer shape, runs any
	// registered per-type validators, and persists the bytes verbatim so
	// downstream consumers (the BackchannelNotifier, the future token-embed
	// path) see the exact JSON the client supplied.
	AuthorizationDetailsRaw []byte
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

	// Determine notification mode. CIBA Core §10 makes the delivery mode a
	// property of the client registration, not the per-request — so we read
	// the row off the client and let the per-request client_notification_token
	// presence act only as a gate (ping/push without a bearer the server can
	// echo isn't useful).
	declared := domain.BackchannelNotificationMode(client.BackchannelTokenDeliveryMode)
	if declared == "" {
		declared = domain.BackchannelNotificationPoll
	}
	notificationMode := domain.BackchannelNotificationPoll
	notificationEndpoint := ""
	switch declared {
	case domain.BackchannelNotificationPing, domain.BackchannelNotificationPush:
		if in.ClientNotificationToken == "" {
			return nil, oauthBadRequest("invalid_request",
				fmt.Sprintf("backchannel_token_delivery_mode=%s requires client_notification_token on bc-authorize", declared))
		}
		if client.ClientNotificationEndpoint == "" {
			return nil, oauthBadRequest("invalid_request",
				"client_notification_token requires the client to have a registered client_notification_endpoint")
		}
		// Defence-in-depth: re-validate the registered endpoint at request time.
		// Two reasons:
		//   1. Re-confirm HTTPS so a future registration-side bypass cannot
		//      silently degrade ping/push to plaintext.
		//   2. Re-resolve the host against the SSRF blocklist. The registered
		//      hostname might have been DNS-rebound to point at a private IP
		//      since registration — this catches that (GHSA-599q-j34m-33vc).
		if err := validateNotificationEndpoint(ctx, client.ClientNotificationEndpoint, s.cfg.AllowPrivateNotificationEndpoints); err != nil {
			return nil, oauthBadRequestCause("invalid_request", "client_notification_endpoint is invalid", err)
		}
		notificationMode = declared
		notificationEndpoint = client.ClientNotificationEndpoint
	default:
		// Poll mode. If the client passed a notification_token despite being
		// poll-mode, accept it but ignore — clients shouldn't conditionally
		// branch and we'd rather degrade gracefully than reject.
	}

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

	// RFC 9396 Rich Authorization Requests (RAR).
	//
	// Three steps in order:
	//   1. Size-cap the raw bytes before parsing so a multi-MB payload is
	//      rejected before allocating the typed slice.
	//   2. Parse with domain.ParseAuthorizationDetails — enforces outer
	//      shape (array of objects, each with a non-empty string `type`).
	//   3. Run any deployer-registered per-type validator. RFC 9396 §5.4
	//      specifies `invalid_authorization_details` as the OAuth error
	//      code for any RAR-specific rejection; map both the outer-shape
	//      failure and any per-type rejection to that code.
	rarDetails, rarRaw, err := s.parseAndValidateAuthorizationDetails(in.AuthorizationDetailsRaw)
	if err != nil {
		return nil, err
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
		AuthReqID:                  authReqID,
		AccountID:                  in.AccountID,
		ProjectID:                  in.ProjectID,
		ClientID:                   in.ClientID,
		LoginHint:                  in.LoginHint,
		Scope:                      in.Scope,
		BindingMessage:             bindingMsg,
		AuthorizationDetailsRaw:    rarRaw,
		NotificationMode:           notificationMode,
		ClientNotificationEndpoint: notificationEndpoint,
		ClientNotificationToken:    in.ClientNotificationToken,
		Status:                     domain.BackchannelStatusPending,
		IntervalSeconds:            s.cfg.DefaultPollInterval,
		ExpiresAt:                  now.Add(expiry),
		CreatedAt:                  now,
	}
	if err := s.repo.Create(ctx, row); err != nil {
		return nil, oauthServerError("failed to persist backchannel auth request", err)
	}

	s.dispatchNotifierWithRAR(ctx, row, rarDetails)

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
	// Re-load so callbacks see the persisted approved_subject_* fields and
	// the updated status. Ping/push dispatchers consume these.
	persisted, err := s.repo.GetByAuthReqID(ctx, in.AuthReqID)
	if err == nil {
		s.dispatchResolution(ctx, persisted, resolutionApproved)
	} else {
		log.Warn().Err(err).Str("auth_req_id", in.AuthReqID).Msg("approved row reload failed; dispatch skipped")
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
	persisted, err := s.repo.GetByAuthReqID(ctx, in.AuthReqID)
	if err == nil {
		s.dispatchResolution(ctx, persisted, resolutionDenied)
	} else {
		log.Warn().Err(err).Str("auth_req_id", in.AuthReqID).Msg("denied row reload failed; dispatch skipped")
	}
	return nil
}

// resolutionOutcome is the post-transition state used by dispatchResolution
// to select the right ping/push payload.
type resolutionOutcome int

const (
	resolutionApproved resolutionOutcome = iota
	resolutionDenied
)

// dispatchResolution selects the right callback path for the row's
// notification mode and the outcome (approved/denied):
//
//	mode=poll  → no callback; client must poll
//	mode=ping  → POST {auth_req_id} to client_notification_endpoint
//	mode=push  → on approved, mint the access token and POST the full
//	             token response; on denied, POST the OAuth error body.
//
// Push-mode minting happens HERE rather than inside Redeem so that the
// token is delivered exactly once — either via push or, for ping/poll,
// via a subsequent /oauth2/token call. Redeem refuses push-mode rows.
func (s *BackchannelService) dispatchResolution(ctx context.Context, row *domain.BackchannelAuthRequest, outcome resolutionOutcome) {
	if row == nil {
		return
	}
	switch row.NotificationMode {
	case domain.BackchannelNotificationPing:
		s.dispatchPing(ctx, row)
	case domain.BackchannelNotificationPush:
		if outcome == resolutionApproved {
			s.dispatchPushApproval(ctx, row)
		} else {
			s.dispatchPushDenial(ctx, row)
		}
	}
}

// RedeemInput is the polling-side input the CIBA grant handler hands over.
type RedeemInput struct {
	AuthReqID string
	ClientID  string
	// DPoPKeyThumbprint forwards the proof key thumbprint from the token
	// endpoint so a CIBA-redeemed token can still be DPoP-bound (RFC 9449).
	// Non-empty when the polling /oauth2/token call carried a valid DPoP
	// proof; the issued credential then carries cnf.jkt + token_type "DPoP".
	DPoPKeyThumbprint string
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

	// Push mode never permits polling — the token is delivered via the
	// callback exactly once. Allowing both would double-deliver and break
	// single-use semantics.
	if row.NotificationMode == domain.BackchannelNotificationPush {
		return nil, oauthBadRequest("access_denied", "auth_req_id is delivered via push callback; polling is not permitted")
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
		return s.issueTokenForApprovedRow(ctx, row, in.DPoPKeyThumbprint)

	default:
		return nil, oauthBadRequest("invalid_grant", fmt.Sprintf("unexpected request status %q", row.Status))
	}
}

// issueTokenForApprovedRow mints the CIBA access token for an approved row
// and atomically flips the row to status='issued'. Shared between Redeem
// (poll/ping modes — client pulls via /oauth2/token) and dispatchPushApproval
// (push mode — server delivers via callback).
//
// Caller MUST hold the invariant that row.Status == approved. The MarkIssued
// guard provides the actual at-most-once gate; on a lost race the second
// caller gets affected=0 and an *OAuthError signalling the duplication.
func (s *BackchannelService) issueTokenForApprovedRow(ctx context.Context, row *domain.BackchannelAuthRequest, dpopKeyThumbprint string) (*domain.AccessToken, error) {
	// Claim-first: flip approved → issued BEFORE minting the token so only
	// one caller can ever reach IssueCredential. The conditional UPDATE in
	// MarkIssued (status='approved' guard) is the at-most-once invariant;
	// a concurrent caller gets affected=0 and is rejected with access_denied.
	// This matches the CIBA Core "auth_req_id is single-use" requirement
	// and prevents the double-mint window that mint-first would expose.
	//
	// Trade-off: if IssueCredential fails after the row has been flipped to
	// "issued", the user is locked out of retrying this auth_req_id and must
	// initiate a new bc-authorize. That's preferable to silently minting two
	// tokens — the failure is loud (HTTP 500) and the client's
	// retry-with-new-auth-req-id path handles it cleanly.
	affected, mErr := s.repo.MarkIssued(ctx, row.AuthReqID)
	if mErr != nil {
		log.Error().Err(mErr).Str("auth_req_id", row.AuthReqID).Msg("failed to mark backchannel request issued")
		return nil, oauthServerError("failed to commit issuance state", mErr)
	}
	if affected == 0 {
		return nil, oauthBadRequest("access_denied", "auth_req_id has already been redeemed")
	}

	// Synthesise an identity for the approved user. CIBA Core §10.1.2 requires
	// the issued token to identify the user; we mirror ExternalPrincipalExchange
	// (the human-token path).
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
		Identity:          identity,
		Scopes:            parseScopeString(row.Scope),
		GrantType:         domain.GrantTypeCIBA,
		TTL:               900, // 15 minutes — short-lived; matches ExternalPrincipalExchange
		UseRS256:          true,
		SubjectOverride:   row.ApprovedSubjectID,
		UserEmail:         row.ApprovedSubjectEmail,
		UserName:          row.ApprovedSubjectName,
		CustomClaims:      customClaims,
		DPoPKeyThumbprint: dpopKeyThumbprint,
	})
	if err != nil {
		return nil, oauthServerError("failed to issue CIBA-grant token", err)
	}

	accessToken.AccountID = row.AccountID
	accessToken.ProjectID = row.ProjectID
	return accessToken, nil
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

// parseAndValidateAuthorizationDetails enforces RFC 9396 §2 outer shape on
// the raw `authorization_details` JSON, then runs any registered per-type
// validators. Returns:
//   - the typed slice (nil-or-empty for callers that omit the parameter,
//     keeping the legacy CIBA path branch-free),
//   - the canonical raw bytes to persist on the row (nil if the client
//     supplied nothing, to preserve the empty-array DEFAULT semantics in
//     the Postgres column),
//   - an OAuth-shaped error mapped to invalid_authorization_details for
//     any rejection (RFC 9396 §5.4).
func (s *BackchannelService) parseAndValidateAuthorizationDetails(raw []byte) (domain.AuthorizationDetails, []byte, error) {
	// emptyRAR is the canonical persisted value for "client supplied no
	// authorization_details" — the same JSON shape as the column's DB
	// default. We persist this explicitly (instead of letting bun emit
	// NULL via a `nullzero` tag and relying on Postgres to swap NULL for
	// DEFAULT — which Postgres does not do) so the insert path is
	// independent of bun's zero-value handling. Belt-and-suspenders with
	// the migration's NOT NULL DEFAULT '[]'::jsonb.
	emptyRAR := []byte("[]")

	if len(raw) == 0 {
		return nil, emptyRAR, nil
	}

	if len(raw) > domain.MaxAuthorizationDetailsBytes {
		return nil, nil, oauthBadRequestCause(
			"invalid_authorization_details",
			fmt.Sprintf("authorization_details exceeds %d bytes", domain.MaxAuthorizationDetailsBytes),
			fmt.Errorf("%w: length %d > cap %d",
				domain.ErrAuthorizationDetailsOversized,
				len(raw), domain.MaxAuthorizationDetailsBytes),
		)
	}

	parsed, err := domain.ParseAuthorizationDetails(raw)
	if err != nil {
		return nil, nil, oauthBadRequestCause(
			"invalid_authorization_details",
			"authorization_details is not a valid RFC 9396 array of typed objects",
			err,
		)
	}

	if len(parsed) == 0 {
		// Empty array or `null` — treat as if the client omitted the
		// parameter. Persist the canonical empty array so the row's
		// authorization_details column always carries a valid JSONB
		// value, never NULL.
		return nil, emptyRAR, nil
	}

	// Run any deployer-registered per-type validator. Types without a
	// registration pass through (outer-shape-only validation is the
	// permissive default). Strict allow-listing (reject unknown types
	// during bc-authorize) is not expressible via this registry — see
	// the public docs on Server.RegisterAuthorizationDetailValidator.
	for i, d := range parsed {
		fn := s.rarValidatorFor(d.Type)
		if fn == nil {
			continue
		}

		// runRARValidator wraps fn in a defer-recover so a buggy
		// deployer-registered validator (nil-deref, library panic) maps
		// to invalid_authorization_details rather than escaping as
		// HTTP 500 via chi's Recoverer. RFC 9396 §5.4 is the only error
		// code clients should see for any RAR-side rejection.
		if vErr := runRARValidator(fn, d.Raw); vErr != nil {
			return nil, nil, oauthBadRequestCause(
				"invalid_authorization_details",
				fmt.Sprintf("authorization_details[%d] (type=%q): %s", i, d.Type, vErr.Error()),
				vErr,
			)
		}
	}

	return parsed, raw, nil
}

// runRARValidator invokes a deployer-registered validator and converts any
// panic into an error so the caller can map it to the RFC 9396 §5.4 OAuth
// error code uniformly with explicit-error returns.
func runRARValidator(fn AuthorizationDetailValidator, raw json.RawMessage) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("validator panicked: %v", r)
		}
	}()

	return fn(raw)
}

// dispatchNotifierWithRAR fires the BackchannelNotifier hook with the parsed
// authorization_details threaded through to the notification payload.
//
// Runs on a goroutine by default so notifier latency (third-party push
// providers, SMS APIs) does not block the bc-authorize response. Failures
// are recorded on the row's last_notify_error for operator debugging —
// the request remains valid because the user may approve through another
// channel. Tests can flip dispatch to synchronous via
// SetNotifyDispatchSync(true).
//
// The inbound request's ctx is intentionally NOT carried into the dispatch:
// the deliver goroutine parents on the service's long-lived svcCtx so a
// client disconnect can't cancel an already-fired approval prompt. Graceful
// shutdown still cancels deliveries via Server.Shutdown → Stop().
func (s *BackchannelService) dispatchNotifierWithRAR(
	_ context.Context,
	row *domain.BackchannelAuthRequest,
	details domain.AuthorizationDetails,
) {
	// Single RLock snapshot of all the shared state the dispatch path
	// needs. Holding RLock across the snapshot prevents a Stop() racing
	// in between two separate acquisitions and leaving us with a
	// half-stale view (e.g., notifier installed, svcCtx already nil).
	s.mu.RLock()
	fn := s.notifier
	async := s.notifyDispatchAsync
	parent := s.svcCtx
	s.mu.RUnlock()

	if fn == nil || parent == nil {
		return
	}

	payload := BackchannelNotification{
		AuthReqID:            row.AuthReqID,
		AccountID:            row.AccountID,
		ProjectID:            row.ProjectID,
		ClientID:             row.ClientID,
		LoginHint:            row.LoginHint,
		Scope:                row.Scope,
		BindingMessage:       row.BindingMessage,
		ExpiresAt:            row.ExpiresAt,
		AuthorizationDetails: details,
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

// dispatchPushApproval mints the access token for an approved push-mode
// request and POSTs the full token-endpoint response (CIBA Core §10.3.1)
// to the client's registered notification endpoint. The bearer header carries
// the per-request client_notification_token so the client can authenticate
// the inbound delivery.
//
// At-most-once delivery is guaranteed by issueTokenForApprovedRow's MarkIssued
// gate — a parallel call gets access_denied and we don't double-post. On
// transport failure, the row stays issued (single-use is sacrificed for
// retry simplicity: a client that registered push mode trusts the server's
// delivery; if the callback host is unreachable, the deployer operationalises
// retry through the admin API or, more realistically, falls back to ping mode).
//
// Network retry uses the same exponential-backoff + jitter loop as
// dispatchPing. 4xx is terminal, 5xx is retried. last_notify_error is
// recorded so operators see why a token never landed.
func (s *BackchannelService) dispatchPushApproval(ctx context.Context, row *domain.BackchannelAuthRequest) {
	if row == nil || row.NotificationMode != domain.BackchannelNotificationPush {
		return
	}
	if row.ClientNotificationEndpoint == "" || row.ClientNotificationToken == "" {
		return
	}

	// Push mode mints server-side without a client polling the token endpoint,
	// so there is no DPoP proof — passes empty thumbprint to keep the token
	// as Bearer. Resource-server-side DPoP for CIBA-push tokens is a future
	// item if it's ever needed.
	accessToken, err := s.issueTokenForApprovedRow(ctx, row, "")
	if err != nil {
		// Most likely an OAuthError("access_denied") from a lost race against
		// a concurrent dispatch. Log and exit — the first dispatcher will
		// have delivered (or will deliver).
		log.Warn().Err(err).Str("auth_req_id", row.AuthReqID).Msg("push approval mint failed")
		_ = s.repo.SetLastNotifyError(ctx, row.AuthReqID, err.Error())
		return
	}

	// Build the CIBA Core §10.3.1 push notification body. Mirrors the
	// /oauth2/token success response shape so clients can reuse their
	// existing token-response parser.
	tokenType := accessToken.TokenType
	if tokenType == "" {
		tokenType = "Bearer"
	}
	payload := map[string]any{
		"access_token": accessToken.AccessToken,
		"token_type":   tokenType,
		"expires_in":   accessToken.ExpiresIn,
		"auth_req_id":  row.AuthReqID,
	}
	if accessToken.Scope != "" {
		payload["scope"] = accessToken.Scope
	}
	if accessToken.RefreshToken != "" {
		payload["refresh_token"] = accessToken.RefreshToken
	}

	s.postCallback(ctx, row, payload)
}

// dispatchPushDenial POSTs the OAuth error body (CIBA Core §10.3.2) to the
// client's notification endpoint when the user denies a push-mode request.
// No token is minted. Mirrors RFC 6749 §5.2 error shape so clients can reuse
// their existing token-error parser.
func (s *BackchannelService) dispatchPushDenial(ctx context.Context, row *domain.BackchannelAuthRequest) {
	if row == nil || row.NotificationMode != domain.BackchannelNotificationPush {
		return
	}
	if row.ClientNotificationEndpoint == "" || row.ClientNotificationToken == "" {
		return
	}
	payload := map[string]any{
		"error":             "access_denied",
		"error_description": "the user denied the authentication request",
		"auth_req_id":       row.AuthReqID,
	}
	s.postCallback(ctx, row, payload)
}

// postCallback is the shared outbound POST machinery for push approval/denial.
// Detached context, exponential backoff + jitter, 4xx terminal / 5xx retried,
// last_notify_error recorded. Shared with dispatchPing's retry loop pattern
// but takes an arbitrary JSON-serializable payload.
func (s *BackchannelService) postCallback(ctx context.Context, row *domain.BackchannelAuthRequest, payload map[string]any) {
	s.mu.RLock()
	client := s.pingClient
	async := s.pingDispatchAsync
	maxRetries := s.cfg.PingMaxRetries
	baseDelay := s.cfg.PingBaseDelay
	parent := s.svcCtx
	s.mu.RUnlock()
	if parent == nil {
		// Stop() has been called; service is shutting down — drop the
		// push rather than firing into the void.
		return
	}

	endpoint := row.ClientNotificationEndpoint
	bearer := row.ClientNotificationToken
	authReqID := row.AuthReqID

	body, err := json.Marshal(payload)
	if err != nil {
		log.Error().Err(err).Str("auth_req_id", authReqID).Msg("failed to marshal push callback payload")
		return
	}

	deliver := func() {
		// Parent on svcCtx (cancelled by Server.Shutdown via Stop) instead
		// of context.Background — graceful shutdown cancels in-flight push
		// retries instead of letting them outlive the server. Still detached
		// from the inbound request's ctx so a client disconnect doesn't kill
		// the outbound delivery.
		dctx, cancel := context.WithTimeout(parent,
			s.cfg.PingTimeout*time.Duration(maxRetries+1)+baseDelay*time.Duration(maxRetries+1))
		defer cancel()

		var lastErr error
		for attempt := 0; attempt <= maxRetries; attempt++ {
			if attempt > 0 {
				delay := baseDelay << (attempt - 1)
				jitter := time.Duration(jitterMillis()) * time.Millisecond
				select {
				case <-time.After(delay + jitter):
				case <-dctx.Done():
					lastErr = dctx.Err()
					goto done
				}
			}

			req, err := http.NewRequestWithContext(dctx, http.MethodPost, endpoint, bytes.NewReader(body))
			if err != nil {
				lastErr = err
				goto done
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+bearer)
			req.Header.Set("User-Agent", "zeroid-ciba-push/1.0")

			resp, err := client.Do(req)
			if err != nil {
				lastErr = err
				continue
			}
			// Drain + close so the underlying TCP connection can be reused
			// across retries. HTTP/1.1 keepalive requires the body fully read.
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				_ = s.repo.SetLastNotifyError(dctx, authReqID, "")
				return
			}
			lastErr = fmt.Errorf("push callback returned HTTP %d", resp.StatusCode)
			if resp.StatusCode >= 400 && resp.StatusCode < 500 {
				goto done
			}
		}

	done:
		log.Warn().
			Err(lastErr).
			Str("auth_req_id", authReqID).
			Str("endpoint", endpoint).
			Msg("CIBA push dispatch failed")
		if lastErr != nil {
			if rerr := s.repo.SetLastNotifyError(dctx, authReqID, lastErr.Error()); rerr != nil {
				log.Warn().Err(rerr).Str("auth_req_id", authReqID).Msg("failed to record push last_notify_error")
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

// dispatchPing POSTs the CIBA ping callback (Core §10.2) to the client's
// registered client_notification_endpoint. The payload is the minimal
// {"auth_req_id": "..."} JSON; the access token is NOT included (that's push
// mode, which is PR 3). The Authorization header carries the client_notification_token
// the client supplied at bc-authorize so the client can authenticate the
// inbound notification.
//
// No-ops when:
//   - notification_mode is "poll"
//   - client_notification_endpoint is empty (defence-in-depth; CreateAuthRequest
//     already enforces this)
//   - client_notification_token is empty (same reason)
//
// On retryable failure (network error, 5xx) the dispatcher retries with
// exponential backoff up to PingMaxRetries; the final error is recorded on
// the row's last_notify_error column for operator debugging. Non-2xx 4xx
// responses are treated as terminal (client misconfiguration; retrying
// won't fix it).
func (s *BackchannelService) dispatchPing(ctx context.Context, row *domain.BackchannelAuthRequest) {
	if row == nil || row.NotificationMode != domain.BackchannelNotificationPing {
		return
	}
	if row.ClientNotificationEndpoint == "" || row.ClientNotificationToken == "" {
		return
	}

	s.mu.RLock()
	client := s.pingClient
	async := s.pingDispatchAsync
	maxRetries := s.cfg.PingMaxRetries
	baseDelay := s.cfg.PingBaseDelay
	parent := s.svcCtx
	s.mu.RUnlock()
	if parent == nil {
		// Stop() has been called; service is shutting down — drop the
		// ping rather than firing into the void.
		return
	}

	endpoint := row.ClientNotificationEndpoint
	bearer := row.ClientNotificationToken
	authReqID := row.AuthReqID

	deliver := func() {
		// Detach from the inbound request's ctx (so a client disconnect doesn't
		// kill the delivery — the user has already approved) but parent on
		// svcCtx so Server.Shutdown → Stop() cancels in-flight retries on
		// graceful shutdown instead of letting them outlive the server.
		dctx, cancel := context.WithTimeout(parent, s.cfg.PingTimeout*time.Duration(maxRetries+1)+baseDelay*time.Duration(maxRetries+1))
		defer cancel()

		payload, _ := json.Marshal(map[string]string{"auth_req_id": authReqID})

		var lastErr error
		for attempt := 0; attempt <= maxRetries; attempt++ {
			if attempt > 0 {
				// Exponential backoff with mild jitter. Jitter prevents
				// retry storms when many requests resolve simultaneously.
				delay := baseDelay << (attempt - 1)
				jitter := time.Duration(jitterMillis()) * time.Millisecond
				select {
				case <-time.After(delay + jitter):
				case <-dctx.Done():
					lastErr = dctx.Err()
					goto done
				}
			}

			req, err := http.NewRequestWithContext(dctx, http.MethodPost, endpoint, bytes.NewReader(payload))
			if err != nil {
				lastErr = err
				goto done // non-retryable: bad URL etc.
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+bearer)
			req.Header.Set("User-Agent", "zeroid-ciba-ping/1.0")

			resp, err := client.Do(req)
			if err != nil {
				lastErr = err
				continue // network error — retry
			}
			// Drain + close so the underlying TCP connection can be reused
			// across retries / future requests. HTTP/1.1 keepalive requires
			// the body to be fully read before the connection returns to the pool.
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				// Clear any previous last_notify_error so operators see
				// "succeeded after retry" rather than a stale failure.
				_ = s.repo.SetLastNotifyError(dctx, authReqID, "")
				return
			}
			lastErr = fmt.Errorf("ping callback returned HTTP %d", resp.StatusCode)
			if resp.StatusCode >= 400 && resp.StatusCode < 500 {
				// 4xx is terminal — client rejected the callback, retrying
				// won't change the outcome. Examples: bad bearer, wrong path.
				goto done
			}
		}

	done:
		log.Warn().
			Err(lastErr).
			Str("auth_req_id", authReqID).
			Str("endpoint", endpoint).
			Msg("CIBA ping dispatch failed")
		if lastErr != nil {
			if rerr := s.repo.SetLastNotifyError(dctx, authReqID, lastErr.Error()); rerr != nil {
				log.Warn().Err(rerr).Str("auth_req_id", authReqID).Msg("failed to record ping last_notify_error")
			}
		}
	}

	if async {
		go deliver()
		return
	}
	deliver()
}

// jitterMillis returns a random 0–250 ms jitter value for retry backoff.
// Sourced from crypto/rand so we don't depend on math/rand seeding.
func jitterMillis() int {
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	// b[0] ∈ [0,255]; scale to roughly [0, 250].
	return int(b[0]) * 250 / 255
}
