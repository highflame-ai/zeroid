package aauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
)

// Revoking agent tokens at the agent's person server (protocol draft, "Token
// Revocation"). An agent token is revoked by the Agent Provider that issued
// it, at the person server only: the token's ps. ZeroID records every agent
// and sub-agent token it issues with a ps claim in aauth_ps_revocations, and
// a worker sends the revocation once the token's credential is revoked or
// its identity is no longer active, retrying until the person server records
// it, says it takes none, or the token expires. Every revocation path
// (an admin revoke, a cascade, deactivation, suspension, offboarding) ends in
// one of those states, so none needs its own hook.

// PersonServerMetadataDWK is the person server's metadata document.
const PersonServerMetadataDWK = "aauth-person.json"

// DefaultPSRevocationInterval is how often the worker looks for revoked
// tokens to send.
const DefaultPSRevocationInterval = 15 * time.Second

// Outcomes recorded in aauth_ps_revocations.outcome.
const (
	psOutcomeRevoked     = "revoked"                // the person server recorded it (200)
	psOutcomeUnsupported = "revocation_unsupported" // no revocation_endpoint, or unsupported_iss
	psOutcomeRejected    = "rejected"               // a 4xx no retry fixes; logged
)

// maxPSPollWait bounds how long one revocation waits on a 202 before it is
// left for a later pass (re-sending is idempotent at the person server).
const maxPSPollWait = 30 * time.Second

// errPSRetry marks a revocation with no terminal outcome yet: retried later.
type errPSRetry struct {
	err        error
	retryAfter time.Duration
}

func (e *errPSRetry) Error() string { return e.err.Error() }
func (e *errPSRetry) Unwrap() error { return e.err }

// trackForPersonServer records an issued agent token with a ps claim, so its
// revocation reaches the person server. A token that cannot be tracked is
// revoked here and the issuance fails: a revocation that could never be sent
// would leave the person server honouring it until it expires.
func (p *Provider) trackForPersonServer(ctx context.Context, row *domain.IssuedCredential, ps string) error {
	if ps == "" || row == nil {
		return nil
	}
	_, err := p.db.NewRaw(`INSERT INTO aauth_ps_revocations (jti, person_server, expires_at)
		VALUES (?, ?, ?) ON CONFLICT (jti) DO NOTHING`, row.JTI, ps, row.ExpiresAt).Exec(ctx)
	if err == nil {
		return nil
	}
	if rErr := p.creds.RevokeCredential(ctx, row.ID, row.AccountID, row.ProjectID,
		"could not record the agent token for revocation at its person server"); rErr != nil {
		log.Error().Err(rErr).Str("jti", row.JTI).Msg("aauth: could not revoke an agent token that could not be tracked for its person server")
	}
	return fmt.Errorf("recording the agent token for its person server: %w", err)
}

// RunPersonServerRevocations sends pending person-server revocations every
// interval until ctx ends. Zero means DefaultPSRevocationInterval.
func (p *Provider) RunPersonServerRevocations(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultPSRevocationInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if _, err := p.SendPersonServerRevocations(ctx); err != nil && ctx.Err() == nil {
			log.Warn().Err(err).Msg("aauth: person-server revocation pass failed")
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// pendingPSRevocation is a tracked agent token due to be revoked at its
// person server.
type pendingPSRevocation struct {
	JTI          string    `bun:"jti"`
	PersonServer string    `bun:"person_server"`
	ExpiresAt    time.Time `bun:"expires_at"`
	Attempts     int       `bun:"attempts"`
}

// SendPersonServerRevocations runs one pass: every tracked, unexpired token
// whose credential is revoked or whose identity is not active, and which is
// due, is revoked at its person server. It returns how many reached a
// terminal outcome. Several replicas may send the same revocation; the
// person server treats a repeat as idempotent.
func (p *Provider) SendPersonServerRevocations(ctx context.Context) (int, error) {
	now := p.now()
	var due []pendingPSRevocation
	err := p.db.NewRaw(`SELECT r.jti, r.person_server, r.expires_at, r.attempts
		FROM aauth_ps_revocations r
		JOIN issued_credentials ic ON ic.jti = r.jti
		LEFT JOIN identities i ON i.id = ic.identity_id
		WHERE r.notified_at IS NULL AND r.next_attempt_at <= ? AND r.expires_at > ?
		  AND (ic.is_revoked OR i.id IS NULL OR i.status <> ?)
		ORDER BY r.next_attempt_at
		LIMIT 100`, now, now, string(domain.IdentityStatusActive)).Scan(ctx, &due)
	if err != nil {
		return 0, fmt.Errorf("reading pending person-server revocations: %w", err)
	}
	done := 0
	for _, r := range due {
		if ctx.Err() != nil {
			return done, ctx.Err()
		}
		outcome, err := p.revokeAtPersonServer(ctx, r)
		var retry *errPSRetry
		if errors.As(err, &retry) {
			wait := psBackoff(r.Attempts)
			if retry.retryAfter > wait {
				wait = retry.retryAfter
			}
			log.Info().Err(err).Str("jti", r.JTI).Str("person_server", r.PersonServer).Dur("retry_in", wait).
				Msg("aauth: person-server revocation not yet delivered")
			_, uErr := p.db.NewRaw(`UPDATE aauth_ps_revocations
				SET attempts = attempts + 1, next_attempt_at = ?, last_error = ? WHERE jti = ?`,
				now.Add(wait), truncate(err.Error(), 500), r.JTI).Exec(ctx)
			if uErr != nil {
				return done, fmt.Errorf("recording a failed person-server revocation: %w", uErr)
			}
			continue
		}
		lastErr := ""
		if err != nil {
			lastErr = truncate(err.Error(), 500)
			log.Warn().Err(err).Str("jti", r.JTI).Str("person_server", r.PersonServer).Str("outcome", outcome).
				Msg("aauth: person server did not take the revocation")
		}
		if _, uErr := p.db.NewRaw(`UPDATE aauth_ps_revocations
			SET notified_at = ?, outcome = ?, attempts = attempts + 1, last_error = NULLIF(?, '') WHERE jti = ?`,
			now, outcome, lastErr, r.JTI).Exec(ctx); uErr != nil {
			return done, fmt.Errorf("recording a person-server revocation: %w", uErr)
		}
		done++
	}
	return done, nil
}

// psBackoff is the wait after the attempts-th failure: 10 s doubling to at
// most 10 minutes.
func psBackoff(attempts int) time.Duration {
	d := 10 * time.Second
	for i := 0; i < attempts && d < 10*time.Minute; i++ {
		d *= 2
	}
	return min(d, 10*time.Minute)
}

// revokeAtPersonServer discovers the person server's revocation_endpoint
// and posts the revocation, signed as this Agent Provider. It returns a
// terminal outcome, or an *errPSRetry.
func (p *Provider) revokeAtPersonServer(ctx context.Context, r pendingPSRevocation) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, maxPSPollWait+15*time.Second)
	defer cancel()
	endpoint, err := p.psRevocationEndpoint(ctx, r.PersonServer)
	if err != nil {
		return "", err
	}
	if endpoint == "" {
		return psOutcomeUnsupported, errors.New("the person server publishes no revocation_endpoint")
	}
	body, _ := json.Marshal(map[string]any{"jti": r.JTI, "exp": r.ExpiresAt.Unix()})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return psOutcomeRejected, err
	}
	req.Header.Set("Content-Type", "application/json")
	if err := p.key.signAsServer(req, body, p.cfg.Issuer, p.now()); err != nil {
		return "", &errPSRetry{err: err}
	}
	res, err := p.psClient.Do(req)
	if err != nil {
		return "", &errPSRetry{err: fmt.Errorf("revocation request: %w", err)}
	}
	deadline := time.Now().Add(maxPSPollWait)
	for res.StatusCode == http.StatusAccepted {
		// Deferred: poll the pending URL with signed GETs under the same
		// identity until the cascade has a terminal outcome.
		loc, wait := res.Header.Get("Location"), retryAfter(res)
		drain(res)
		pending, err := url.Parse(endpoint)
		if err == nil {
			pending, err = pending.Parse(loc)
		}
		if err != nil || loc == "" || pending.Scheme != "https" {
			return "", &errPSRetry{err: fmt.Errorf("a 202 without a usable https Location %q", loc)}
		}
		if wait <= 0 {
			wait = time.Second
		}
		if time.Now().Add(wait).After(deadline) {
			return "", &errPSRetry{err: errors.New("the person server is still revoking; sent again later"), retryAfter: wait}
		}
		select {
		case <-ctx.Done():
			return "", &errPSRetry{err: ctx.Err()}
		case <-time.After(wait):
		}
		poll, _ := http.NewRequestWithContext(ctx, http.MethodGet, pending.String(), nil)
		if err := p.key.signAsServer(poll, nil, p.cfg.Issuer, p.now()); err != nil {
			return "", &errPSRetry{err: err}
		}
		if res, err = p.psClient.Do(poll); err != nil {
			return "", &errPSRetry{err: fmt.Errorf("polling the revocation: %w", err)}
		}
	}
	defer drain(res)
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	var problem struct {
		Error  string `json:"error"`
		Detail string `json:"detail"`
	}
	_ = json.Unmarshal(raw, &problem)
	switch {
	case res.StatusCode == http.StatusOK:
		return psOutcomeRevoked, nil
	case res.StatusCode == http.StatusForbidden && problem.Error == "unsupported_iss":
		return psOutcomeUnsupported, fmt.Errorf("the person server does not take revocations from this Agent Provider: %s", problem.Detail)
	case res.StatusCode == http.StatusTooManyRequests || res.StatusCode == http.StatusUnauthorized || res.StatusCode >= 500:
		// 401: the person server may hold a stale copy of our keys.
		return "", &errPSRetry{err: fmt.Errorf("status %d %s: %s", res.StatusCode, problem.Error, problem.Detail), retryAfter: retryAfter(res)}
	default:
		return psOutcomeRejected, fmt.Errorf("status %d %s: %s", res.StatusCode, problem.Error, problem.Detail)
	}
}

// psRevocationEndpoint reads the person server's metadata document and
// returns its revocation_endpoint ("" when it publishes none). The document's
// issuer must equal the person server's identifier byte for byte.
func (p *Provider) psRevocationEndpoint(ctx context.Context, ps string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ps+"/.well-known/"+PersonServerMetadataDWK, nil)
	if err != nil {
		return "", err
	}
	res, err := p.psClient.Do(req)
	if err != nil {
		return "", &errPSRetry{err: fmt.Errorf("person server metadata: %w", err)}
	}
	defer drain(res)
	if res.StatusCode != http.StatusOK {
		return "", &errPSRetry{err: fmt.Errorf("person server metadata: status %d", res.StatusCode)}
	}
	var md struct {
		Issuer             string `json:"issuer"`
		RevocationEndpoint string `json:"revocation_endpoint"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&md); err != nil {
		return "", &errPSRetry{err: fmt.Errorf("person server metadata: %w", err)}
	}
	switch {
	case md.Issuer == "":
		return "", &errPSRetry{err: errors.New("person server metadata: issuer_missing")}
	case md.Issuer != ps:
		return "", &errPSRetry{err: fmt.Errorf("person server metadata: issuer_mismatch (%q)", md.Issuer)}
	case md.RevocationEndpoint == "":
		return "", nil
	}
	u, err := url.Parse(md.RevocationEndpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", &errPSRetry{err: fmt.Errorf("person server revocation_endpoint %q is not an https URL", md.RevocationEndpoint)}
	}
	return md.RevocationEndpoint, nil
}

func retryAfter(res *http.Response) time.Duration {
	if s, err := strconv.Atoi(res.Header.Get("Retry-After")); err == nil && s > 0 {
		return min(time.Duration(s)*time.Second, 10*time.Minute)
	}
	return 0
}

func drain(res *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 64<<10))
	_ = res.Body.Close()
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
