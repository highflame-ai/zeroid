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
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/uptrace/bun"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/attestation"
	"github.com/highflame-ai/zeroid/internal/telemetry"
)

// Revoking agent tokens at the agent's person server (protocol draft, "Token
// Revocation"). An agent token is revoked by the Agent Provider that issued
// it, at the person server only: the token's ps. ZeroID records every agent
// and sub-agent token it issues with a ps claim in aauth_ps_revocations, and
// a worker sends the revocation once ZeroID treats the token as inactive:
// its credential revoked (an admin revoke, a cascade, deactivation,
// suspension, offboarding), its identity no longer active, or an identity
// above it in the registration tree stopped (re-checked through
// IntrospectToken, the same test introspection applies). It retries until the
// person server records the revocation, says it takes none, or the token
// expires.

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
		internalRevocation+"could not record the agent token for revocation at its person server"); rErr != nil {
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

// psLease is how long a pass holds the rows it claimed: another replica
// takes them only after it lapses (a crashed pass), so replicas do not send
// the same revocation at once.
const psLease = 5 * time.Minute

// psConcurrency bounds the person servers one pass talks to at once. Rows of
// one person server are sent in turn.
const psConcurrency = 8

// psPassBudget and psServerBudget bound one pass and one person server's
// share of it, both well inside psLease: a slow or dead person server holds
// up the others' next pass by at most psPassBudget, and no row is still being
// sent when its lease lapses. Rows not reached in time are released for the
// next pass.
const (
	psPassBudget   = 3 * time.Minute
	psServerBudget = time.Minute
)

// psCheckInterval is how often a live tracked token's identity chain is
// re-checked, and psChecksPerPass how many one pass checks.
//
// ponytail: one introspection per live tracked token per minute; a
// tree-walk in SQL, or a hook on ancestor stops, if that gets heavy.
const (
	psCheckInterval = time.Minute
	psChecksPerPass = 500
)

// SendPersonServerRevocations runs one pass: it claims every tracked,
// unexpired token whose credential is revoked or whose identity is not
// active, and which is due, and revokes each at its person server. It
// returns how many reached a terminal outcome.
func (p *Provider) SendPersonServerRevocations(ctx context.Context) (int, error) {
	if err := p.markStoppedChains(ctx); err != nil {
		log.Warn().Err(err).Msg("aauth: could not re-check the identity chains of tracked agent tokens")
	}
	ctx, cancel := context.WithTimeout(ctx, psPassBudget)
	defer cancel()
	now := p.now()
	var due []pendingPSRevocation
	err := p.db.NewRaw(`UPDATE aauth_ps_revocations SET next_attempt_at = ?
		WHERE jti IN (
			SELECT r.jti FROM aauth_ps_revocations r
			JOIN issued_credentials ic ON ic.jti = r.jti
			LEFT JOIN identities i ON i.id = ic.identity_id
			WHERE r.notified_at IS NULL AND r.next_attempt_at <= ? AND r.expires_at > ?
			  AND (ic.is_revoked OR i.id IS NULL OR i.status <> ? OR r.chain_stopped)
			ORDER BY r.next_attempt_at
			LIMIT 100
			FOR UPDATE OF r SKIP LOCKED)
		RETURNING jti, person_server, expires_at, attempts`,
		now.Add(psLease), now, now, string(domain.IdentityStatusActive)).Scan(ctx, &due)
	if err != nil {
		return 0, fmt.Errorf("claiming pending person-server revocations: %w", err)
	}
	byPS := map[string][]pendingPSRevocation{}
	for _, r := range due {
		byPS[r.PersonServer] = append(byPS[r.PersonServer], r)
	}

	var (
		mu       sync.Mutex
		done     int
		firstErr error
		wg       sync.WaitGroup
		sem      = make(chan struct{}, psConcurrency)
	)
	for ps, rows := range byPS {
		wg.Add(1)
		sem <- struct{}{}
		go func(ps string, rows []pendingPSRevocation) {
			defer wg.Done()
			defer func() { <-sem }()
			n, err := p.sendToPersonServer(ctx, ps, rows)
			mu.Lock()
			defer mu.Unlock()
			done += n
			if err != nil && firstErr == nil {
				firstErr = err
			}
		}(ps, rows)
	}
	wg.Wait()
	return done, firstErr
}

// markStoppedChains finds live tracked tokens that ZeroID nonetheless
// treats as inactive (an identity above theirs in the registration tree
// stopped, which revokes nothing and leaves their own identity active), and
// marks them for revocation at their person server.
func (p *Provider) markStoppedChains(ctx context.Context) error {
	now := p.now()
	var jtis []string
	err := p.db.NewRaw(`SELECT r.jti FROM aauth_ps_revocations r
		JOIN issued_credentials ic ON ic.jti = r.jti
		WHERE r.notified_at IS NULL AND NOT r.chain_stopped AND NOT ic.is_revoked
		  AND r.expires_at > ? AND r.next_check_at <= ?
		ORDER BY r.next_check_at
		LIMIT ?`, now, now, psChecksPerPass).Scan(ctx, &jtis)
	if err != nil {
		return err
	}
	for _, jti := range jtis {
		_, active, err := p.creds.IntrospectToken(ctx, jti)
		if err != nil {
			continue // checked again next pass
		}
		q := `UPDATE aauth_ps_revocations SET next_check_at = ? WHERE jti = ?`
		args := []any{now.Add(psCheckInterval), jti}
		if !active {
			q = `UPDATE aauth_ps_revocations SET chain_stopped = TRUE WHERE jti = ?`
			args = []any{jti}
		}
		if _, err := p.db.NewRaw(q, args...).Exec(ctx); err != nil {
			return err
		}
	}
	return nil
}

// sendToPersonServer revokes rows, all for ps, discovering its
// revocation_endpoint once, within psServerBudget. Rows it does not reach are
// released for the next pass.
func (p *Provider) sendToPersonServer(ctx context.Context, ps string, rows []pendingPSRevocation) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, psServerBudget)
	defer cancel()
	// Outcomes are recorded even when the budget ran out mid-request.
	wctx := context.WithoutCancel(ctx)
	var endpoint string
	err := ctx.Err()
	if err == nil {
		dctx, dcancel := context.WithTimeout(ctx, 15*time.Second)
		endpoint, err = p.psRevocationEndpoint(dctx, ps)
		dcancel()
	}
	done := 0
	for i, r := range rows {
		if ctx.Err() != nil {
			return done, p.releasePS(wctx, rows[i:])
		}
		var outcome string
		var rErr error
		switch {
		case err != nil:
			outcome, rErr = classifyTransport(err)
		case endpoint == "":
			outcome, rErr = psOutcomeUnsupported, errors.New("the person server publishes no revocation_endpoint")
		default:
			outcome, rErr = p.revokeAtPersonServer(ctx, endpoint, r)
		}
		terminal, uErr := p.recordPSOutcome(wctx, r, outcome, rErr)
		if uErr != nil {
			return done, uErr
		}
		if terminal {
			done++
		}
	}
	return done, nil
}

// releasePS gives rows back for the next pass to claim at once.
func (p *Provider) releasePS(ctx context.Context, rows []pendingPSRevocation) error {
	jtis := make([]string, len(rows))
	for i, r := range rows {
		jtis[i] = r.JTI
	}
	_, err := p.db.NewRaw(`UPDATE aauth_ps_revocations SET next_attempt_at = ?
		WHERE jti IN (?) AND notified_at IS NULL`, p.now(), bun.List(jtis)).Exec(ctx)
	if err != nil {
		return fmt.Errorf("releasing person-server revocations not reached: %w", err)
	}
	return nil
}

// recordPSOutcome records one revocation attempt: a terminal outcome, or a
// retry after the backoff (or the person server's Retry-After, if longer).
// Each write applies only while the row is still pending.
func (p *Provider) recordPSOutcome(ctx context.Context, r pendingPSRevocation, outcome string, err error) (bool, error) {
	now := p.now()
	var retry *errPSRetry
	counted := outcome
	if errors.As(err, &retry) {
		counted = "retry"
	}
	telemetry.AAuthPSRevocations.Add(ctx, 1, metric.WithAttributes(attribute.String("outcome", counted)))
	if retry != nil {
		wait := psBackoff(r.Attempts)
		if retry.retryAfter > wait {
			wait = retry.retryAfter
		}
		log.Info().Err(err).Str("jti", r.JTI).Str("person_server", r.PersonServer).Dur("retry_in", wait).
			Msg("aauth: person-server revocation not yet delivered")
		if _, uErr := p.db.NewRaw(`UPDATE aauth_ps_revocations
			SET attempts = attempts + 1, next_attempt_at = ?, last_error = ?
			WHERE jti = ? AND notified_at IS NULL`,
			now.Add(wait), truncate(err.Error(), 500), r.JTI).Exec(ctx); uErr != nil {
			return false, fmt.Errorf("recording a failed person-server revocation: %w", uErr)
		}
		return false, nil
	}
	lastErr := ""
	if err != nil {
		lastErr = truncate(err.Error(), 500)
		log.Warn().Err(err).Str("jti", r.JTI).Str("person_server", r.PersonServer).Str("outcome", outcome).
			Msg("aauth: person server did not take the revocation")
	}
	if _, uErr := p.db.NewRaw(`UPDATE aauth_ps_revocations
		SET notified_at = ?, outcome = ?, attempts = attempts + 1, last_error = NULLIF(?, '')
		WHERE jti = ? AND notified_at IS NULL`,
		now, outcome, lastErr, r.JTI).Exec(ctx); uErr != nil {
		return false, fmt.Errorf("recording a person-server revocation: %w", uErr)
	}
	return true, nil
}

// classifyTransport makes a request that the SSRF guard refused terminal
// (no retry reaches a private address), and leaves anything else to retry.
func classifyTransport(err error) (string, error) {
	if errors.Is(err, attestation.ErrPrivateAttestationEndpoint) {
		return psOutcomeRejected, err
	}
	var retry *errPSRetry
	if errors.As(err, &retry) {
		return "", err
	}
	return "", &errPSRetry{err: err}
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

// revokeAtPersonServer posts the revocation to endpoint, signed as this
// Agent Provider. It returns a terminal outcome, or an *errPSRetry.
func (p *Provider) revokeAtPersonServer(ctx context.Context, endpoint string, r pendingPSRevocation) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, maxPSPollWait+15*time.Second)
	defer cancel()
	endpointURL, err := url.Parse(endpoint)
	if err != nil {
		return psOutcomeRejected, err
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
		return classifyTransport(fmt.Errorf("revocation request: %w", err))
	}
	deadline := time.Now().Add(maxPSPollWait)
	for res.StatusCode == http.StatusAccepted {
		// Deferred: poll the pending URL with signed GETs under the same
		// identity until the cascade has a terminal outcome.
		loc, wait := res.Header.Get("Location"), retryAfter(res)
		drain(res)
		// The pending URL is polled only on the endpoint's own origin: a
		// signed request goes nowhere else on a person server's say-so.
		pending, err := endpointURL.Parse(loc)
		if err != nil || loc == "" || pending.Scheme != "https" || pending.Host != endpointURL.Host {
			return "", &errPSRetry{err: fmt.Errorf("a 202 whose Location %q is not on the revocation endpoint's origin", loc)}
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
			return classifyTransport(fmt.Errorf("polling the revocation: %w", err))
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
	case res.StatusCode == http.StatusBadRequest:
		// invalid_request: the request itself is malformed; resending it
		// changes nothing.
		return psOutcomeRejected, fmt.Errorf("status %d %s: %s", res.StatusCode, problem.Error, problem.Detail)
	default:
		// Anything else may pass: 401 (a stale copy of our keys), 404 or 403
		// from a deploy or a proxy, 408, 429, 5xx. Retried until the token
		// expires, which bounds it.
		return "", &errPSRetry{err: fmt.Errorf("status %d %s: %s", res.StatusCode, problem.Error, problem.Detail), retryAfter: retryAfter(res)}
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
