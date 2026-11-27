package aauth

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/rs/zerolog/log"
	"github.com/uptrace/bun"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/service"
	"github.com/highflame-ai/zeroid/pkg/dpop"
)

// The two-key refresh (bootstrap draft, Refresh Patterns): an agent key that
// enrolled at /ap/token with a platform token is the durable key. To refresh,
// it signs a naming JWT delegating to a fresh ephemeral key, which signs the
// request under the jkt-jwt Signature-Key scheme; the new agent token binds
// the ephemeral key. No platform token is presented, so everything it proved
// is re-checked from the enrollment: the issuer row and binding still map the
// subject to the same identity, no agent token of the enrollment has been
// revoked, and the enrollment is younger than aauth.enrollment_ttl_seconds.
// A policy opts in by listing aauth_refresh. A workload can always enroll
// again with a fresh platform token instead.

// PathRefresh is the two-key refresh endpoint.
const PathRefresh = "/ap/refresh"

// DefaultEnrollmentTTL is how long an enrollment may refresh before its key
// must enroll again with a platform token, when none is configured.
const DefaultEnrollmentTTL = 8 * time.Hour

// namingJWTType is the typ of a jkt-jwt naming JWT whose thumbprint is
// SHA-256; its iss is jktURNPrefix and the thumbprint.
const (
	namingJWTType = "jkt-s256+jwt"
	jktURNPrefix  = "urn:jkt:sha-256:"
)

// maxNamingJWTLifetime is the furthest ahead a naming JWT may expire: replay
// state is kept until it does.
const maxNamingJWTLifetime = 10 * time.Minute

// delegation is a verified naming JWT: the durable key and the ephemeral key
// it delegated to.
type delegation struct {
	durable, ephemeral JWK
	durableJKT         string
	jti                string
	exp                time.Time
}

// verifyNamingJWT checks a jkt-jwt naming JWT (signature-key draft, jkt-jwt
// scheme): typ, the header jwk and its alg, iss equal to the jwk's thumbprint
// URI, the signature under that key, iat and exp (bounded), a jti, and the
// ephemeral key in cnf.jwk.
func verifyNamingJWT(raw string, now time.Time) (*delegation, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errors.New("not a compact JWS")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("unreadable header")
	}
	var hdr struct {
		Typ string `json:"typ"`
		Alg string `json:"alg"`
		JWK *JWK   `json:"jwk"`
	}
	if err := json.Unmarshal(hb, &hdr); err != nil || hdr.JWK == nil {
		return nil, errors.New("the header needs typ, alg and jwk")
	}
	if hdr.Typ != namingJWTType {
		return nil, fmt.Errorf("typ is %q, not %s", hdr.Typ, namingJWTType)
	}
	durable := *hdr.JWK
	if hdr.Alg != durable.Alg || !isSupportedAlg(hdr.Alg) {
		return nil, fmt.Errorf("alg %q must be the jwk's, and Ed25519 or ES256", hdr.Alg)
	}
	pub, err := durable.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("header jwk: %w", err)
	}
	alg := jwa.EdDSAEd25519()
	if hdr.Alg == AlgES256 {
		alg = jwa.ES256()
	}
	payload, err := jws.Verify([]byte(raw), jws.WithKey(alg, pub))
	if err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}
	var claims struct {
		Iss string `json:"iss"`
		Iat *int64 `json:"iat"`
		Exp *int64 `json:"exp"`
		JTI string `json:"jti"`
		Cnf struct {
			JWK *JWK `json:"jwk"`
		} `json:"cnf"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, errors.New("unreadable claims")
	}
	durableJKT, err := durable.Thumbprint()
	if err != nil {
		return nil, err
	}
	switch {
	case claims.Iss != jktURNPrefix+durableJKT:
		return nil, errors.New("iss is not the header jwk's thumbprint URI")
	case claims.Iat == nil || claims.Exp == nil:
		return nil, errors.New("iat and exp are required")
	case claims.JTI == "" || len(claims.JTI) > 255:
		return nil, errors.New("a jti of at most 255 characters is required")
	case claims.Cnf.JWK == nil:
		return nil, errors.New("cnf.jwk is required")
	}
	exp, iat := time.Unix(*claims.Exp, 0), time.Unix(*claims.Iat, 0)
	switch {
	case !now.Before(exp):
		return nil, errAgentTokenExpired
	case exp.Sub(now) > maxNamingJWTLifetime+DefaultSignatureWindow:
		return nil, fmt.Errorf("exp is more than %v ahead", maxNamingJWTLifetime)
	case iat.Sub(now) > DefaultSignatureWindow:
		return nil, errors.New("iat is ahead of this server's clock")
	}
	ephemeral := *claims.Cnf.JWK
	if _, err := ephemeral.PublicKey(); err != nil || !isSupportedAlg(ephemeral.Alg) {
		return nil, errors.New("cnf.jwk must be an Ed25519 or ES256 public key with its alg")
	}
	if ej, err := ephemeral.Thumbprint(); err != nil || ej == durableJKT {
		return nil, errors.New("the ephemeral key must differ from the durable key")
	}
	return &delegation{durable: durable, ephemeral: ephemeral, durableJKT: durableJKT, jti: claims.JTI, exp: exp}, nil
}

// handleRefresh is POST /ap/refresh.
func (p *Provider) handleRefresh(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBootstrapBody+1))
	if err != nil || len(body) > maxBootstrapBody {
		writeError(w, http.StatusBadRequest, "invalid_request", "the request body is unreadable or too large")
		return
	}
	authority := requestAuthority(r)
	if authority != p.authority {
		WriteSigError(w, sigErr(ErrCodeInvalidSignature, "this Agent Provider is %s", p.authority))
		return
	}
	now := p.now()
	var d *delegation
	_, err = VerifyRequest(r, body, VerifyOptions{
		Now:                 now,
		Authority:           authority,
		RequireBodyCoverage: true,
		Schemes:             []string{"jkt-jwt"},
		ResolveKey: func(_ string, params map[string]any) (JWK, error) {
			raw, _ := params["jwt"].(string)
			if raw == "" {
				return JWK{}, sigErr(ErrCodeInvalidJWT, "the jkt-jwt scheme needs a jwt parameter")
			}
			got, err := verifyNamingJWT(raw, now)
			if errors.Is(err, errAgentTokenExpired) {
				return JWK{}, sigErr(ErrCodeExpiredJWT, "the naming JWT has expired")
			}
			if err != nil {
				return JWK{}, sigErr(ErrCodeInvalidJWT, "naming JWT: %v", err)
			}
			d = got
			return got.ephemeral, nil
		},
	})
	if err != nil {
		var se *SigError
		if !errors.As(err, &se) {
			se = sigErr(ErrCodeInvalidSignature, "%v", err)
		}
		WriteSigError(w, se)
		return
	}

	token, ttl, err := p.refresh(r.Context(), d, now)
	if err != nil {
		var se *SigError
		if errors.As(err, &se) {
			WriteSigError(w, se)
			return
		}
		var refusal *bootstrapRefusal
		if errors.As(err, &refusal) {
			status := http.StatusForbidden
			if refusal.status != 0 {
				status = refusal.status
			}
			if refusal.retryAfter > 0 {
				w.Header().Set("Retry-After", fmt.Sprint(refusal.retryAfter))
			}
			writeError(w, status, refusal.code, refusal.description)
			return
		}
		log.Error().Err(err).Msg("aauth: refresh failed")
		writeError(w, http.StatusInternalServerError, "server_error", "agent token refresh failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"agent_token": token, "expires_in": ttl})
}

// enrollment is an aauth_enrollments row.
type enrollment struct {
	DurableJKT string    `bun:"durable_jkt"`
	IdentityID string    `bun:"identity_id"`
	AccountID  string    `bun:"account_id"`
	ProjectID  string    `bun:"project_id"`
	IssuerID   string    `bun:"issuer_id"`
	Subject    string    `bun:"subject"`
	RootJTI    string    `bun:"root_jti"`
	ExpiresAt  time.Time `bun:"expires_at"`
}

// notEnrolled is the one answer for every reason an enrollment cannot
// refresh: a durable key is pseudonymous, and a distinct answer would say
// which keys are enrolled. The reason goes to the log.
func notEnrolled(reason string) error {
	log.Info().Str("reason", reason).Msg("aauth: refresh refused")
	return &bootstrapRefusal{code: "denied", description: "this key cannot refresh; enroll again with a platform token"}
}

// refresh issues an agent token for d's ephemeral key on its durable key's
// enrollment.
func (p *Provider) refresh(ctx context.Context, d *delegation, now time.Time) (string, int, error) {
	if ok, wait := p.limits.allow("refresh:" + d.durableJKT); !ok {
		return "", 0, rateLimited(wait)
	}
	var e enrollment
	err := p.db.NewRaw(`SELECT durable_jkt, identity_id, account_id, project_id, issuer_id, subject, root_jti, expires_at
		FROM aauth_enrollments WHERE durable_jkt = ?`, d.durableJKT).Scan(ctx, &e)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "", 0, notEnrolled("the durable key is not enrolled")
	case err != nil:
		return "", 0, fmt.Errorf("reading the enrollment: %w", err)
	case !now.Before(e.ExpiresAt):
		return "", 0, notEnrolled("the enrollment has expired")
	}
	root, err := p.rootLive(ctx, e.RootJTI)
	if err != nil {
		return "", 0, err
	}

	// Everything the platform token proved, except the token: the issuer row
	// is enabled, and an enabled binding maps the subject to the same active
	// identity (no first contact: a refresh registers nothing).
	var row domain.ExternalIssuer
	err = p.db.NewSelect().Model(&row).Where("id = ? AND account_id = ?", e.IssuerID, e.AccountID).Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, notEnrolled("the enrollment's issuer row is gone")
	}
	if err != nil {
		return "", 0, fmt.Errorf("reading the enrollment's issuer row: %w", err)
	}
	identity, err := p.oauth.ResolveBoundWorkloadAgent(ctx, &row, e.Subject, string(domain.GrantTypeAAuthRefresh))
	if err != nil {
		if failure := refusalOrFailure(err); !isRefusal(failure) {
			return "", 0, failure
		}
		return "", 0, notEnrolled("the binding no longer maps the subject: " + err.Error())
	}
	if identity.ID != e.IdentityID {
		return "", 0, notEnrolled("the binding now maps the subject to another identity")
	}
	policy, err := p.oauth.ResolveWorkloadPolicy(ctx, identity)
	if err != nil {
		return "", 0, err
	}
	if policy == nil || !slices.Contains(policy.AllowedGrantTypes, string(domain.GrantTypeAAuthRefresh)) {
		return "", 0, notEnrolled("the identity's policy does not list aauth_refresh")
	}

	// Single use, spent once the request is authorized (a key that is not
	// enrolled cannot fill the store), before anything is issued.
	if err := p.oauth.SpendSingleUse(ctx, "aauth-refresh\x00"+d.durableJKT+"\x00"+d.jti, d.exp); err != nil {
		if errors.Is(err, dpop.ErrReplay) {
			return "", 0, sigErr(ErrCodeInvalidJWT, "the naming JWT has already been used")
		}
		return "", 0, fmt.Errorf("spending the naming JWT: %w", err)
	}

	ttl := int(p.cfg.AgentTokenTTL / time.Second)
	if policy.MaxTTLSeconds > 0 && policy.MaxTTLSeconds < ttl {
		ttl = policy.MaxTTLSeconds
	}
	if ttl <= minAgentTokenTTL {
		return "", 0, &bootstrapRefusal{code: "denied",
			description: fmt.Sprintf("the identity's credential policy allows tokens of at most %ds; an agent token needs over %ds", ttl, minAgentTokenTTL)}
	}
	ephemeralJKT, err := d.ephemeral.Thumbprint()
	if err != nil {
		return "", 0, err
	}
	sub := "aauth:" + identity.ID + "@" + p.authority
	ps := policy.AAuthPersonServer
	ictx, icancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer icancel()
	issued, issuedRow, err := p.creds.IssueCredential(ictx, service.IssueRequest{
		Identity:          identity,
		IdentityPolicyID:  policy.ID,
		TTL:               ttl,
		GrantType:         domain.GrantTypeAAuthAgent,
		ParentJTI:         e.RootJTI,      // revoking the first token while it lives revokes every refresh
		MissionID:         root.MissionID, // every refresh stays in the enrollment's delegation tree
		DPoPKeyThumbprint: ephemeralJKT,
		AgentTokenSigner: func(jti string, iat, exp time.Time) (string, error) {
			return p.key.sign(p.cfg.Issuer, sub, d.ephemeral, jti, iat, exp, tokenExtras{PS: ps})
		},
	})
	if err != nil {
		if errors.Is(err, service.ErrPolicyViolation) || errors.Is(err, service.ErrScopesNotAllowed) ||
			errors.Is(err, domain.ErrIdentityNotUsable) || errors.Is(err, domain.ErrIdentityExpired) ||
			errors.Is(err, domain.ErrCredentialExpired) {
			return "", 0, &bootstrapRefusal{code: "denied", description: err.Error(), cause: err}
		}
		return "", 0, fmt.Errorf("issuing the refreshed agent token: %w", err)
	}

	// The root may have been revoked after the check above and before this
	// row was written, which the revoke's cascade then missed: re-check, and
	// revoke the new token unless the root is confirmed live, fail closed.
	bctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if _, err := p.rootLive(bctx, e.RootJTI); err != nil {
		if rErr := p.creds.RevokeCredential(bctx, issuedRow.ID, issuedRow.AccountID, issuedRow.ProjectID,
			"enrollment not confirmed live after refresh"); rErr != nil {
			log.Error().Err(rErr).Str("jti", issuedRow.JTI).Msg("aauth: could not revoke a refreshed token whose enrollment was not confirmed live")
		}
		return "", 0, err
	}
	if err := p.trackForPersonServer(bctx, issuedRow, ps); err != nil {
		return "", 0, err
	}
	return issued.AccessToken, issued.ExpiresIn, nil
}

// rootLive refuses an enrollment once its first agent token, or any agent
// token refreshed from it, has been revoked, and fails closed on a storage
// error. Any of them, not only the first: a revoke skips an expired token,
// so the first token (which lives minutes) cannot be revoked for most of the
// enrollment's life, but the agent's current token can. Revoking it cuts off
// the durable key; the workload enrolls again with a platform token.
func (p *Provider) rootLive(ctx context.Context, rootJTI string) (*domain.IssuedCredential, error) {
	root, err := p.creds.CredentialByJTI(ctx, rootJTI)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, notEnrolled("the enrollment's first agent token is gone")
	} else if err != nil {
		return nil, fmt.Errorf("reading the enrollment's first agent token: %w", err)
	}
	revoked, err := p.db.NewSelect().Table("issued_credentials").
		Where("is_revoked").
		WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
			return q.Where("jti = ?", rootJTI).
				WhereOr("parent_jti = ? AND grant_type = ?", rootJTI, string(domain.GrantTypeAAuthAgent))
		}).
		Exists(ctx)
	if err != nil {
		return nil, fmt.Errorf("checking the enrollment's agent tokens: %w", err)
	}
	if revoked {
		return nil, notEnrolled("an agent token of this enrollment was revoked")
	}
	return root, nil
}

// enroll records key's enrollment after a platform-token issuance, when the
// identity's policy lists aauth_refresh. The latest enrollment of a key
// wins: a fresh platform token is the authoritative statement of whose key
// it is. A failure leaves the token valid; the key just cannot refresh.
func (p *Provider) enroll(ctx context.Context, jkt string, wa *service.WorkloadAssertion, identity *domain.Identity,
	policy *domain.CredentialPolicy, root *domain.IssuedCredential) {
	if policy == nil || root == nil || !slices.Contains(policy.AllowedGrantTypes, string(domain.GrantTypeAAuthRefresh)) {
		return
	}
	now := p.now()
	_, err := p.db.NewRaw(`INSERT INTO aauth_enrollments
		(durable_jkt, identity_id, account_id, project_id, issuer_id, subject, root_jti, enrolled_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (durable_jkt) DO UPDATE SET identity_id = EXCLUDED.identity_id, account_id = EXCLUDED.account_id,
			project_id = EXCLUDED.project_id, issuer_id = EXCLUDED.issuer_id, subject = EXCLUDED.subject,
			root_jti = EXCLUDED.root_jti, enrolled_at = EXCLUDED.enrolled_at, expires_at = EXCLUDED.expires_at`,
		jkt, identity.ID, identity.AccountID, identity.ProjectID, wa.Entry.Row.ID, wa.Subject, root.JTI,
		now, now.Add(p.cfg.EnrollmentTTL)).Exec(ctx)
	if err != nil {
		log.Warn().Err(err).Str("identity_id", identity.ID).Msg("aauth: could not record the enrollment; this key cannot refresh")
	}
}
