package aauth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/highflame-ai/zeroid/domain"
	"github.com/highflame-ai/zeroid/internal/service"
)

// PathSubagent is where a parent agent asks for a sub-agent token.
const PathSubagent = "/ap/subagent"

// DefaultMaxLiveSubagents bounds one parent agent token's unexpired,
// unrevoked sub-agent tokens when none is configured.
const DefaultMaxLiveSubagents = 16

// maxSubagentBody bounds the /ap/subagent body: one public JWK and a short
// discriminator.
const maxSubagentBody = 8 << 10

// discriminatorPattern is a sub-agent discriminator: the agent identifier's
// local-part characters without '+', which delimits it (protocol draft,
// "Agent Identifiers"), and short enough that parent and discriminator stay
// well inside the 255-character local part.
var discriminatorPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// subagentRequest is the /ap/subagent body: the sub-agent's public key, and
// optionally the discriminator its identifier ends in. aauth-go's
// agentprovider client sends these members.
type subagentRequest struct {
	JWK           *JWK   `json:"jwk"`
	Discriminator string `json:"discriminator,omitempty"`
}

// handleSubagent is POST /ap/subagent (protocol draft, "Sub-Agents";
// bootstrap draft, sub-agents under a hosted Agent Provider). The parent
// signs the request under the jwt scheme with its own agent token from this
// Agent Provider. The sub-agent token has the parent's iss and ps, sub the
// parent's local part plus "+" and a discriminator, parent_agent naming the
// parent, cnf the sub-agent's own key, and an exp no later than the
// parent's. It is the parent's child (parent_jti), so revoking the parent
// revokes it. A sub-agent cannot have sub-agents.
func (p *Provider) handleSubagent(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxSubagentBody+1))
	if err != nil || len(body) > maxSubagentBody {
		writeError(w, http.StatusBadRequest, "invalid_request", "the request body is unreadable or too large")
		return
	}
	authority := requestAuthority(r)
	if authority != p.authority {
		WriteSigError(w, sigErr(ErrCodeInvalidSignature, "this Agent Provider is %s", p.authority))
		return
	}

	now := p.now()
	var parent *agentClaims
	_, err = VerifyRequest(r, body, VerifyOptions{
		Now:                 now,
		Authority:           authority,
		RequireBodyCoverage: true,
		Schemes:             []string{"jwt"},
		ResolveKey: func(_ string, params map[string]any) (JWK, error) {
			raw, _ := params["jwt"].(string)
			if raw == "" {
				return JWK{}, sigErr(ErrCodeInvalidJWT, "the jwt scheme needs a jwt parameter")
			}
			claims, err := p.key.verify(raw, p.cfg.Issuer, now)
			if errors.Is(err, errAgentTokenExpired) {
				return JWK{}, sigErr(ErrCodeExpiredJWT, "the parent's agent token has expired")
			}
			if err != nil {
				return JWK{}, sigErr(ErrCodeInvalidJWT, "not an agent token from this Agent Provider: %v", err)
			}
			parent = claims
			return claims.Cnf, nil
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

	token, ttl, err := p.subagent(r.Context(), parent, body, now)
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
		log.Error().Err(err).Msg("aauth: sub-agent issuance failed")
		writeError(w, http.StatusInternalServerError, "server_error", "sub-agent token issuance failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"agent_token": token, "expires_in": ttl})
}

// subagent issues a sub-agent token to the verified parent.
func (p *Provider) subagent(ctx context.Context, parent *agentClaims, body []byte, now time.Time) (string, int, error) {
	// The protocol's single level: an Agent Provider MUST NOT issue a
	// sub-agent token whose parent is itself a sub-agent. parent_agent is the
	// authoritative marker, not the row's lineage (a refreshed agent token
	// also has a parent row).
	if parent.ParentAgent != "" {
		return "", 0, &bootstrapRefusal{code: "denied", description: "a sub-agent may not have sub-agents"}
	}
	if ok, wait := p.limits.allow("subagent:" + parent.Subject); !ok {
		return "", 0, rateLimited(wait)
	}
	// The row, not only the signature: a revoked or unknown parent is
	// refused, fail closed on a storage error.
	row, err := p.creds.CredentialByJTI(ctx, parent.JTI)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "", 0, sigErr(ErrCodeRevokedJWT, "the parent's agent token is revoked or unknown")
	case err != nil:
		return "", 0, fmt.Errorf("reading the parent's agent token: %w", err)
	case row.IsRevoked:
		return "", 0, sigErr(ErrCodeRevokedJWT, "the parent's agent token is revoked")
	case row.GrantType != domain.GrantTypeAAuthAgent || row.IdentityID == nil:
		return "", 0, sigErr(ErrCodeInvalidJWT, "the parent's token is not an agent token")
	}

	var req subagentRequest
	if err := json.Unmarshal(body, &req); err != nil || req.JWK == nil {
		return "", 0, &bootstrapRefusal{code: "invalid_request", status: http.StatusBadRequest,
			description: `the body must be {"jwk": <the sub-agent's public key>, "discriminator": <optional>}`}
	}
	child := *req.JWK
	if _, err := child.PublicKey(); err != nil || !isSupportedAlg(child.Alg) {
		return "", 0, &bootstrapRefusal{code: "invalid_request", status: http.StatusBadRequest,
			description: "jwk must be an Ed25519 or ES256 public key with its alg"}
	}
	childJKT, err := child.Thumbprint()
	if err != nil {
		return "", 0, &bootstrapRefusal{code: "invalid_request", status: http.StatusBadRequest, description: "jwk has no thumbprint"}
	}
	if parentJKT, err := parent.Cnf.Thumbprint(); err != nil || parentJKT == childJKT {
		return "", 0, &bootstrapRefusal{code: "invalid_request", status: http.StatusBadRequest,
			description: "a sub-agent holds its own key, never its parent's"}
	}
	disc := req.Discriminator
	if disc == "" {
		b := make([]byte, 6)
		if _, err := rand.Read(b); err != nil {
			return "", 0, err
		}
		disc = base64.RawURLEncoding.EncodeToString(b)
	}
	if !discriminatorPattern.MatchString(disc) {
		return "", 0, &bootstrapRefusal{code: "invalid_request", status: http.StatusBadRequest,
			description: "discriminator must be 1 to 64 letters, digits, '.', '_' or '-'"}
	}
	local, domainPart, ok := strings.Cut(strings.TrimPrefix(parent.Subject, "aauth:"), "@")
	if !ok || domainPart != p.authority || strings.Contains(local, "+") {
		return "", 0, sigErr(ErrCodeInvalidJWT, "the parent's agent identifier is not this Agent Provider's")
	}
	sub := "aauth:" + local + "+" + disc + "@" + p.authority

	// ponytail: best effort. Count then issue, so a burst of concurrent
	// requests can pass the cap by its concurrency (the per-parent rate limit
	// bounds that); an advisory lock on the parent jti, held in issuance's
	// transaction, if the bound must be exact.
	live, err := p.liveSubagents(ctx, parent.JTI, now)
	if err != nil {
		return "", 0, err
	}
	if live >= p.cfg.MaxLiveSubagents {
		return "", 0, &bootstrapRefusal{code: "denied",
			description: fmt.Sprintf("this agent already has %d live sub-agents, the most it may have", live)}
	}

	identity, err := p.identities.GetIdentity(ctx, *row.IdentityID, row.AccountID, row.ProjectID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, &bootstrapRefusal{code: "denied", description: "the parent's identity no longer exists"}
	}
	if err != nil {
		return "", 0, fmt.Errorf("loading the parent's identity: %w", err)
	}
	policy, err := p.oauth.ResolveWorkloadPolicy(ctx, identity)
	if err != nil {
		return "", 0, err
	}
	ttl := int(p.cfg.AgentTokenTTL / time.Second)
	if policy != nil && policy.MaxTTLSeconds > 0 && policy.MaxTTLSeconds < ttl {
		ttl = policy.MaxTTLSeconds
	}
	// Never past the parent's exp. A parent refreshes its own token when
	// fewer than five minutes remain, so a parent this close to its exp is
	// told to refresh first rather than given a token due for refresh at once.
	if left := int(parent.ExpiresAt.Sub(now) / time.Second); left < ttl {
		ttl = left
	}
	if ttl <= minAgentTokenTTL {
		return "", 0, &bootstrapRefusal{code: "denied",
			description: fmt.Sprintf("a sub-agent token would last %ds; refresh the parent's agent token first", ttl)}
	}
	parentExp := parent.ExpiresAt

	ictx, icancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer icancel()
	issued, issuedRow, err := p.creds.IssueCredential(ictx, service.IssueRequest{
		Identity:            identity,
		IdentityPolicyID:    policyID(policy),
		TTL:                 ttl,
		GrantType:           domain.GrantTypeAAuthSubagent,
		ParentJTI:           parent.JTI, // revoking the parent revokes this token
		MissionID:           row.MissionID,
		CredentialExpiresAt: &parentExp,
		DPoPKeyThumbprint:   childJKT,
		AgentTokenSigner: func(jti string, iat, exp time.Time) (string, error) {
			return p.key.sign(p.cfg.Issuer, sub, child, jti, iat, exp,
				tokenExtras{PS: parent.PS, ParentAgent: parent.Subject}) // ps copied from the parent
		},
	})
	if err != nil {
		if errors.Is(err, service.ErrPolicyViolation) || errors.Is(err, service.ErrScopesNotAllowed) ||
			errors.Is(err, domain.ErrIdentityNotUsable) || errors.Is(err, domain.ErrIdentityExpired) ||
			errors.Is(err, domain.ErrCredentialExpired) {
			return "", 0, &bootstrapRefusal{code: "denied", description: err.Error(), cause: err}
		}
		return "", 0, fmt.Errorf("issuing the sub-agent token: %w", err)
	}

	// The parent may have been revoked after the check above and before the
	// child row was written, which the revoke's cascade then missed. Re-check
	// and revoke the child unless the parent is confirmed live, fail closed.
	bctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	again, err := p.creds.CredentialByJTI(bctx, parent.JTI)
	if err != nil || again.IsRevoked {
		if rErr := p.creds.RevokeCredential(bctx, issuedRow.ID, issuedRow.AccountID, issuedRow.ProjectID,
			"parent agent token not confirmed live after sub-agent issuance"); rErr != nil {
			log.Error().Err(rErr).Str("jti", issuedRow.JTI).Msg("aauth: could not revoke a sub-agent token whose parent was not confirmed live")
		}
		if err != nil {
			return "", 0, fmt.Errorf("re-checking the parent's agent token: %w", err)
		}
		return "", 0, sigErr(ErrCodeRevokedJWT, "the parent's agent token was revoked during issuance")
	}
	if err := p.trackForPersonServer(bctx, issuedRow, parent.PS); err != nil {
		return "", 0, err
	}
	return issued.AccessToken, issued.ExpiresIn, nil
}

// liveSubagents counts parentJTI's unexpired, unrevoked sub-agent tokens.
func (p *Provider) liveSubagents(ctx context.Context, parentJTI string, now time.Time) (int, error) {
	n, err := p.db.NewSelect().Table("issued_credentials").
		Where("parent_jti = ?", parentJTI).
		Where("grant_type = ?", string(domain.GrantTypeAAuthSubagent)).
		Where("is_revoked = false").
		Where("expires_at > ?", now).
		Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("counting live sub-agents: %w", err)
	}
	return n, nil
}

func isSupportedAlg(alg string) bool {
	for _, a := range SupportedAlgs {
		if a == alg {
			return true
		}
	}
	return false
}
