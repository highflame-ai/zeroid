package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/uptrace/bun"
)

// IssuerKind says what an external issuer's tokens name (ADR 0042 D4).
type IssuerKind string

const (
	// IssuerKindPerson is an IdP whose ID-JAGs and ID tokens name people.
	IssuerKindPerson IssuerKind = "person"
	// IssuerKindWorkload is a client-assertion issuer for workloads.
	IssuerKindWorkload IssuerKind = "workload"
)

// Valid reports whether k is a known kind.
func (k IssuerKind) Valid() bool {
	return k == IssuerKindPerson || k == IssuerKindWorkload
}

// IssuerSource says who created an external issuer.
type IssuerSource string

const (
	IssuerSourceAdmin     IssuerSource = "admin"
	IssuerSourceConnector IssuerSource = "connector"
	// IssuerSourceConfig marks a static external_issuers entry. Never stored.
	IssuerSourceConfig IssuerSource = "config"
)

// Defaults for an external issuer row.
const (
	DefaultIssuerMaxTokenAgeSeconds  = 600
	DefaultIssuerJWKSCacheTTLSeconds = 300
)

// ExternalIssuer is a trusted issuer owned by one account (ADR 0042 D4).
// See docs/external-issuers.md.
type ExternalIssuer struct {
	bun.BaseModel `bun:"table:external_issuers,alias:ei"`

	ID                  string              `bun:"id,pk,type:uuid,default:gen_random_uuid()" json:"id"`
	AccountID           string              `bun:"account_id,notnull"                        json:"account_id"`
	Issuer              string              `bun:"issuer,notnull"                            json:"issuer"`
	Kind                IssuerKind          `bun:"kind,notnull"                              json:"kind"`
	DisplayName         string              `bun:"display_name,notnull"                      json:"display_name"`
	JWKSURI             string              `bun:"jwks_uri,notnull"                          json:"jwks_uri"`
	Audiences           []string            `bun:"audiences,array"                           json:"audiences"`
	Algorithms          []string            `bun:"algorithms,array"                          json:"algorithms"`
	ClaimMapping        map[string]string   `bun:"claim_mapping,type:jsonb,notnull"          json:"claim_mapping"`
	PropagateClaims     []string            `bun:"propagate_claims,array"                    json:"propagate_claims"`
	ClaimConstraints    map[string][]string `bun:"claim_constraints,type:jsonb,notnull"      json:"claim_constraints"`
	ConstraintsKey      string              `bun:"constraints_key,notnull"                   json:"-"`
	MaxTokenAgeSeconds  int                 `bun:"max_token_age_seconds,notnull"             json:"max_token_age_seconds"`
	JWKSCacheTTLSeconds int                 `bun:"jwks_cache_ttl_seconds,notnull"            json:"jwks_cache_ttl_seconds"`
	Source              IssuerSource        `bun:"source,notnull"                            json:"source"`
	SourceRef           string              `bun:"source_ref,notnull"                        json:"source_ref"`
	Enabled             bool                `bun:"enabled,notnull"                           json:"enabled"`
	CreatedBy           string              `bun:"created_by,notnull"                        json:"created_by"`
	UpdatedBy           string              `bun:"updated_by,notnull"                        json:"updated_by"`
	CreatedAt           time.Time           `bun:"created_at,notnull,default:current_timestamp" json:"created_at"`
	UpdatedAt           time.Time           `bun:"updated_at,notnull,default:current_timestamp" json:"updated_at"`
}

// IssuerBinding maps a credential's runtime subject key, under one issuer
// row, to a ZeroID identity (ADR 0042 D6).
type IssuerBinding struct {
	bun.BaseModel `bun:"table:external_issuer_bindings,alias:eib"`

	ID         string    `bun:"id,pk,type:uuid,default:gen_random_uuid()" json:"id"`
	AccountID  string    `bun:"account_id,notnull"                        json:"account_id"`
	IssuerID   string    `bun:"issuer_id,type:uuid,notnull"               json:"issuer_id"`
	SubjectKey string    `bun:"subject_key,notnull"                       json:"subject_key"`
	IdentityID string    `bun:"identity_id,type:uuid,notnull"             json:"identity_id"`
	Enabled    bool      `bun:"enabled,notnull"                           json:"enabled"`
	CreatedBy  string    `bun:"created_by,notnull"                        json:"created_by"`
	UpdatedBy  string    `bun:"updated_by,notnull"                        json:"updated_by"`
	CreatedAt  time.Time `bun:"created_at,notnull,default:current_timestamp" json:"created_at"`
	UpdatedAt  time.Time `bun:"updated_at,notnull,default:current_timestamp" json:"updated_at"`
}

// IssuerValidationError is a refused issuer write. Code is the stable
// machine-readable reason documented in docs/external-issuers.md.
type IssuerValidationError struct {
	Code    string
	Message string
}

func (e *IssuerValidationError) Error() string { return e.Message }

func issuerInvalid(code, format string, args ...any) error {
	return &IssuerValidationError{Code: code, Message: fmt.Sprintf(format, args...)}
}

// IssuerValidation is what row validation needs from the deployment.
type IssuerValidation struct {
	// AllowHTTP admits http URLs, for a deployment that allows private
	// endpoints (local development against a mock IdP).
	AllowHTTP bool
	// Shared reports whether the issuer is on the platform's shared list.
	Shared bool
}

// knownMappingKeys are the claim_mapping targets a grant reads.
var knownMappingKeys = []string{"user_id", "email", "email_verified", "name", "role", "privilege_scope", "scope", "trust_level"}

// Normalize trims the row and applies defaults to unset fields.
func (e *ExternalIssuer) Normalize() {
	e.Issuer = strings.TrimSpace(e.Issuer)
	e.JWKSURI = strings.TrimSpace(e.JWKSURI)
	e.DisplayName = strings.TrimSpace(e.DisplayName)
	if len(e.Algorithms) == 0 {
		e.Algorithms = []string{"RS256", "ES256", "PS256"}
	}
	if e.MaxTokenAgeSeconds == 0 {
		e.MaxTokenAgeSeconds = DefaultIssuerMaxTokenAgeSeconds
	}
	if e.JWKSCacheTTLSeconds == 0 {
		e.JWKSCacheTTLSeconds = DefaultIssuerJWKSCacheTTLSeconds
	}
	if e.Source == "" {
		e.Source = IssuerSourceAdmin
	}
	if e.ClaimMapping == nil {
		e.ClaimMapping = map[string]string{}
	}
	if e.ClaimConstraints == nil {
		e.ClaimConstraints = map[string][]string{}
	}
	if e.PropagateClaims == nil {
		e.PropagateClaims = []string{}
	}
	e.Audiences = compactStrings(e.Audiences)
}

// Validate checks a row before it is written. Call Normalize first.
func (e *ExternalIssuer) Validate(v IssuerValidation) error {
	if !e.Kind.Valid() {
		return issuerInvalid("invalid_kind", "kind must be person or workload")
	}
	if err := checkIssuerURL(e.Issuer, v.AllowHTTP); err != nil {
		return issuerInvalid("invalid_issuer", "issuer %v", err)
	}
	if templatedIssuer(e.Issuer) {
		return issuerInvalid("invalid_issuer", "issuer %q is a template; use the tenant's own issuer", e.Issuer)
	}
	if e.Kind == IssuerKindPerson && slices.Contains(WorkloadOnlyIssuers, CanonicalIssuer(e.Issuer)) {
		return issuerInvalid("invalid_issuer", "issuer %q issues workload tokens only; it can be a workload issuer, not a person issuer", e.Issuer)
	}
	if e.Kind == IssuerKindPerson && EntraMultiTenantIssuer(e.Issuer) {
		return issuerInvalid("invalid_issuer",
			"issuer %q is an Entra multi-tenant endpoint; a person issuer must be one tenant (https://login.microsoftonline.com/<tenant-id>/v2.0)", e.Issuer)
	}
	if err := checkIssuerURL(e.JWKSURI, v.AllowHTTP); err != nil {
		return issuerInvalid("invalid_jwks_uri", "jwks_uri %v", err)
	}
	// A person row may leave audiences empty: on the ID-token exchange an
	// enabled binding admits its client_id as the audience, and an ID-JAG's
	// audience is ZeroID's issuer. A workload row has no such rule.
	if e.Kind == IssuerKindWorkload && len(e.Audiences) == 0 {
		return issuerInvalid("invalid_audiences", "a workload issuer needs at least one audience")
	}
	for _, alg := range e.Algorithms {
		if !ExternalIssuerAlgorithmAllowed(alg) {
			return issuerInvalid("invalid_algorithms", "algorithm %q is not supported (allowed: RS256, ES256, PS256)", alg)
		}
	}
	for _, c := range e.PropagateClaims {
		if !ExternalIssuerPropagatableClaim(c) {
			return issuerInvalid("invalid_propagate_claims", "propagate_claims entry %q is not supported (allowed: auth_time, acr, amr)", c)
		}
	}
	for k, claim := range e.ClaimMapping {
		if !slices.Contains(knownMappingKeys, k) {
			return issuerInvalid("invalid_claim_mapping", "claim_mapping key %q is not recognised", k)
		}
		if strings.TrimSpace(claim) == "" {
			return issuerInvalid("invalid_claim_mapping", "claim_mapping.%s names no claim", k)
		}
	}
	if e.Kind == IssuerKindPerson && e.ClaimMapping["user_id"] == "" {
		return issuerInvalid("invalid_claim_mapping", "a person issuer needs claim_mapping.user_id, the claim that carries the person's user key")
	}
	for claim, values := range e.ClaimConstraints {
		if strings.TrimSpace(claim) == "" || len(values) == 0 || slices.Contains(values, "") {
			return issuerInvalid("invalid_claim_constraints", "claim_constraints.%s must list at least one non-empty value", claim)
		}
	}
	if v.Shared && len(e.ClaimConstraints) == 0 {
		return &IssuerValidationError{Code: "shared_issuer_requires_constraints",
			Message: fmt.Sprintf("issuer %q is shared by many customers; add claim_constraints that pin it to yours", e.Issuer)}
	}
	if e.MaxTokenAgeSeconds < 1 || e.MaxTokenAgeSeconds > 3600 {
		return issuerInvalid("invalid_max_token_age", "max_token_age_seconds must be between 1 and 3600")
	}
	if e.JWKSCacheTTLSeconds < 30 || e.JWKSCacheTTLSeconds > 86400 {
		return issuerInvalid("invalid_jwks_cache_ttl", "jwks_cache_ttl_seconds must be between 30 and 86400")
	}
	switch e.Source {
	case IssuerSourceAdmin:
		if e.SourceRef != "" {
			return issuerInvalid("invalid_source", "source_ref is only set for source connector")
		}
	case IssuerSourceConnector:
		if e.SourceRef == "" {
			return issuerInvalid("invalid_source", "source connector needs source_ref, the connector that created the row")
		}
	default:
		return issuerInvalid("invalid_source", "source must be admin or connector")
	}
	if len(e.DisplayName) > 255 || len(e.SourceRef) > 255 {
		return issuerInvalid("invalid_request", "display_name and source_ref are at most 255 characters")
	}
	return nil
}

// UniquenessKey is the constraints_key column: empty for a customer-unique
// issuer, so the unique index allows one row per kind, and a hash of the
// canonical constraints for a shared one.
func (e *ExternalIssuer) UniquenessKey(shared bool) string {
	if !shared {
		return ""
	}
	keys := make([]string, 0, len(e.ClaimConstraints))
	for k := range e.ClaimConstraints {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	canon := make([][2]any, 0, len(keys))
	for _, k := range keys {
		vals := slices.Clone(e.ClaimConstraints[k])
		sort.Strings(vals)
		canon = append(canon, [2]any{k, vals})
	}
	raw, _ := json.Marshal(canon)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// ConstraintsMatch reports whether claims satisfy every claim constraint: the
// claim is present and equals one of the listed values (or, for an array
// claim, contains one).
func (e *ExternalIssuer) ConstraintsMatch(claims map[string]any) bool {
	for claim, allowed := range e.ClaimConstraints {
		if !claimMatches(claims[claim], allowed) {
			return false
		}
	}
	return true
}

func claimMatches(v any, allowed []string) bool {
	switch tv := v.(type) {
	case string:
		return slices.Contains(allowed, tv)
	case []string:
		for _, s := range tv {
			if slices.Contains(allowed, s) {
				return true
			}
		}
	case []any:
		for _, e := range tv {
			if s, ok := e.(string); ok && slices.Contains(allowed, s) {
				return true
			}
		}
	}
	return false
}

// AsConfig projects the row onto the config shape the grants verify against.
// AllowedAccounts is the owning account.
func (e *ExternalIssuer) AsConfig() ExternalIssuerConfig {
	return ExternalIssuerConfig{
		Issuer:          e.Issuer,
		JWKSURI:         e.JWKSURI,
		Audiences:       slices.Clone(e.Audiences),
		Kind:            e.Kind,
		Algorithms:      slices.Clone(e.Algorithms),
		MaxTokenAge:     time.Duration(e.MaxTokenAgeSeconds) * time.Second,
		JWKSCacheTTL:    time.Duration(e.JWKSCacheTTLSeconds) * time.Second,
		ClaimMapping:    e.ClaimMapping,
		AllowedAccounts: []string{e.AccountID},
		PropagateClaims: slices.Clone(e.PropagateClaims),
	}
}

func checkIssuerURL(raw string, allowHTTP bool) error {
	if raw == "" {
		return fmt.Errorf("is required")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
		return fmt.Errorf("must be an absolute URL with no userinfo, query or fragment, got %q", raw)
	}
	if u.Scheme != "https" && (u.Scheme != "http" || !allowHTTP) {
		return fmt.Errorf("must be an https URL, got %q", raw)
	}
	if len(raw) > 2048 {
		return fmt.Errorf("is longer than 2048 characters")
	}
	return nil
}

// templatedIssuer catches a discovery document's placeholder (Entra's
// multi-tenant issuer is literally ".../{tenantid}/v2.0").
func templatedIssuer(iss string) bool {
	return strings.ContainsAny(iss, "{}")
}

const entraHost = "login.microsoftonline.com"

// EntraMultiTenantIssuer reports whether iss is an Entra endpoint that names
// no single tenant: common, organizations or consumers.
func EntraMultiTenantIssuer(iss string) bool {
	u, err := url.Parse(iss)
	if err != nil || !strings.EqualFold(u.Host, entraHost) {
		return false
	}
	seg, _, _ := strings.Cut(strings.TrimPrefix(u.Path, "/"), "/")
	switch strings.ToLower(seg) {
	case "common", "organizations", "consumers":
		return true
	}
	return false
}

// WorkloadOnlyIssuers name no people, so they are never person issuers.
var WorkloadOnlyIssuers = []string{"https://token.actions.githubusercontent.com"}

// CanonicalIssuer is iss without trailing slashes: the form issuer
// uniqueness, locking and the shared list compare on. Tokens are still
// matched against the row's issuer exactly.
func CanonicalIssuer(iss string) string {
	return strings.TrimRight(strings.TrimSpace(iss), "/")
}

// DefaultSharedIssuers is the platform's shared-issuer list when the
// deployment configures none (ADR 0042 D4). Rows for these need claim
// constraints and may exist in several accounts.
var DefaultSharedIssuers = []string{
	"https://accounts.google.com",
	"https://token.actions.githubusercontent.com",
	"https://login.microsoftonline.com/common/v2.0",
	"https://login.microsoftonline.com/organizations/v2.0",
	"https://login.microsoftonline.com/consumers/v2.0",
	// The Microsoft personal-account tenant, the issuer consumer tokens carry.
	"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
}

func compactStrings(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}
