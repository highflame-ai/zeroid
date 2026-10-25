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

	ID                 string              `bun:"id,pk,type:uuid,default:gen_random_uuid()" json:"id"`
	AccountID          string              `bun:"account_id,notnull"                        json:"account_id"`
	Issuer             string              `bun:"issuer,notnull"                            json:"issuer"`
	Kind               IssuerKind          `bun:"kind,notnull"                              json:"kind"`
	DisplayName        string              `bun:"display_name,notnull"                      json:"display_name"`
	JWKSURI            string              `bun:"jwks_uri,notnull"                          json:"jwks_uri"`
	Audiences          []string            `bun:"audiences,array"                           json:"audiences"`
	Algorithms         []string            `bun:"algorithms,array"                          json:"algorithms"`
	ClaimMapping       map[string]string   `bun:"claim_mapping,type:jsonb,notnull"          json:"claim_mapping"`
	PropagateClaims    []string            `bun:"propagate_claims,array"                    json:"propagate_claims"`
	ClaimConstraints   map[string][]string `bun:"claim_constraints,type:jsonb,notnull"      json:"claim_constraints"`
	ConstraintsKey     string              `bun:"constraints_key,notnull"                   json:"-"`
	MaxTokenAgeSeconds int                 `bun:"max_token_age_seconds,notnull"             json:"max_token_age_seconds"`
	// TrustEmail makes the issuer vouch for its own email claim: a person
	// token that carries an email but no email_verified claim counts as
	// verified. An explicit email_verified=false is never overridden.
	TrustEmail          bool         `bun:"trust_email,notnull"                       json:"trust_email"`
	JWKSCacheTTLSeconds int          `bun:"jwks_cache_ttl_seconds,notnull"            json:"jwks_cache_ttl_seconds"`
	Source              IssuerSource `bun:"source,notnull"                            json:"source"`
	SourceRef           string       `bun:"source_ref,notnull"                        json:"source_ref"`
	Enabled             bool         `bun:"enabled,notnull"                           json:"enabled"`
	CreatedBy           string       `bun:"created_by,notnull"                        json:"created_by"`
	UpdatedBy           string       `bun:"updated_by,notnull"                        json:"updated_by"`
	CreatedAt           time.Time    `bun:"created_at,notnull,default:current_timestamp" json:"created_at"`
	UpdatedAt           time.Time    `bun:"updated_at,notnull,default:current_timestamp" json:"updated_at"`
	DeletedAt           *time.Time   `bun:"deleted_at"                                json:"-"`
}

// IssuerBinding maps a credential's runtime subject key, under one issuer
// row, to a ZeroID identity (ADR 0042 D6).
type IssuerBinding struct {
	bun.BaseModel `bun:"table:external_issuer_bindings,alias:eib"`

	ID         string `bun:"id,pk,type:uuid,default:gen_random_uuid()" json:"id"`
	AccountID  string `bun:"account_id,notnull"                        json:"account_id"`
	IssuerID   string `bun:"issuer_id,type:uuid,notnull"               json:"issuer_id"`
	SubjectKey string `bun:"subject_key,notnull"                       json:"subject_key"`
	IdentityID string `bun:"identity_id,type:uuid,notnull"             json:"identity_id"`
	Enabled    bool   `bun:"enabled,notnull"                           json:"enabled"`
	// ExplicitlyDisabled records an admin's decision to disable, as opposed
	// to disabled only because the identity was not active yet.
	ExplicitlyDisabled bool       `bun:"explicitly_disabled,notnull" json:"explicitly_disabled"`
	DeletedAt          *time.Time `bun:"deleted_at"                  json:"-"`
	CreatedBy          string     `bun:"created_by,notnull"                        json:"created_by"`
	UpdatedBy          string     `bun:"updated_by,notnull"                        json:"updated_by"`
	CreatedAt          time.Time  `bun:"created_at,notnull,default:current_timestamp" json:"created_at"`
	UpdatedAt          time.Time  `bun:"updated_at,notnull,default:current_timestamp" json:"updated_at"`
}

// Length caps. URLs and subject keys sit in btree indexes (about 2.7 kB per
// entry); the rest bound what a row carries.
const (
	MaxIssuerURLBytes   = 2000
	MaxSubjectKeyBytes  = 2000
	maxClaimNameBytes   = 128
	maxClaimValueBytes  = 256
	maxClaimValues      = 50
	maxConstraintClaims = 20
	maxAudiences        = 50
)

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
	// PinClaim is the shared-issuer list's pinning claim for this issuer, or
	// "" for a customer-unique issuer.
	PinClaim string
	// JWKSURIPending skips jwks_uri, which is discovered after validation.
	JWKSURIPending bool
}

// ValidateIssuerURL checks an issuer or JWKS URL the way Validate does.
func ValidateIssuerURL(raw string, allowHTTP bool) error {
	if err := checkIssuerURL(raw, allowHTTP); err != nil {
		return issuerInvalid("invalid_issuer", "issuer %v", err)
	}
	return nil
}

// unpinnableClaims cannot pin an issuer to a customer: every token carries
// them, and iss and aud are checked separately. A constraint on one would
// only let a shared-issuer row look distinct from another while matching
// the same tokens.
var unpinnableClaims = []string{"iss", "aud", "exp", "iat", "nbf", "jti"}

// knownMappingKeys are the claim_mapping targets a grant reads.
var knownMappingKeys = []string{"user_id", "email", "email_verified", "name", "scope", "trust_level"}

// reservedMappingKeys are token claims an IdP claim must never set: a
// person's role and privilege scope come only from the deployer's own
// membership store, never from the customer's IdP (ADR 0044 D16). A
// claim_mapping naming one is refused with claim_mapping_reserved.
var reservedMappingKeys = []string{"role", "privilege_scope"}

// ReservedMappingKeysIn returns the reserved keys mapping names, in a fixed
// order, so callers report the same key whatever the map's iteration order.
func ReservedMappingKeysIn(mapping map[string]string) []string {
	var found []string
	for _, k := range reservedMappingKeys {
		if _, ok := mapping[k]; ok {
			found = append(found, k)
		}
	}
	return found
}

// Normalize trims the row and applies defaults to unset fields.
func (e *ExternalIssuer) Normalize() {
	e.Issuer = strings.TrimSpace(e.Issuer)
	e.JWKSURI = strings.TrimSpace(e.JWKSURI)
	e.DisplayName = strings.TrimSpace(e.DisplayName)
	if len(e.Algorithms) == 0 {
		// ES384 for AWS STS, which signs with RS256 or ES384 as the caller asks.
		e.Algorithms = []string{"RS256", "ES256", "ES384", "PS256"}
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
	if slices.Contains(unclaimableIssuers, CanonicalIssuer(e.Issuer)) {
		return issuerInvalid("invalid_issuer", "issuer %q (personal Microsoft accounts) belongs to no customer and cannot be trusted by an account", e.Issuer)
	}
	if e.Kind == IssuerKindPerson && slices.Contains(WorkloadOnlyIssuers, CanonicalIssuer(e.Issuer)) {
		return issuerInvalid("invalid_issuer", "issuer %q issues workload tokens only; it can be a workload issuer, not a person issuer", e.Issuer)
	}
	// No token carries these as iss, and their discovery documents publish
	// a templated issuer, so a row on one could never match: each tenant is
	// its own issuer.
	if EntraMultiTenantIssuer(e.Issuer) {
		return issuerInvalid("invalid_issuer",
			"issuer %q is an Entra multi-tenant endpoint; add each tenant's own issuer (https://login.microsoftonline.com/<tenant-id>/v2.0)", e.Issuer)
	}
	if !v.JWKSURIPending {
		if err := checkIssuerURL(e.JWKSURI, v.AllowHTTP); err != nil {
			return issuerInvalid("invalid_jwks_uri", "jwks_uri %v", err)
		}
	}
	// A person row may leave audiences empty: on the ID-token exchange an
	// enabled binding admits its client_id as the audience, and an ID-JAG's
	// audience is ZeroID's issuer. A workload row has no such rule.
	if e.Kind == IssuerKindWorkload && len(e.Audiences) == 0 {
		return issuerInvalid("invalid_audiences", "a workload issuer needs at least one audience")
	}
	// Only a person token has an email to vouch for.
	if e.TrustEmail && e.Kind != IssuerKindPerson {
		return issuerInvalid("invalid_trust_email", "trust_email applies to a person issuer only")
	}
	if len(e.Audiences) > maxAudiences || slices.ContainsFunc(e.Audiences, func(a string) bool { return len(a) > MaxIssuerURLBytes }) {
		return issuerInvalid("invalid_audiences", "at most %d audiences of at most %d bytes", maxAudiences, MaxIssuerURLBytes)
	}
	for _, alg := range e.Algorithms {
		if !ExternalIssuerAlgorithmAllowed(alg) {
			return issuerInvalid("invalid_algorithms", "algorithm %q is not supported (allowed: RS256, ES256, ES384, PS256)", alg)
		}
	}
	for _, c := range e.PropagateClaims {
		if !ExternalIssuerPropagatableClaim(c) {
			return issuerInvalid("invalid_propagate_claims", "propagate_claims entry %q is not supported (allowed: auth_time, acr, amr)", c)
		}
	}
	// Before the per-key loop: map order must not decide between this code
	// and invalid_claim_mapping when a mapping has both kinds of fault.
	if reserved := ReservedMappingKeysIn(e.ClaimMapping); len(reserved) > 0 {
		return issuerInvalid("claim_mapping_reserved", "claim_mapping key %q is reserved: an IdP claim cannot set a token's %s", reserved[0], reserved[0])
	}
	for k, claim := range e.ClaimMapping {
		if len(claim) > maxClaimNameBytes {
			return issuerInvalid("invalid_claim_mapping", "claim_mapping.%s is longer than %d bytes", k, maxClaimNameBytes)
		}
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
	if len(e.ClaimConstraints) > maxConstraintClaims {
		return issuerInvalid("invalid_claim_constraints", "at most %d constrained claims", maxConstraintClaims)
	}
	for claim, values := range e.ClaimConstraints {
		if len(claim) > maxClaimNameBytes || len(values) > maxClaimValues ||
			slices.ContainsFunc(values, func(v string) bool { return len(v) > maxClaimValueBytes }) {
			return issuerInvalid("invalid_claim_constraints",
				"claim_constraints: names up to %d bytes, up to %d values of up to %d bytes each", maxClaimNameBytes, maxClaimValues, maxClaimValueBytes)
		}
		if slices.Contains(unpinnableClaims, claim) {
			return issuerInvalid("invalid_claim_constraints",
				"claim_constraints.%s pins nothing: every token carries it with no customer-specific value", claim)
		}
		if strings.TrimSpace(claim) == "" || len(values) == 0 || slices.Contains(values, "") {
			return issuerInvalid("invalid_claim_constraints", "claim_constraints.%s must list at least one non-empty value", claim)
		}
	}
	if v.PinClaim != "" && len(e.ClaimConstraints[v.PinClaim]) == 0 {
		return &IssuerValidationError{Code: "shared_issuer_requires_constraints",
			Message: fmt.Sprintf("issuer %q is shared by many customers; pin it to yours with claim_constraints.%s", e.Issuer, v.PinClaim)}
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
// pinning claim's values for a shared one (pin is that claim).
func (e *ExternalIssuer) UniquenessKey(pin string) string {
	if pin == "" {
		return ""
	}
	vals := slices.Clone(e.ClaimConstraints[pin])
	sort.Strings(vals)
	raw, _ := json.Marshal([2]any{pin, vals})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// ConstraintsMatch reports whether claims satisfy every claim constraint: the
// claim is present and equals one of the listed values (or, for an array
// claim, contains one). The pinning claim pin, when set, must be a single
// string: an array naming several customers' values would match each of
// their rows.
func (e *ExternalIssuer) ConstraintsMatch(claims map[string]any, pin string) bool {
	for claim, allowed := range e.ClaimConstraints {
		if claim == pin {
			if s, ok := claims[claim].(string); !ok || !slices.Contains(allowed, s) {
				return false
			}
			continue
		}
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
		TrustEmail:      e.TrustEmail,
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
	if len(raw) > MaxIssuerURLBytes {
		return fmt.Errorf("is longer than %d bytes", MaxIssuerURLBytes)
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

// SharedIssuer is an issuer many customers share (ADR 0042 D4) and the one
// claim whose value says which customer a token belongs to. Every row on it
// pins that claim, and rows are told apart on that claim alone.
type SharedIssuer struct {
	Issuer   string `koanf:"issuer"    json:"issuer"`
	PinClaim string `koanf:"pin_claim" json:"pin_claim"`
}

// DefaultSharedIssuers is the platform's shared-issuer list when the
// deployment configures none.
var DefaultSharedIssuers = []SharedIssuer{
	{Issuer: "https://accounts.google.com", PinClaim: "hd"},
	{Issuer: "https://token.actions.githubusercontent.com", PinClaim: "repository_owner_id"},
}

// SharedPin returns iss's pinning claim when iss is on list.
func SharedPin(list []SharedIssuer, iss string) (string, bool) {
	canon := CanonicalIssuer(iss)
	for _, sh := range list {
		if CanonicalIssuer(sh.Issuer) == canon {
			return sh.PinClaim, true
		}
	}
	return "", false
}

// ValidateSharedIssuers checks a configured shared-issuer list. allowHTTP
// admits http issuers, as federation.allow_private_endpoints does for rows
// (local development against a mock IdP).
func ValidateSharedIssuers(list []SharedIssuer, allowHTTP bool) error {
	for i, sh := range list {
		if err := checkIssuerURL(sh.Issuer, allowHTTP); err != nil {
			return fmt.Errorf("shared_issuers[%d].issuer %v", i, err)
		}
		if sh.PinClaim == "" || slices.Contains(unpinnableClaims, sh.PinClaim) {
			return fmt.Errorf("shared_issuers[%d].pin_claim must name a claim that identifies the customer (not iss, aud, exp, iat, nbf or jti)", i)
		}
	}
	return nil
}

// unclaimableIssuers name no customer and pin to none: Microsoft personal
// accounts all carry this tenant. No account may trust them.
var unclaimableIssuers = []string{"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0"}

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
