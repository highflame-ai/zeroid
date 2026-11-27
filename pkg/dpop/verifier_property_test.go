package dpop

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// propHTU is an absolute http(s) URL assembled from parts, so a property can
// vary one RFC 3986 component and hold the rest.
type propHTU struct {
	scheme, host, port, path, query, fragment string
}

func (u propHTU) String() string {
	s := u.scheme + "://" + u.host + u.port + u.path
	if u.query != "" {
		s += "?" + u.query
	}
	if u.fragment != "" {
		s += "#" + u.fragment
	}
	return s
}

func propRandomCase(t *rapid.T, s, label string) string {
	b := []byte(s)
	for i, c := range b {
		if rapid.Bool().Draw(t, label) {
			b[i] = byte(strings.ToUpper(string(c))[0])
		}
	}
	return string(b)
}

func propHTUParts(t *rapid.T) propHTU {
	lower := []rune("abcdefghijklmnopqrstuvwxyz0123456789")
	// Percent-escapes are drawn whole: a lone '%' is not a URI, and
	// normalizeHTU returns what it cannot parse unchanged, by design. The
	// path's escapes encode characters that are not unreserved, so RFC 3986
	// §6.2.2.2 does not allow decoding them.
	//
	// The path is drawn already in normal form, so no RFC 3986 normalization
	// may change it: never empty (§6.2.3 lets "" become "/") and with no "."
	// or ".." segment (§6.2.2.3 removes those). Empty segments are drawn,
	// since "/a/" and "/a//b" are not "/a" and "/a/b".
	segment := rapid.Map(rapid.SliceOfN(rapid.SampledFrom([]string{"a", "b", "c", "X", "Y", "Z", "0", "1", "9", "-", ".", "_", "~", "%2F", "%25", "%20"}), 1, 8), func(parts []string) string {
		return strings.Join(parts, "")
	}).Filter(func(s string) bool { return s != "." && s != ".." })
	segments := rapid.SliceOfN(rapid.OneOf(segment, segment, segment, rapid.Just("")), 1, 4).Draw(t, "path")
	path := "/" + strings.Join(segments, "/")
	queryPart := rapid.SliceOfN(rapid.SampledFrom([]string{"a", "X", "0", "=", "&", "-", ".", "~", "/", "?", "%2F", "%41"}), 0, 8)
	joined := func(label string) string { return strings.Join(queryPart.Draw(t, label), "") }
	return propHTU{
		scheme:   rapid.SampledFrom([]string{"http", "https"}).Draw(t, "scheme"),
		host:     rapid.StringOfN(rapid.SampledFrom(lower), 1, 10, -1).Draw(t, "host") + ".test",
		port:     rapid.SampledFrom([]string{"", ":80", ":443", ":8080", ":8443"}).Draw(t, "port"),
		path:     path,
		query:    joined("query"),
		fragment: joined("fragment"),
	}
}

// TestProperty_NormalizeHTU_Idempotent: normalizing an htu a second time changes nothing, for well-formed URLs and arbitrary strings alike.
func TestProperty_NormalizeHTU_Idempotent(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		raw := rapid.OneOf(
			rapid.Map(rapid.Custom(propHTUParts), propHTU.String),
			rapid.String(),
		).Draw(t, "raw")

		once := normalizeHTU(raw)
		if twice := normalizeHTU(once); twice != once {
			t.Fatalf("normalizeHTU(%q) = %q, then %q", raw, once, twice)
		}
	})
}

// TestProperty_NormalizeHTU_IgnoresQueryFragmentCaseAndDefaultPort: RFC 9449 §4.3 compares htu without query and fragment, after RFC 3986 §6.2.2.1 case and §6.2.3 default-port normalization (only the scheme's own default port), and keeps a path already in normal form as is.
func TestProperty_NormalizeHTU_IgnoresQueryFragmentCaseAndDefaultPort(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		u := propHTUParts(t)
		bare := u
		bare.query, bare.fragment = "", ""
		if (u.scheme == "https" && u.port == ":443") || (u.scheme == "http" && u.port == ":80") {
			bare.port = ""
		}
		// propHTUParts draws a lower-case scheme and host, so bare is already
		// in normal form. Computing want from it, not from normalizeHTU, is
		// what catches a normalizer that folds the other scheme's port too.
		want := bare.String()
		if got := normalizeHTU(want); got != want {
			t.Fatalf("normalizeHTU(%q) = %q, want it unchanged", want, got)
		}

		variant := u
		variant.scheme = propRandomCase(t, u.scheme, "schemeCase")
		variant.host = propRandomCase(t, u.host, "hostCase")
		if got := normalizeHTU(variant.String()); got != want {
			t.Fatalf("normalizeHTU(%q) = %q, want %q (from %q)", variant.String(), got, want, bare.String())
		}

		if strings.ContainsAny(u.path, "abc") {
			upper := bare
			upper.path = strings.ToUpper(u.path)
			if normalizeHTU(upper.String()) == want {
				t.Fatalf("path case was folded: %q and %q normalize the same", upper.String(), bare.String())
			}
		}
		other := bare
		other.port = ":9999"
		if normalizeHTU(other.String()) == want {
			t.Fatalf("a non-default port was dropped: %q", other.String())
		}
	})
}

// propFlipCase changes the case of one letter of s, or returns s when it has
// none.
func propFlipCase(t *rapid.T, s, label string) string {
	var letters []int
	for i := 0; i < len(s); i++ {
		if c := s[i] | 0x20; 'a' <= c && c <= 'z' {
			letters = append(letters, i)
		}
	}
	if len(letters) == 0 {
		return s
	}
	i := rapid.SampledFrom(letters).Draw(t, label)
	return s[:i] + string(s[i]^0x20) + s[i+1:]
}

// TestProperty_CheckATH_AcceptsExactlyTheTokenHash: checkATH accepts an ath iff it is base64url(SHA-256(access token)) without padding, so a case-folded, truncated or extended hash is refused.
func TestProperty_CheckATH_AcceptsExactlyTheTokenHash(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		token := rapid.String().Draw(t, "token")
		sum := sha256.Sum256([]byte(token))
		// Written from RFC 9449 §4.2's definition, not with the encoder checkATH uses.
		want := strings.TrimRight(strings.NewReplacer("+", "-", "/", "_").Replace(base64.StdEncoding.EncodeToString(sum[:])), "=")

		var ath string
		switch rapid.IntRange(0, 9).Draw(t, "form") {
		case 0:
			ath = want
		case 1:
			ath = ""
		case 2:
			ath = base64.URLEncoding.EncodeToString(sum[:]) // padded
		case 3:
			ath = base64.StdEncoding.EncodeToString(sum[:])
		case 4:
			i := rapid.IntRange(0, len(want)-1).Draw(t, "flip")
			ath = want[:i] + string(want[i]^byte(rapid.IntRange(1, 0x3f).Draw(t, "xor"))) + want[i+1:]
		case 5:
			other := sha256.Sum256([]byte(rapid.String().Draw(t, "otherToken")))
			ath = base64.RawURLEncoding.EncodeToString(other[:])
		case 6:
			ath = rapid.String().Draw(t, "random")
		case 7:
			ath = propFlipCase(t, want, "caseFlip")
		case 8:
			ath = want[:rapid.IntRange(1, len(want)-1).Draw(t, "cut")]
		case 9:
			ath = want + rapid.SampledFrom([]string{"A", "-", "_", "=", " "}).Draw(t, "suffix")
		}

		err := checkATH(ath, token)
		if (err == nil) != (ath == want) {
			t.Fatalf("checkATH(%q, %q) = %v, want accepted=%v", ath, token, err, ath == want)
		}
		if err != nil && !errors.Is(err, ErrATHMismatch) {
			t.Fatalf("checkATH refusal is %v, want ErrATHMismatch", err)
		}
	})
}

// TestProperty_CheckIATFreshness_AcceptsExactlyTheWindow: an iat is fresh iff now-maxAge-clockSkew <= iat <= now+clockSkew.
func TestProperty_CheckIATFreshness_AcceptsExactlyTheWindow(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		now := time.Unix(rapid.Int64Range(1e9, 3e9).Draw(t, "now"), 0)
		maxAge := time.Duration(rapid.Int64Range(2, 600).Draw(t, "maxAge")) * time.Second
		skew := time.Duration(rapid.Int64Range(0, int64(maxAge/time.Second)/2).Draw(t, "skew")) * time.Second
		v, err := NewVerifier(Config{Store: NewMemoryStore()}, WithMaxAge(maxAge), WithClockSkew(skew), WithNow(func() time.Time { return now }))
		if err != nil {
			t.Fatalf("NewVerifier: %v", err)
		}
		lower, upper := now.Add(-maxAge-skew), now.Add(skew)
		iat := rapid.OneOf(
			rapid.SampledFrom([]time.Time{lower, upper, lower.Add(-time.Nanosecond), upper.Add(time.Nanosecond), now}),
			rapid.Map(rapid.Int64Range(-2*int64(maxAge), 2*int64(maxAge)), func(d int64) time.Time { return now.Add(time.Duration(d)) }),
		).Draw(t, "iat")

		err = v.checkIATFreshness(iat)
		fresh := !iat.Before(lower) && !iat.After(upper)
		if (err == nil) != fresh {
			t.Fatalf("iat %s, window [%s, %s]: err=%v, want fresh=%v", iat, lower, upper, err, fresh)
		}
		if err != nil && !errors.Is(err, ErrClockSkew) {
			t.Fatalf("checkIATFreshness refusal is %v, want ErrClockSkew", err)
		}
	})
}
