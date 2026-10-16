package service

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// sha256SecretPrefix marks a client secret stored as a SHA-256 digest.
//
// Client secrets are 32 bytes from crypto/rand (generateSecureToken), never
// chosen by a person, so a slow password KDF buys nothing: 256 bits of entropy
// cannot be brute-forced from a leaked digest regardless of hash speed. bcrypt
// at cost 10–12 instead cost 60–250 ms of CPU per verify, which capped
// client_credentials at ~200 tokens/s on 16 cores and taxed every
// authenticated revoke/introspect call.
//
// Never use this for anything a human picks.
const sha256SecretPrefix = "sha256$"

// isServerGeneratedSecret reports whether secret has generateSecureToken(32)'s
// shape: 64 lowercase hex characters. Only such secrets may be moved off bcrypt.
func isServerGeneratedSecret(secret string) bool {
	if len(secret) != 64 {
		return false
	}
	for _, c := range secret {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// shouldUpgradeSecretHash decides whether a verified secret's bcrypt hash is
// rewritten as SHA-256: only a legacy hash, only when SHA-256 storage is
// enabled, and only for a secret this server could have generated.
func shouldUpgradeSecretHash(legacy, sha256Enabled bool, secret string) bool {
	return legacy && sha256Enabled && isServerGeneratedSecret(secret)
}

// hashClientSecret returns the stored form of a server-generated secret.
func hashClientSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return sha256SecretPrefix + hex.EncodeToString(sum[:])
}

// verifyClientSecret checks secret against a stored hash in either format.
// legacy reports a bcrypt hash that verified, so the caller can upgrade it.
func verifyClientSecret(stored, secret string) (ok, legacy bool) {
	if strings.HasPrefix(stored, sha256SecretPrefix) {
		return subtle.ConstantTimeCompare([]byte(stored), []byte(hashClientSecret(secret))) == 1, false
	}
	if stored == "" {
		return false, false
	}
	ok = bcrypt.CompareHashAndPassword([]byte(stored), []byte(secret)) == nil
	return ok, ok
}
