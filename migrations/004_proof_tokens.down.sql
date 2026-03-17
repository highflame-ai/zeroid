-- 004_proof_tokens.down.sql
-- Reverses 004_proof_tokens.up.sql

DROP INDEX IF EXISTS idx_proof_tokens_expires_at;
DROP INDEX IF EXISTS idx_proof_tokens_nonce;
DROP INDEX IF EXISTS idx_proof_tokens_identity_id;
DROP TABLE IF EXISTS proof_tokens;
