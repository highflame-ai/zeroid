-- 069_aauth_bootstrap_redemptions.up.sql
-- AAuth Agent Provider (internal/aauth): which agent key redeemed each
-- workload assertion at POST /ap/token.
--
-- The assertion itself is spent in the shared single-use store (dpop_jti,
-- under the federated client assertion's key), so a platform token redeemed
-- at the token endpoint can't be redeemed here and the reverse. This table
-- adds what that store can't say: the key the first redemption bound. The
-- same key may redeem the same assertion again until it expires, once it
-- minted, because a Kubernetes projected token can't be re-minted on demand
-- and every worker and restarted container of a pod shares it. Any other key
-- is refused.
CREATE TABLE IF NOT EXISTS aauth_bootstrap_redemptions (
    replay_key  VARCHAR(512) PRIMARY KEY,
    jkt         VARCHAR(64)  NOT NULL,
    minted      BOOLEAN      NOT NULL DEFAULT FALSE,
    expires_at  TIMESTAMPTZ  NOT NULL,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_aauth_bootstrap_redemptions_expires_at
    ON aauth_bootstrap_redemptions (expires_at);
