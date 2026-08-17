-- Denylist for already-issued JWTs, populated when tokens are revoked.
-- Enforcement points (gateway) can check the jti of a presented token
-- against this table to close the revocation gap until the token expires.
CREATE TABLE oauth2_token_denylist (
    jti        VARCHAR(255) PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ix_oauth2_token_denylist_expires_at ON oauth2_token_denylist (expires_at);
