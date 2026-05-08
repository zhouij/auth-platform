-- Password reset tokens for regular users
CREATE TABLE user_password_reset_tokens (
    id         BIGSERIAL PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    jti        VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    used       BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX ux_user_password_reset_tokens_jti ON user_password_reset_tokens (jti);
CREATE INDEX ix_user_password_reset_tokens_user_id ON user_password_reset_tokens (user_id);

-- Password reset tokens for admin users
CREATE TABLE admin_password_reset_tokens (
    id             BIGSERIAL PRIMARY KEY,
    admin_user_id  UUID NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
    jti            VARCHAR(255) NOT NULL UNIQUE,
    expires_at     TIMESTAMPTZ NOT NULL,
    used           BOOLEAN NOT NULL DEFAULT false,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX ux_admin_password_reset_tokens_jti ON admin_password_reset_tokens (jti);
CREATE INDEX ix_admin_password_reset_tokens_admin_user_id ON admin_password_reset_tokens (admin_user_id);
