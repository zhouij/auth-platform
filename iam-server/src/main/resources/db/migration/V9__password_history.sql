-- Password history for reuse prevention (one of user_id/admin_user_id is set).
CREATE TABLE password_history (
    id             BIGSERIAL PRIMARY KEY,
    user_id        UUID REFERENCES users(id) ON DELETE CASCADE,
    admin_user_id  UUID REFERENCES admin_users(id) ON DELETE CASCADE,
    password_hash  VARCHAR(512) NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_password_history_owner CHECK (
        (user_id IS NOT NULL AND admin_user_id IS NULL) OR
        (user_id IS NULL AND admin_user_id IS NOT NULL)
    )
);

CREATE INDEX ix_password_history_user ON password_history (user_id, created_at DESC);
CREATE INDEX ix_password_history_admin ON password_history (admin_user_id, created_at DESC);
