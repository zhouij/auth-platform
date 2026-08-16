-- Append-only security audit trail.
CREATE TABLE audit_log (
    id          BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_type  VARCHAR(50),
    actor_id    VARCHAR(255),
    action      VARCHAR(100) NOT NULL,
    target      VARCHAR(255),
    ip_address  VARCHAR(45),
    outcome     VARCHAR(20) NOT NULL,
    detail      VARCHAR(1000)
);

CREATE INDEX ix_audit_log_occurred_at ON audit_log (occurred_at);
CREATE INDEX ix_audit_log_action ON audit_log (action);
CREATE INDEX ix_audit_log_target ON audit_log (target);
