-- Brute-force protection state: failed login attempts per account.
CREATE TABLE login_attempts (
    email            VARCHAR(255) PRIMARY KEY,
    failed_count     INTEGER NOT NULL DEFAULT 0,
    first_failed_at  TIMESTAMPTZ,
    last_failed_at   TIMESTAMPTZ,
    locked_until     TIMESTAMPTZ
);
