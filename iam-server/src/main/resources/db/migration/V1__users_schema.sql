-- Regular users table
CREATE TABLE users (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email                  VARCHAR(255) NOT NULL,
    username               VARCHAR(100),
    password_hash          VARCHAR(255) NOT NULL,
    first_name             VARCHAR(100),
    last_name              VARCHAR(100),
    enabled                BOOLEAN NOT NULL DEFAULT true,
    email_verified         BOOLEAN NOT NULL DEFAULT false,
    credentials_changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at          TIMESTAMPTZ
);

CREATE UNIQUE INDEX ux_users_email ON users (lower(email));
CREATE INDEX ix_users_username ON users (username) WHERE username IS NOT NULL;
CREATE UNIQUE INDEX ux_users_username ON users (lower(username)) WHERE username IS NOT NULL;
