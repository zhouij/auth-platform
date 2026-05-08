-- Admin users table
CREATE TABLE admin_users (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email                  VARCHAR(255) NOT NULL,
    username               VARCHAR(100),
    password_hash          VARCHAR(255) NOT NULL,
    first_name             VARCHAR(100),
    last_name              VARCHAR(100),
    enabled                BOOLEAN NOT NULL DEFAULT true,
    credentials_changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at          TIMESTAMPTZ
);

CREATE UNIQUE INDEX ux_admin_users_email ON admin_users (lower(email));
CREATE INDEX ix_admin_users_username ON admin_users (username) WHERE username IS NOT NULL;
CREATE UNIQUE INDEX ux_admin_users_username ON admin_users (lower(username)) WHERE username IS NOT NULL;

-- Admin groups table
CREATE TABLE admin_groups (
    id          BIGSERIAL PRIMARY KEY,
    name        VARCHAR(100) NOT NULL UNIQUE,
    description VARCHAR(255)
);

CREATE UNIQUE INDEX ux_admin_groups_name ON admin_groups (name);

-- Admin group membership junction table
CREATE TABLE admin_group_members (
    admin_user_id UUID NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
    group_id      BIGINT NOT NULL REFERENCES admin_groups(id) ON DELETE CASCADE,
    PRIMARY KEY (admin_user_id, group_id)
);

CREATE INDEX ix_admin_group_members_group_id ON admin_group_members (group_id);
