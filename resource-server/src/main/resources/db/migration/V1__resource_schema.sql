-- Resource server domain schema
CREATE TABLE user_resources (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_subject  VARCHAR(255) NOT NULL,
    name           VARCHAR(255) NOT NULL,
    data           TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ix_user_resources_owner_subject ON user_resources (owner_subject);
CREATE UNIQUE INDEX ux_user_resources_owner_name ON user_resources (owner_subject, name);
CREATE INDEX ix_user_resources_updated_at ON user_resources (updated_at);
