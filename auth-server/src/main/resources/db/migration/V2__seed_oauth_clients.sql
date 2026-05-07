-- Seed OAuth2 clients with BCrypt-hashed secrets
-- Secrets (plaintext for dev only):
--   web-client      secret -> $2a$10$v8XOQhGQh/p1tF0lOJVJFuVJZvKXvIxhI58d1Xm6zQqN5G8RqjWCe
--   service-client  service-secret -> $2a$10$wNMjVFB7d7hU3zLw5R.KSuXPqPYNcSD/jp/OM5HhWMHFX4K5RQvBK
--   gateway-client  gateway-secret -> $2a$10$2UJ0mL.kgPRVL/G5Zgp/hOJApKmxMsBzCpBhRL5TIxbj8CqBEDNke

INSERT INTO oauth2_registered_client (
    id, client_id, client_id_issued_at, client_secret, client_name,
    client_authentication_methods, authorization_grant_types, redirect_uris,
    post_logout_redirect_uris, scopes, client_settings, token_settings
) VALUES (
    gen_random_uuid()::text,
    'web-client',
    CURRENT_TIMESTAMP,
    '$2a$10$v8XOQhGQh/p1tF0lOJVJFuVJZvKXvIxhI58d1Xm6zQqN5G8RqjWCe',
    'Web Client',
    'client_secret_basic',
    'authorization_code,refresh_token',
    'http://localhost:3000/callback,http://localhost:9081/callback',
    'http://localhost:3000/',
    'openid,profile,read,write',
    '{"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-proof-key":true,"settings.client.require-authorization-consent":true}',
    '{"@class":"java.util.Collections$UnmodifiableMap","settings.token.reuse-refresh-tokens":false,"settings.token.access-token-time-to-live":["java.time.Duration",900.000000000],"settings.token.refresh-token-time-to-live":["java.time.Duration",86400.000000000]}'
);

INSERT INTO oauth2_registered_client (
    id, client_id, client_id_issued_at, client_secret, client_name,
    client_authentication_methods, authorization_grant_types,
    scopes, client_settings, token_settings
) VALUES (
    gen_random_uuid()::text,
    'service-client',
    CURRENT_TIMESTAMP,
    '$2a$10$wNMjVFB7d7hU3zLw5R.KSuXPqPYNcSD/jp/OM5HhWMHFX4K5RQvBK',
    'Service Client',
    'client_secret_basic',
    'client_credentials',
    'read,write',
    '{"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-proof-key":false,"settings.client.require-authorization-consent":false}',
    '{"@class":"java.util.Collections$UnmodifiableMap","settings.token.reuse-refresh-tokens":true,"settings.token.access-token-time-to-live":["java.time.Duration",1800.000000000]}'
);

INSERT INTO oauth2_registered_client (
    id, client_id, client_id_issued_at, client_secret, client_name,
    client_authentication_methods, authorization_grant_types,
    scopes, client_settings, token_settings
) VALUES (
    gen_random_uuid()::text,
    'gateway-client',
    CURRENT_TIMESTAMP,
    '$2a$10$2UJ0mL.kgPRVL/G5Zgp/hOJApKmxMsBzCpBhRL5TIxbj8CqBEDNke',
    'Gateway Service Client',
    'client_secret_basic',
    'client_credentials',
    'internal.gateway',
    '{"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-proof-key":false,"settings.client.require-authorization-consent":false}',
    '{"@class":"java.util.Collections$UnmodifiableMap","settings.token.reuse-refresh-tokens":true,"settings.token.access-token-time-to-live":["java.time.Duration",3600.000000000]}'
);
