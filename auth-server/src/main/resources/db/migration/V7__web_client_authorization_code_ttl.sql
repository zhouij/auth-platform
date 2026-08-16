-- Spring Security 7 reads the authorization code TTL from the registered
-- client's token_settings. The V2 seed for web-client did not include it,
-- which made the authorization_code grant fail with a NullPointerException.
-- Add the missing TTL (5 minutes).
UPDATE oauth2_registered_client
SET token_settings = '{"@class":"java.util.Collections$UnmodifiableMap","settings.token.reuse-refresh-tokens":false,"settings.token.access-token-time-to-live":["java.time.Duration",900.000000000],"settings.token.refresh-token-time-to-live":["java.time.Duration",86400.000000000],"settings.token.authorization-code-time-to-live":["java.time.Duration",300.000000000]}'
WHERE client_id = 'web-client'
  AND token_settings NOT LIKE '%authorization-code-time-to-live%';
