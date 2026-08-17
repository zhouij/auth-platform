-- Re-enable the consent screen for the web-client BFF. V4 disabled it while
-- no consent UI existed; the consent page (/oauth2/consent) now exists.
UPDATE oauth2_registered_client
SET client_settings = replace(
    client_settings,
    '"settings.client.require-authorization-consent":false',
    '"settings.client.require-authorization-consent":true'
)
WHERE client_id = 'web-client';
