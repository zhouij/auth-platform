UPDATE oauth2_registered_client
SET client_settings = replace(
    client_settings,
    '"settings.client.require-authorization-consent":true',
    '"settings.client.require-authorization-consent":false'
)
WHERE client_id = 'web-client';
