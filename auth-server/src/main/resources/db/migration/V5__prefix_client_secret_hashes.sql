-- Spring Security 7 DelegatingPasswordEncoder requires an encoding prefix
-- on stored client secrets. Prefix the legacy raw-BCrypt seeds with {bcrypt}.
UPDATE oauth2_registered_client
SET client_secret = '{bcrypt}' || client_secret
WHERE client_secret IS NOT NULL
  AND client_secret NOT LIKE '{%';
