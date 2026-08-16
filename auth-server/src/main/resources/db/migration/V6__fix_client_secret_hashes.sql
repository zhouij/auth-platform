-- The original V2 seed hashes did not match the documented dev secrets.
-- Replace them with correct BCrypt hashes of the documented plaintexts:
--   web-client     -> "secret"
--   service-client -> "service-secret"
--   gateway-client -> "gateway-secret"
UPDATE oauth2_registered_client
SET client_secret = '{bcrypt}$2a$10$ZyshstwKgD1lqsSW8lr7Wew.JkoYkU9sLKAsODd7fEIeR0nKuDsbG'
WHERE client_id = 'web-client';

UPDATE oauth2_registered_client
SET client_secret = '{bcrypt}$2a$10$.G5fuIVUnjJvo49FNtJ/hut.gFDC7AeY25pAna6uJnq3eY0NIgy6a'
WHERE client_id = 'service-client';

UPDATE oauth2_registered_client
SET client_secret = '{bcrypt}$2a$10$u2aluebjEncMGfWF7/9NC.GrxRDsGUbwwgcmN4Ib62hp48KLyt2ue'
WHERE client_id = 'gateway-client';
