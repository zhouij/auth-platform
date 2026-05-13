UPDATE oauth2_registered_client
SET redirect_uris = redirect_uris || ',http://localhost:9084/login/oauth2/code/auth-platform',
    post_logout_redirect_uris = post_logout_redirect_uris || ',http://localhost:9084/'
WHERE client_id = 'web-client'
  AND redirect_uris NOT LIKE '%http://localhost:9084/login/oauth2/code/auth-platform%';
