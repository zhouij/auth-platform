-- Align the seeded admin password hash with PasswordService.hashAdmin settings.
-- Email: admin@localhost
-- Password: admin123 (Argon2id hashed — 128 MiB, t=4, p=4)
UPDATE admin_users
SET password_hash = '$argon2id$v=19$m=131072,t=4,p=4$GbjCGdzxxIZrt6YHc3CK3Q$6fD7XeXKDpjLFz2EAbG2qAFYkGy4RMtfMRiMsU4HbMI'
WHERE email = 'admin@localhost'
  AND password_hash = '$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$hKOCJkTPFUZvLR+NmGKPOOj3j1SLhVETPAfVp8Kq7mM';
