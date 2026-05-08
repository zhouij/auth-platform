-- Seed default admin user
-- Email: admin@localhost
-- Password: admin123 (Argon2id hashed — 64 MiB, t=3, p=4)
INSERT INTO admin_users (email, username, password_hash, first_name, last_name) VALUES
    ('admin@localhost', 'admin',
     '$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$hKOCJkTPFUZvLR+NmGKPOOj3j1SLhVETPAfVp8Kq7mM',
     'System', 'Administrator');

-- Assign FULL_ACCESS group to default admin
INSERT INTO admin_group_members (admin_user_id, group_id)
    SELECT a.id, g.id FROM admin_users a, admin_groups g
    WHERE a.email = 'admin@localhost' AND g.name = 'FULL_ACCESS';
