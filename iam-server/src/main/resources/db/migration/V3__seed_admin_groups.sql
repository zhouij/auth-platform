-- Seed admin groups
INSERT INTO admin_groups (name, description) VALUES
    ('FULL_ACCESS', 'Unrestricted access to all admin functions'),
    ('USER_MANAGEMENT', 'Can manage regular user accounts'),
    ('ADMIN_MANAGEMENT', 'Can manage other admin accounts');
