-- Demo users for local development / testing
-- All passwords are: password
-- NOTE: All nullable string fields MUST be set to '' (not NULL) because the Go
-- sqlx scanner fails on NULL → string without a sql.NullString wrapper.

INSERT INTO users (email, password_hash, first_name, last_name, display_name, phone, avatar_url, provider_user_id, two_factor_secret, status, email_verified, metadata, created_at, updated_at)
SELECT 'admin@ryanweiss.net', '$2a$12$M/VOLH6UKOYWsPgRqNlQyeSVfawoif81sIb57ANfianeb9j9jr9Vq', 'Super', 'Admin', 'Super Admin', '', '', '', '', 'active', true, '{}', NOW(), NOW()
WHERE NOT EXISTS (SELECT 1 FROM users WHERE email = 'admin@ryanweiss.net');
UPDATE users SET password_hash = '$2a$12$M/VOLH6UKOYWsPgRqNlQyeSVfawoif81sIb57ANfianeb9j9jr9Vq', status = 'active', email_verified = true, metadata = COALESCE(metadata, '{}'), display_name = COALESCE(display_name, 'Super Admin'), phone = COALESCE(phone, ''), avatar_url = COALESCE(avatar_url, ''), provider_user_id = COALESCE(provider_user_id, ''), two_factor_secret = COALESCE(two_factor_secret, '') WHERE email = 'admin@ryanweiss.net';

INSERT INTO users (email, password_hash, first_name, last_name, display_name, phone, avatar_url, provider_user_id, two_factor_secret, status, email_verified, metadata, created_at, updated_at)
SELECT 'manager@ryanweiss.net', '$2a$12$M/VOLH6UKOYWsPgRqNlQyeSVfawoif81sIb57ANfianeb9j9jr9Vq', 'Demo', 'Manager', 'Demo Manager', '', '', '', '', 'active', true, '{}', NOW(), NOW()
WHERE NOT EXISTS (SELECT 1 FROM users WHERE email = 'manager@ryanweiss.net');

-- Assign roles
INSERT INTO user_base_roles (user_id, role_id) SELECT u.id, r.id FROM users u, roles r WHERE u.email = 'admin@ryanweiss.net' AND r.name = 'Super Administrator' AND NOT EXISTS (SELECT 1 FROM user_base_roles WHERE user_id = u.id AND role_id = r.id);
INSERT INTO user_base_roles (user_id, role_id) SELECT u.id, r.id FROM users u, roles r WHERE u.email = 'manager@ryanweiss.net' AND r.name = 'Organization Manager' AND NOT EXISTS (SELECT 1 FROM user_base_roles WHERE user_id = u.id AND role_id = r.id);
