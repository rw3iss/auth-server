-- Demo system_admin user for the auth-client-demo site.
-- Version: 021
-- Login: ryan@ryanweiss.net  /  (password hashed below, bcrypt cost 12)
--
-- NOTE: All nullable string fields MUST be set to '' (not NULL) because the Go
-- sqlx scanner fails on NULL -> string without a sql.NullString wrapper.

-- 1. The user ------------------------------------------------------------
INSERT INTO users (email, password_hash, first_name, last_name, display_name, phone, avatar_url, provider_user_id, two_factor_secret, status, email_verified, metadata, created_at, updated_at)
SELECT 'ryan@ryanweiss.net', '$2a$12$Eum7sdHmeRA5o0ECSdYel.VYppxNQ8JIbsFXs.sTPMDJ.PsCVYUKG', 'Ryan', 'Weiss', 'Ryan Weiss', '', '', '', '', 'active', true, '{}', NOW(), NOW()
WHERE NOT EXISTS (SELECT 1 FROM users WHERE email = 'ryan@ryanweiss.net');

-- Keep the password / active flags in sync if the row already exists.
UPDATE users
SET password_hash = '$2a$12$Eum7sdHmeRA5o0ECSdYel.VYppxNQ8JIbsFXs.sTPMDJ.PsCVYUKG',
    status = 'active',
    email_verified = true,
    metadata = COALESCE(metadata, '{}'),
    display_name = COALESCE(display_name, 'Ryan Weiss'),
    phone = COALESCE(phone, ''),
    avatar_url = COALESCE(avatar_url, ''),
    provider_user_id = COALESCE(provider_user_id, ''),
    two_factor_secret = COALESCE(two_factor_secret, '')
WHERE email = 'ryan@ryanweiss.net';

-- 2. Grant the platform-owner base role (by code) ------------------------
INSERT INTO user_base_roles (user_id, role_id)
SELECT u.id, r.id
FROM users u, roles r
WHERE u.email = 'ryan@ryanweiss.net'
  AND r.code = 'system_admin'
  AND r.organization_id IS NULL
  AND NOT EXISTS (SELECT 1 FROM user_base_roles WHERE user_id = u.id AND role_id = r.id);

-- 3. Grant demo-app membership so login works immediately ----------------
-- (the auth-client-demo app also has auto_grant_on_signup = true, so this
--  is belt-and-suspenders — it makes the account usable without a first
--  auto-grant round-trip.)
INSERT INTO user_apps (user_id, app_id, status)
SELECT u.id, a.id, 'active'
FROM users u, apps a
WHERE u.email = 'ryan@ryanweiss.net'
  AND a.code = 'auth-client-demo'
ON CONFLICT (user_id, app_id) DO UPDATE SET status = 'active';
