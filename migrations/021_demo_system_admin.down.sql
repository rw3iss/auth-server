-- Rollback demo system_admin user
-- Version: 021

DELETE FROM user_apps
WHERE user_id IN (SELECT id FROM users WHERE email = 'ryan@ryanweiss.net');

DELETE FROM user_base_roles
WHERE user_id IN (SELECT id FROM users WHERE email = 'ryan@ryanweiss.net');

DELETE FROM users WHERE email = 'ryan@ryanweiss.net';
