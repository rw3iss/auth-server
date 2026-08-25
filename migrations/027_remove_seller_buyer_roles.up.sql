-- 027 — remove the `seller` and `buyer` roles.
--
-- WHY THEY WERE STILL HERE: they came from the original demo seed, which described a marketplace. Migration
-- 024 removed the demo ORGS and USERS but left these two ROLE DEFINITIONS behind. Because they are global
-- rows with `is_org_role = true`, every organisation created since has offered them — so a civic platform
-- was creating "seller" and "buyer" roles on every new org, and would keep doing so forever.
--
-- No migration in this repo creates them, so a FRESH installation is already clean. This exists for
-- installations that carry the historical rows.
--
-- SAFE TO RUN: verified on the live database before writing this — 0 user_base_roles, 0
-- organization_member_roles and 0 invitation_roles referenced either role, so no account loses access.
-- The DELETE is still written to cascade its dependents explicitly rather than relying on that remaining
-- true on some other installation.

-- Dependents first: an installation that DOES have assignments should have them removed rather than
-- hitting a foreign-key error halfway through.
DELETE FROM invitation_roles
 WHERE role_id IN (SELECT id FROM roles WHERE code IN ('seller', 'buyer'));

DELETE FROM organization_member_roles
 WHERE role_id IN (SELECT id FROM roles WHERE code IN ('seller', 'buyer'));

DELETE FROM user_base_roles
 WHERE role_id IN (SELECT id FROM roles WHERE code IN ('seller', 'buyer'));

DELETE FROM role_permissions
 WHERE role_id IN (SELECT id FROM roles WHERE code IN ('seller', 'buyer'));

DELETE FROM roles WHERE code IN ('seller', 'buyer');
