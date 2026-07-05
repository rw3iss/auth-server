-- Migration 016: roles.name uses short "Admin" form (no "Administrator")
--
-- Original seeds (002, 005, 008) wrote the long-form English in
-- roles.name ("System Administrator", "Super Administrator",
-- "Organization Administrator"). UI surfaces prefer the dynamic
-- role.name over the static KNOWN_BASE_ROLE_LABELS map in
-- auth-shared, so the verbose form leaked into compact table
-- columns and role chips.
--
-- This migration aligns the DB to the compact label set:
--   system_admin → "System Admin"
--   super_admin  → "Super Admin"
--   org_admin    → "Organization Admin"
--
-- Other seeded roles (Org Manager, Org Member, Seller, Buyer, Base User)
-- are already short-form and not touched.
--
-- Idempotent: only updates rows where the old long form is still in
-- place. Safe to re-run.

UPDATE roles SET name = 'System Admin',       updated_at = NOW()
    WHERE code = 'system_admin' AND name = 'System Administrator';

UPDATE roles SET name = 'Super Admin',        updated_at = NOW()
    WHERE code = 'super_admin'  AND name = 'Super Administrator';

UPDATE roles SET name = 'Organization Admin', updated_at = NOW()
    WHERE code = 'org_admin'    AND name = 'Organization Administrator';
