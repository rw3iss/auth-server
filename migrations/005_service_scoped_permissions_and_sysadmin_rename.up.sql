-- ─────────────────────────────────────────────────────────────────────────
-- 005: Service-scoped permissions + rename super_admin → system_admin
--
-- Two orthogonal changes grouped because they're both tiny and the whole
-- platform needs both before release-manager and other services land:
--
--   1. Permissions get a `service` column so each service owns its slice
--      of the catalog. Existing permissions default to service='core'.
--      Services self-register via POST /api/v1/admin/permissions/register.
--
--   2. The platform-wide "super_admin" role is renamed to "system_admin"
--      for clarity — it's the platform/system-level god role, not an
--      organization-scoped admin.
-- ─────────────────────────────────────────────────────────────────────────

BEGIN;

-- ── 1. Service column on permissions ─────────────────────────────────────
-- Default to 'core' so existing rows are attributed to the auth server itself
-- (users, orgs, roles, permissions are all auth-owned). Service code uses the
-- same kebab/snake convention as service identifiers elsewhere.

ALTER TABLE permissions
    ADD COLUMN IF NOT EXISTS service VARCHAR(100) NOT NULL DEFAULT 'core';

CREATE INDEX IF NOT EXISTS idx_permissions_service ON permissions(service);

-- (code, service) uniquely identifies a permission. The original code-only
-- unique constraint is preserved — same code can't exist twice even across
-- services. That keeps the JWT claim format unambiguous (a single string
-- like 'releases:create' resolves to exactly one permission).
--
-- If you want codes to be unique only within a service, drop the existing
-- unique constraint on `code` and add UNIQUE (service, code) instead.
-- We're keeping global uniqueness for now because it's the simpler invariant
-- and matches how callers use permissions (string match in the JWT claim).

-- ── 2. Rename super_admin → system_admin ─────────────────────────────────
-- Idempotent: UPDATE only if the old code exists. Safe to re-run.

UPDATE roles
    SET code = 'system_admin',
        name = 'System Admin',
        description = 'Platform-level system administrator with full access'
    WHERE code = 'super_admin';

COMMIT;
