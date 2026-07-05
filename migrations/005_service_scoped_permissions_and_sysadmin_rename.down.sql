-- Reverse: rename system_admin back to super_admin + drop service column.

BEGIN;

UPDATE roles
    SET code = 'super_admin',
        name = 'Super Administrator',
        description = 'Platform-level super administrator with full access'
    WHERE code = 'system_admin';

DROP INDEX IF EXISTS idx_permissions_service;
ALTER TABLE permissions DROP COLUMN IF EXISTS service;

COMMIT;
