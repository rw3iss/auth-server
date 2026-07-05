-- Migration 016 down: revert roles.name to the original long-form values.

UPDATE roles SET name = 'System Administrator',       updated_at = NOW()
    WHERE code = 'system_admin' AND name = 'System Admin';

UPDATE roles SET name = 'Super Administrator',        updated_at = NOW()
    WHERE code = 'super_admin'  AND name = 'Super Admin';

UPDATE roles SET name = 'Organization Administrator', updated_at = NOW()
    WHERE code = 'org_admin'    AND name = 'Organization Admin';
