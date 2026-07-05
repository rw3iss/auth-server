-- AUDIT C3 — revert.

DELETE FROM role_permissions
WHERE permission_id IN (
    SELECT id FROM permissions WHERE code IN (
        'org:roles:read', 'org:roles:create', 'org:roles:update', 'org:roles:delete'
    )
);

DELETE FROM permissions WHERE code IN (
    'org:roles:read', 'org:roles:create', 'org:roles:update', 'org:roles:delete'
);

DROP INDEX IF EXISTS idx_permissions_org_assignable;

ALTER TABLE permissions DROP COLUMN org_assignable;
