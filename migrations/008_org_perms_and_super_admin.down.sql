-- Undo 008: org:* permissions + super_admin role.
--
-- role_permissions rows cascade on role + permission delete (FK ON DELETE
-- CASCADE in 001), so removing the role and the permission codes is
-- enough.

BEGIN;

DELETE FROM roles WHERE code IN ('super_admin', 'org_member');

DELETE FROM permissions WHERE code IN (
    'org:read', 'org:update',
    'org:members:read', 'org:members:invite', 'org:members:remove', 'org:members:update'
);

COMMIT;
