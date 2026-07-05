-- AUDIT C3 — custom per-org roles + org-assignable permission flag.
--
-- An org admin should be able to define a custom role for their organization
-- (e.g. "Manager", "Inventory Clerk") and assign it a subset of permissions
-- without being able to escalate into platform-admin territory. The
-- org_assignable bit on permissions is the safety gate: only flagged
-- permissions can be selected by an org admin building a custom role.
-- system_admin / super_admin still bypass the gate for platform-level
-- role management at /admin/*.

ALTER TABLE permissions
    ADD COLUMN org_assignable BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX idx_permissions_org_assignable ON permissions(org_assignable)
    WHERE org_assignable = TRUE;

-- Mark the existing org-scoped permissions (seeded in migration 008) as
-- assignable from a custom role. These already represent things an org
-- admin can do; making them flag-assignable lets them be delegated.
UPDATE permissions SET org_assignable = TRUE WHERE code IN (
    'org:read',
    'org:update',
    'org:members:read',
    'org:members:invite',
    'org:members:remove',
    'org:members:update'
);

-- Role-management permissions for the org self-service surface. These
-- govern the lifecycle of custom roles within an organization. They are
-- intentionally NOT org_assignable: an org_admin gets them via the seeded
-- org_admin role, and granting them inside a custom role would let a
-- holder create more roles that grant the same permissions — a
-- self-replication primitive.
INSERT INTO permissions (id, code, name, description, resource, action, category, service, org_assignable)
VALUES
    (uuid_generate_v4(), 'org:roles:read',   'List org roles',     'List system + custom roles available within the organization',                  'org_roles', 'read',   'organization', 'core', FALSE),
    (uuid_generate_v4(), 'org:roles:create', 'Create custom role', 'Create a custom role bound to the organization with org_assignable permissions', 'org_roles', 'create', 'organization', 'core', FALSE),
    (uuid_generate_v4(), 'org:roles:update', 'Update custom role', 'Update a custom org role''s name / description / permission set',                'org_roles', 'update', 'organization', 'core', FALSE),
    (uuid_generate_v4(), 'org:roles:delete', 'Delete custom role', 'Delete a custom org role (only if not currently assigned to any member)',        'org_roles', 'delete', 'organization', 'core', FALSE)
ON CONFLICT (code) DO NOTHING;

-- Grant the role-management permissions to the seeded org_admin role so
-- every existing org admin inherits the capability automatically.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.code = 'org_admin'
  AND p.code IN ('org:roles:read', 'org:roles:create', 'org:roles:update', 'org:roles:delete')
ON CONFLICT DO NOTHING;
