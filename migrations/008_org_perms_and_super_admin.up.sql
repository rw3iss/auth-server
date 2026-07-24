-- ─────────────────────────────────────────────────────────────────────────
-- 008: Org-scoped permissions catalog + super_admin role
--
-- Two related additions:
--
--   1. org:* permission codes (read/update/members:* etc.) for the
--      self-service endpoints introduced in B4 (/orgs/{orgId}/...).
--      These are *separate* from the existing organizations:* codes which
--      target platform-admin endpoints under /admin/organizations.
--      Different routes, different audiences, different scope.
--
--   2. super_admin role — between system_admin (platform owner, level 0)
--      and org_admin (within one org, level 10). super_admin has
--      cross-org data-management access (users, organizations, members)
--      but NOT platform-internal access (app registration,
--      service-permission self-registration). It's the role for
--      operations / customer-success / support staff.
--
-- Role-level ordering (lower number = more privileged):
--
--     0   system_admin     Platform owner — full bypass
--     5   super_admin      Cross-org admin — explicit permissions
--    10   org_admin        Single-org admin
--    20   org_manager
--    80   org_member
--   100   base_user
-- ─────────────────────────────────────────────────────────────────────────

BEGIN;

-- ── 1. org:* permission catalog ──────────────────────────────────────────

INSERT INTO permissions (id, code, name, description, resource, action, category, service) VALUES
    (uuid_generate_v4(), 'org:read',            'View Own Org',        'View your own organization',                       'org', 'read',   'Org Self-Service', 'core'),
    (uuid_generate_v4(), 'org:update',          'Update Own Org',      'Update your own organization settings',            'org', 'update', 'Org Self-Service', 'core'),
    (uuid_generate_v4(), 'org:members:read',    'List Own Members',    'List members of your organization',                'org', 'read',   'Org Self-Service', 'core'),
    (uuid_generate_v4(), 'org:members:invite',  'Invite Member',       'Invite new members to your organization',          'org', 'create', 'Org Self-Service', 'core'),
    (uuid_generate_v4(), 'org:members:remove',  'Remove Member',       'Remove members from your organization',            'org', 'delete', 'Org Self-Service', 'core'),
    (uuid_generate_v4(), 'org:members:update',  'Update Member',       'Update member roles or status in your org',        'org', 'update', 'Org Self-Service', 'core');

-- ── 2. super_admin + org_member roles ────────────────────────────────────

INSERT INTO roles (id, code, name, description, type, level, is_org_role) VALUES
    (uuid_generate_v4(), 'super_admin', 'Super Admin',
     'Cross-organization administrator. Manages users, orgs, and memberships across the platform, but cannot register apps or platform services.',
     'system', 5, false);

-- org_member is the fallback role assigned to any new organization member
-- when the AddMember / AcceptInvitation call doesn't specify a more
-- specific role. Carries the bare minimum: read your own org and see
-- fellow members. Used by AuthService to guarantee every membership row
-- ends up with at least one role so the user's JWT carries org-scoped
-- permissions when they log in with org context.
INSERT INTO roles (id, code, name, description, type, level, is_org_role) VALUES
    (uuid_generate_v4(), 'org_member', 'Organization Member',
     'Baseline membership in an organization — read access to org and member list.',
     'system', 80, true);

-- ── 3. Permission assignments ────────────────────────────────────────────

-- Assign org:* (self-service set) to org_admin. AUDIT 2.4 requires these
-- on the role for the /orgs/{orgId}/* routes to function for any user
-- below system_admin.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.code = 'org_admin'
  AND p.code IN ('org:read', 'org:update', 'org:members:read', 'org:members:invite', 'org:members:remove', 'org:members:update');

-- org_member gets minimal read access — the user can see they're in the
-- org and view the member list, nothing else. More privileged roles
-- (org_manager, org_admin) layer on top.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.code = 'org_member'
  AND p.code IN ('org:read', 'org:members:read');

-- super_admin gets:
--   - every org:* self-service permission (so they can answer support
--     tickets that route to /orgs/{orgId}/* endpoints when they assume
--     org context via "view as" — future tooling).
--   - every organizations:* admin permission (cross-org platform-admin
--     endpoints).
--   - users:* except destructive operations.
--   - invitations:* / roles:read,list,assign / permissions:read,list
--     / settings:read / reports:read,list / auctions:read / bids:read,list
--     / items:read,list — enough to investigate and act on operational
--     issues without being able to delete users, change role catalogs, or
--     register apps.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.code = 'super_admin'
  AND p.code IN (
    'org:read', 'org:update', 'org:members:read', 'org:members:invite',
    'org:members:remove', 'org:members:update',
    'organizations:create', 'organizations:read', 'organizations:update', 'organizations:list',
    'users:create', 'users:read', 'users:update', 'users:list', 'users:invite',
    'roles:read', 'roles:list', 'roles:assign',
    'permissions:read', 'permissions:list',
    'invitations:create', 'invitations:read', 'invitations:delete',
    'settings:read',
    'reports:read', 'reports:list',
    'auctions:read', 'auctions:list',
    'bids:read', 'bids:list',
    'items:read', 'items:list'
);

COMMIT;
