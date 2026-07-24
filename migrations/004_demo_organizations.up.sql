-- Demo organizations for local development / testing
-- Version: 004
-- Description: Seeds a demo organization, memberships, and org member roles

-- Fixed UUIDs for demo organizations (deterministic for reproducibility)
-- rw3iss Marketplace: d0000000-0000-4000-a000-000000000001

-- ============================================================================
-- 1. Organizations
-- ============================================================================

INSERT INTO organizations (id, name, slug, description, owner_id, status, plan, settings, metadata, created_at, updated_at)
SELECT 'd0000000-0000-4000-a000-000000000001', 'rw3iss Marketplace', 'rw3iss-marketplace',
       'Primary demo marketplace organization', u.id, 'active', 'enterprise', '{}', '{}', NOW(), NOW()
FROM users u WHERE u.email = 'admin@ryanweiss.net'
AND NOT EXISTS (SELECT 1 FROM organizations WHERE slug = 'rw3iss-marketplace' AND deleted_at IS NULL);

-- ============================================================================
-- 2. Organization memberships
-- ============================================================================

-- Fixed membership UUIDs:
-- rw3iss Marketplace members:
--   admin@ryanweiss.net:   d1000000-0000-4000-a000-000000000001
--   manager@ryanweiss.net: d1000000-0000-4000-a000-000000000004

-- rw3iss Marketplace memberships
INSERT INTO organization_members (id, user_id, organization_id, status, joined_at, created_at, updated_at)
SELECT 'd1000000-0000-4000-a000-000000000001', u.id, 'd0000000-0000-4000-a000-000000000001', 'active', NOW(), NOW(), NOW()
FROM users u WHERE u.email = 'admin@ryanweiss.net'
ON CONFLICT DO NOTHING;

INSERT INTO organization_members (id, user_id, organization_id, status, joined_at, created_at, updated_at)
SELECT 'd1000000-0000-4000-a000-000000000004', u.id, 'd0000000-0000-4000-a000-000000000001', 'active', NOW(), NOW(), NOW()
FROM users u WHERE u.email = 'manager@ryanweiss.net'
ON CONFLICT DO NOTHING;

-- ============================================================================
-- 3. Organization member roles
-- ============================================================================

-- rw3iss Marketplace: admin@ryanweiss.net → org_admin
INSERT INTO organization_member_roles (id, membership_id, role_id, assigned_by, assigned_at, created_at, updated_at)
SELECT uuid_generate_v4(), 'd1000000-0000-4000-a000-000000000001', r.id, u.id, NOW(), NOW(), NOW()
FROM roles r, users u
WHERE r.code = 'org_admin' AND r.organization_id IS NULL AND u.email = 'admin@ryanweiss.net'
ON CONFLICT DO NOTHING;

-- rw3iss Marketplace: manager@ryanweiss.net → org_manager
INSERT INTO organization_member_roles (id, membership_id, role_id, assigned_by, assigned_at, created_at, updated_at)
SELECT uuid_generate_v4(), 'd1000000-0000-4000-a000-000000000004', r.id, u.id, NOW(), NOW(), NOW()
FROM roles r, users u
WHERE r.code = 'org_manager' AND r.organization_id IS NULL AND u.email = 'admin@ryanweiss.net'
ON CONFLICT DO NOTHING;
