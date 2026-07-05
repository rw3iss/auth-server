-- Demo organizations for local development / testing
-- Version: 004
-- Description: Seeds demo organizations, memberships, and org member roles

-- Fixed UUIDs for demo organizations (deterministic for reproducibility)
-- Vendidit Marketplace: d0000000-0000-4000-a000-000000000001
-- Acme Auctions:        d0000000-0000-4000-a000-000000000002

-- ============================================================================
-- 1. Organizations
-- ============================================================================

INSERT INTO organizations (id, name, slug, description, owner_id, status, plan, settings, metadata, created_at, updated_at)
SELECT 'd0000000-0000-4000-a000-000000000001', 'Vendidit Marketplace', 'vendidit-marketplace',
       'Primary demo marketplace organization', u.id, 'active', 'enterprise', '{}', '{}', NOW(), NOW()
FROM users u WHERE u.email = 'admin@vendidit.com'
AND NOT EXISTS (SELECT 1 FROM organizations WHERE slug = 'vendidit-marketplace' AND deleted_at IS NULL);

INSERT INTO organizations (id, name, slug, description, owner_id, status, plan, settings, metadata, created_at, updated_at)
SELECT 'd0000000-0000-4000-a000-000000000002', 'Acme Auctions', 'acme-auctions',
       'Secondary demo auction house', u.id, 'active', 'free', '{}', '{}', NOW(), NOW()
FROM users u WHERE u.email = 'seller@vendidit.com'
AND NOT EXISTS (SELECT 1 FROM organizations WHERE slug = 'acme-auctions' AND deleted_at IS NULL);

-- ============================================================================
-- 2. Organization memberships
-- ============================================================================

-- Fixed membership UUIDs:
-- Vendidit Marketplace members:
--   admin@vendidit.com:   d1000000-0000-4000-a000-000000000001
--   seller@vendidit.com:  d1000000-0000-4000-a000-000000000002
--   buyer@vendidit.com:   d1000000-0000-4000-a000-000000000003
--   manager@vendidit.com: d1000000-0000-4000-a000-000000000004
-- Acme Auctions members:
--   seller@vendidit.com:  d1000000-0000-4000-a000-000000000005
--   buyer@vendidit.com:   d1000000-0000-4000-a000-000000000006

-- Vendidit Marketplace memberships
INSERT INTO organization_members (id, user_id, organization_id, status, joined_at, created_at, updated_at)
SELECT 'd1000000-0000-4000-a000-000000000001', u.id, 'd0000000-0000-4000-a000-000000000001', 'active', NOW(), NOW(), NOW()
FROM users u WHERE u.email = 'admin@vendidit.com'
ON CONFLICT DO NOTHING;

INSERT INTO organization_members (id, user_id, organization_id, status, joined_at, created_at, updated_at)
SELECT 'd1000000-0000-4000-a000-000000000002', u.id, 'd0000000-0000-4000-a000-000000000001', 'active', NOW(), NOW(), NOW()
FROM users u WHERE u.email = 'seller@vendidit.com'
ON CONFLICT DO NOTHING;

INSERT INTO organization_members (id, user_id, organization_id, status, joined_at, created_at, updated_at)
SELECT 'd1000000-0000-4000-a000-000000000003', u.id, 'd0000000-0000-4000-a000-000000000001', 'active', NOW(), NOW(), NOW()
FROM users u WHERE u.email = 'buyer@vendidit.com'
ON CONFLICT DO NOTHING;

INSERT INTO organization_members (id, user_id, organization_id, status, joined_at, created_at, updated_at)
SELECT 'd1000000-0000-4000-a000-000000000004', u.id, 'd0000000-0000-4000-a000-000000000001', 'active', NOW(), NOW(), NOW()
FROM users u WHERE u.email = 'manager@vendidit.com'
ON CONFLICT DO NOTHING;

-- Acme Auctions memberships
INSERT INTO organization_members (id, user_id, organization_id, status, joined_at, created_at, updated_at)
SELECT 'd1000000-0000-4000-a000-000000000005', u.id, 'd0000000-0000-4000-a000-000000000002', 'active', NOW(), NOW(), NOW()
FROM users u WHERE u.email = 'seller@vendidit.com'
ON CONFLICT DO NOTHING;

INSERT INTO organization_members (id, user_id, organization_id, status, joined_at, created_at, updated_at)
SELECT 'd1000000-0000-4000-a000-000000000006', u.id, 'd0000000-0000-4000-a000-000000000002', 'active', NOW(), NOW(), NOW()
FROM users u WHERE u.email = 'buyer@vendidit.com'
ON CONFLICT DO NOTHING;

-- ============================================================================
-- 3. Organization member roles
-- ============================================================================

-- Vendidit Marketplace: admin@vendidit.com → org_admin
INSERT INTO organization_member_roles (id, membership_id, role_id, assigned_by, assigned_at, created_at, updated_at)
SELECT uuid_generate_v4(), 'd1000000-0000-4000-a000-000000000001', r.id, u.id, NOW(), NOW(), NOW()
FROM roles r, users u
WHERE r.code = 'org_admin' AND r.organization_id IS NULL AND u.email = 'admin@vendidit.com'
ON CONFLICT DO NOTHING;

-- Vendidit Marketplace: seller@vendidit.com → seller
INSERT INTO organization_member_roles (id, membership_id, role_id, assigned_by, assigned_at, created_at, updated_at)
SELECT uuid_generate_v4(), 'd1000000-0000-4000-a000-000000000002', r.id, u.id, NOW(), NOW(), NOW()
FROM roles r, users u
WHERE r.code = 'seller' AND r.organization_id IS NULL AND u.email = 'admin@vendidit.com'
ON CONFLICT DO NOTHING;

-- Vendidit Marketplace: buyer@vendidit.com → buyer
INSERT INTO organization_member_roles (id, membership_id, role_id, assigned_by, assigned_at, created_at, updated_at)
SELECT uuid_generate_v4(), 'd1000000-0000-4000-a000-000000000003', r.id, u.id, NOW(), NOW(), NOW()
FROM roles r, users u
WHERE r.code = 'buyer' AND r.organization_id IS NULL AND u.email = 'admin@vendidit.com'
ON CONFLICT DO NOTHING;

-- Vendidit Marketplace: manager@vendidit.com → org_manager
INSERT INTO organization_member_roles (id, membership_id, role_id, assigned_by, assigned_at, created_at, updated_at)
SELECT uuid_generate_v4(), 'd1000000-0000-4000-a000-000000000004', r.id, u.id, NOW(), NOW(), NOW()
FROM roles r, users u
WHERE r.code = 'org_manager' AND r.organization_id IS NULL AND u.email = 'admin@vendidit.com'
ON CONFLICT DO NOTHING;

-- Acme Auctions: seller@vendidit.com → seller
INSERT INTO organization_member_roles (id, membership_id, role_id, assigned_by, assigned_at, created_at, updated_at)
SELECT uuid_generate_v4(), 'd1000000-0000-4000-a000-000000000005', r.id, u.id, NOW(), NOW(), NOW()
FROM roles r, users u
WHERE r.code = 'seller' AND r.organization_id IS NULL AND u.email = 'seller@vendidit.com'
ON CONFLICT DO NOTHING;

-- Acme Auctions: seller@vendidit.com → org_admin
INSERT INTO organization_member_roles (id, membership_id, role_id, assigned_by, assigned_at, created_at, updated_at)
SELECT uuid_generate_v4(), 'd1000000-0000-4000-a000-000000000005', r.id, u.id, NOW(), NOW(), NOW()
FROM roles r, users u
WHERE r.code = 'org_admin' AND r.organization_id IS NULL AND u.email = 'seller@vendidit.com'
ON CONFLICT DO NOTHING;

-- Acme Auctions: buyer@vendidit.com → buyer
INSERT INTO organization_member_roles (id, membership_id, role_id, assigned_by, assigned_at, created_at, updated_at)
SELECT uuid_generate_v4(), 'd1000000-0000-4000-a000-000000000006', r.id, u.id, NOW(), NOW(), NOW()
FROM roles r, users u
WHERE r.code = 'buyer' AND r.organization_id IS NULL AND u.email = 'seller@vendidit.com'
ON CONFLICT DO NOTHING;
