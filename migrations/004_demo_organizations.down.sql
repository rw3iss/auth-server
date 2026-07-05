-- Rollback demo organizations
-- Version: 004
-- Description: Removes demo organizations, memberships, and org member roles

-- Delete organization member roles (for the fixed membership IDs)
DELETE FROM organization_member_roles WHERE membership_id IN (
    'd1000000-0000-4000-a000-000000000001',
    'd1000000-0000-4000-a000-000000000002',
    'd1000000-0000-4000-a000-000000000003',
    'd1000000-0000-4000-a000-000000000004',
    'd1000000-0000-4000-a000-000000000005',
    'd1000000-0000-4000-a000-000000000006'
);

-- Delete organization memberships
DELETE FROM organization_members WHERE id IN (
    'd1000000-0000-4000-a000-000000000001',
    'd1000000-0000-4000-a000-000000000002',
    'd1000000-0000-4000-a000-000000000003',
    'd1000000-0000-4000-a000-000000000004',
    'd1000000-0000-4000-a000-000000000005',
    'd1000000-0000-4000-a000-000000000006'
);

-- Delete organizations
DELETE FROM organizations WHERE id IN (
    'd0000000-0000-4000-a000-000000000001',
    'd0000000-0000-4000-a000-000000000002'
);
