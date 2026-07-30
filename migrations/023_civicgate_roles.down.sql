-- Revert 023: remove the CivicGate application roles. Soft-safe: also removes any
-- user_roles / role_permissions rows referencing them (defensive; none seeded here).
DELETE FROM user_roles WHERE role_id IN (SELECT id FROM roles WHERE code IN ('moderator', 'editor', 'state_rep') AND organization_id IS NULL);
DELETE FROM role_permissions WHERE role_id IN (SELECT id FROM roles WHERE code IN ('moderator', 'editor', 'state_rep') AND organization_id IS NULL);
DELETE FROM roles WHERE code IN ('moderator', 'editor', 'state_rep') AND organization_id IS NULL;
