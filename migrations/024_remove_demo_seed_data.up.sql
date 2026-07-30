-- ─────────────────────────────────────────────────────────────────────────
-- 024: Remove demo seed data (organizations + users)
--
-- Earlier migrations (003/004/013/021) seeded demo organizations and users.
-- Those source seeds are now removed, but existing DBs still carry the rows —
-- this migration deletes them. Idempotent (deletes nothing when already gone).
--
--   Orgs:  rw3iss Marketplace, Acme Auctions, rw3iss  (no default org — none is wanted).
--   Users: admin@ / seller@ / buyer@ / manager@ / ryan@ryanweiss.net
--
-- FK-aware order: most children ON DELETE CASCADE (organization_members,
-- sessions, refresh_tokens, invitations, roles, user_base_roles, tokens…).
-- Two need care: audit_log.organization_id is NO ACTION (null it first), and
-- organizations.owner_id → users is NO ACTION (delete orgs BEFORE users).
-- apps.default_organization_id is SET NULL (demo apps survive, org ref nulled).
-- ─────────────────────────────────────────────────────────────────────────

-- Match the demo orgs by id OR slug (robust across environments).
-- 1) Detach audit rows (NO ACTION FK) so the org delete isn't blocked.
UPDATE audit_log SET organization_id = NULL
WHERE organization_id IN (
    SELECT id FROM organizations
    WHERE id IN ('d0000000-0000-4000-a000-000000000001', 'd0000000-0000-4000-a000-000000000002', '00000000-0000-0000-0000-000000000001')
       OR slug IN ('rw3iss-marketplace', 'acme-auctions', 'rw3iss')
);

-- 2) Delete the demo organizations (cascades members/roles/invitations/sessions).
DELETE FROM organizations
WHERE id IN ('d0000000-0000-4000-a000-000000000001', 'd0000000-0000-4000-a000-000000000002', '00000000-0000-0000-0000-000000000001')
   OR slug IN ('rw3iss-marketplace', 'acme-auctions', 'rw3iss');

-- 3) Delete the demo users (cascades sessions/tokens/base-roles/memberships).
DELETE FROM users
WHERE email IN ('admin@ryanweiss.net', 'seller@ryanweiss.net', 'buyer@ryanweiss.net', 'manager@ryanweiss.net', 'ryan@ryanweiss.net');
