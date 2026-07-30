-- ─────────────────────────────────────────────────────────────────────────
-- 023: CivicGate application roles (moderator, editor, state_rep)
--
-- Three new platform-global roles for the CivicGate product. They are seeded
-- as type='system', is_org_role=false, organization_id=NULL so they appear in
-- the platform role picker (ListSystemRoles → /admin/users) alongside
-- system_admin / super_admin / base_user.
--
-- IMPORTANT: these roles are AESTHETIC for now — they carry NO permissions
-- (no rows in role_permissions), so they grant no elevated access. CivicGate's
-- gateway isAdmin() only recognizes system_admin/super_admin/org_admin/admin,
-- so a moderator/editor/state_rep user is a normal user with a labeled role
-- until permissions are wired later.
--
--   moderator  — can flag/report content; hide or disapprove forum posts + petitions.
--   editor     — can add special content types and edit entity records/facts (e.g. people).
--   state_rep  — an elected CivicGate user representing a specific state; special
--                state-data / state-user-management actions (state relationships + actions
--                defined later in the product DB). Aesthetic label for now.
-- ─────────────────────────────────────────────────────────────────────────
INSERT INTO roles (id, code, name, description, type, level, is_org_role) VALUES
    (uuid_generate_v4(), 'moderator', 'Moderator',
     'Community moderator — can flag and report content, and hide or disapprove forum posts and petitions.',
     'system', 40, false)
ON CONFLICT (code, organization_id) WHERE deleted_at IS NULL DO NOTHING;

INSERT INTO roles (id, code, name, description, type, level, is_org_role) VALUES
    (uuid_generate_v4(), 'editor', 'Editor',
     'Content editor — can add special content types and edit entity records and facts (e.g. people).',
     'system', 40, false)
ON CONFLICT (code, organization_id) WHERE deleted_at IS NULL DO NOTHING;

INSERT INTO roles (id, code, name, description, type, level, is_org_role) VALUES
    (uuid_generate_v4(), 'state_rep', 'State Representative',
     'An elected CivicGate user representing a specific state, with special state-data and state-user-management actions (defined later).',
     'system', 50, false)
ON CONFLICT (code, organization_id) WHERE deleted_at IS NULL DO NOTHING;
