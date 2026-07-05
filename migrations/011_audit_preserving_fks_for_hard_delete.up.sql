-- AUDIT C8 — hard-delete users. Multiple FKs on users(id) default to ON
-- DELETE NO ACTION, which would block a real DELETE. We don't want that:
-- a hard-delete should succeed without the audit-preserving columns
-- pointing into a dangling row.
--
-- Strategy:
--   * audit_log.user_id, organization_members.invited_by,
--     user_base_roles.assigned_by, organization_member_roles.assigned_by,
--     invitations.invited_by, invitations.accepted_by → ON DELETE SET NULL.
--     History stays; the actor pointer goes NULL.
--   * organizations.owner_id stays as-is — the application layer refuses
--     to hard-delete a user who still owns an org. Transfer ownership
--     first. (Operationally this is the right safety: an org without an
--     owner is an orphan, not something we want to materialize via cascade.)
--
-- NOT NULL is dropped on the columns we're SETting NULL where present.

ALTER TABLE audit_log
    DROP CONSTRAINT audit_log_user_id_fkey,
    ADD CONSTRAINT audit_log_user_id_fkey
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE organization_members
    DROP CONSTRAINT organization_members_invited_by_fkey,
    ADD CONSTRAINT organization_members_invited_by_fkey
        FOREIGN KEY (invited_by) REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE user_base_roles
    DROP CONSTRAINT user_base_roles_assigned_by_fkey,
    ADD CONSTRAINT user_base_roles_assigned_by_fkey
        FOREIGN KEY (assigned_by) REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE invitations
    ALTER COLUMN invited_by DROP NOT NULL,
    DROP CONSTRAINT invitations_invited_by_fkey,
    ADD CONSTRAINT invitations_invited_by_fkey
        FOREIGN KEY (invited_by) REFERENCES users(id) ON DELETE SET NULL,
    DROP CONSTRAINT invitations_accepted_by_fkey,
    ADD CONSTRAINT invitations_accepted_by_fkey
        FOREIGN KEY (accepted_by) REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE organization_member_roles
    ALTER COLUMN assigned_by DROP NOT NULL,
    DROP CONSTRAINT organization_member_roles_assigned_by_fkey,
    ADD CONSTRAINT organization_member_roles_assigned_by_fkey
        FOREIGN KEY (assigned_by) REFERENCES users(id) ON DELETE SET NULL;
