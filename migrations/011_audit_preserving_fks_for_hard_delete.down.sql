-- AUDIT C8 — revert. Note: re-establishing NOT NULL only succeeds if no
-- rows currently have NULL in those columns. Operationally you'd need to
-- backfill or accept the migration failure.

ALTER TABLE audit_log
    DROP CONSTRAINT audit_log_user_id_fkey,
    ADD CONSTRAINT audit_log_user_id_fkey
        FOREIGN KEY (user_id) REFERENCES users(id);

ALTER TABLE organization_members
    DROP CONSTRAINT organization_members_invited_by_fkey,
    ADD CONSTRAINT organization_members_invited_by_fkey
        FOREIGN KEY (invited_by) REFERENCES users(id);

ALTER TABLE user_base_roles
    DROP CONSTRAINT user_base_roles_assigned_by_fkey,
    ADD CONSTRAINT user_base_roles_assigned_by_fkey
        FOREIGN KEY (assigned_by) REFERENCES users(id);

ALTER TABLE invitations
    DROP CONSTRAINT invitations_invited_by_fkey,
    DROP CONSTRAINT invitations_accepted_by_fkey,
    ADD CONSTRAINT invitations_invited_by_fkey
        FOREIGN KEY (invited_by) REFERENCES users(id),
    ADD CONSTRAINT invitations_accepted_by_fkey
        FOREIGN KEY (accepted_by) REFERENCES users(id),
    ALTER COLUMN invited_by SET NOT NULL;

ALTER TABLE organization_member_roles
    DROP CONSTRAINT organization_member_roles_assigned_by_fkey,
    ADD CONSTRAINT organization_member_roles_assigned_by_fkey
        FOREIGN KEY (assigned_by) REFERENCES users(id),
    ALTER COLUMN assigned_by SET NOT NULL;
