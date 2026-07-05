-- Revert migration 017 (user pools / namespaces).
--
-- Restoring global email uniqueness only succeeds if no two live users
-- share an email across namespaces. If the feature was used, the
-- operator must reconcile duplicates before this down can complete.

ALTER TABLE apps
    DROP COLUMN IF EXISTS read_namespaces,
    DROP COLUMN IF EXISTS registration_namespace;

DROP INDEX IF EXISTS idx_users_namespace_email;
DROP INDEX IF EXISTS users_namespace_email_unique;

CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique
    ON users(email) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_users_email
    ON users(LOWER(email)) WHERE deleted_at IS NULL;

ALTER TABLE users DROP COLUMN IF EXISTS namespace;
