-- Migration 017: per-app user pools / namespaces.
-- Full design + rationale: docs/USER_POOLS.md.
--
-- Adds a "namespace" (user pool) dimension to identity:
--   - users.namespace — the user's home pool. Default 'default' for
--     every existing + future user not explicitly placed.
--   - apps.registration_namespace — the WRITE pool: which pool new
--     users created through this app land in. NULL/'' ⇒ 'default'.
--   - apps.read_namespaces — the READ pools: which pools this app
--     authenticates users against at login. Empty ⇒ [write namespace].
--
-- Email uniqueness moves from global to per-namespace (model A): the
-- same email may be a distinct identity in two pools. Fully backwards
-- compatible — unconfigured apps + all existing users resolve to
-- 'default', identical to pre-017 behavior.
--
-- Idempotent (IF [NOT] EXISTS) so it's safe to re-run on a drifted dev DB.

-- 1. users.namespace ---------------------------------------------------
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS namespace VARCHAR(100) NOT NULL DEFAULT 'default';

COMMENT ON COLUMN users.namespace IS
    'Home user pool. Default ''default''. Email is unique per (namespace, email) — see docs/USER_POOLS.md.';

-- 2. Per-namespace email uniqueness ------------------------------------
-- Replace the global unique index with a (namespace, email) one.
DROP INDEX IF EXISTS users_email_unique;
CREATE UNIQUE INDEX IF NOT EXISTS users_namespace_email_unique
    ON users(namespace, email) WHERE deleted_at IS NULL;

DROP INDEX IF EXISTS idx_users_email;
CREATE INDEX IF NOT EXISTS idx_users_namespace_email
    ON users(namespace, LOWER(email)) WHERE deleted_at IS NULL;

-- 3. apps read/write pool config ---------------------------------------
ALTER TABLE apps
    ADD COLUMN IF NOT EXISTS registration_namespace VARCHAR(100),
    ADD COLUMN IF NOT EXISTS read_namespaces        TEXT[] NOT NULL DEFAULT '{}';

COMMENT ON COLUMN apps.registration_namespace IS
    'WRITE pool: namespace new users registered through this app are created in. NULL/empty = ''default''.';
COMMENT ON COLUMN apps.read_namespaces IS
    'READ pools: namespaces this app authenticates users against at login. Empty = [registration_namespace]. The write namespace is always implicitly readable.';
