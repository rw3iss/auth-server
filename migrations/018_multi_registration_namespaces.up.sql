-- Migration 018: multiple registration namespaces per app.
-- Extends migration 017 (user pools) — see docs/USER_POOLS.md.
--
-- An app may now register new users into SEVERAL pools at once:
--
--   - apps.registration_namespaces TEXT[]
--       Ordered write-pool list. The FIRST entry is the user's home
--       namespace (users.namespace — the per-pool email-uniqueness
--       anchor and the `namespace` JWT claim); the rest become
--       membership rows in user_namespaces. Empty ⇒ fall back to the
--       singular apps.registration_namespace (017), which remains for
--       back-compat. Both empty ⇒ 'default'.
--
--   - user_namespaces (user_id, namespace)
--       ADDITIONAL pools a user belongs to beyond their home
--       namespace. Login / register lookups match a user when their
--       home namespace OR any membership namespace intersects the
--       app's read set. No backfill needed: home-namespace matching
--       covers every pre-018 user.
--
-- Example (the claimleo app): registration_namespaces =
-- ['default','claimleo'] ⇒ new users live in the shared `default`
-- pool (home) AND are tagged as claimleo members, so future apps
-- reading `default` pick them up while claimleo can still address
-- its own cohort.
--
-- Idempotent (IF NOT EXISTS) — safe to re-run on a drifted dev DB.

ALTER TABLE apps
    ADD COLUMN IF NOT EXISTS registration_namespaces TEXT[] NOT NULL DEFAULT '{}';

COMMENT ON COLUMN apps.registration_namespaces IS
    'Ordered WRITE pools for new users. First = home namespace (users.namespace); rest become user_namespaces memberships. Empty = fall back to registration_namespace, then ''default''.';

CREATE TABLE IF NOT EXISTS user_namespaces (
    user_id    UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    namespace  VARCHAR(100) NOT NULL,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, namespace)
);

COMMENT ON TABLE user_namespaces IS
    'Additional user pools beyond users.namespace (the home pool). Auth lookups match home OR membership. Migration 018 / docs/USER_POOLS.md.';

CREATE INDEX IF NOT EXISTS idx_user_namespaces_namespace
    ON user_namespaces(namespace);
