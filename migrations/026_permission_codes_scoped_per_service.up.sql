-- ─────────────────────────────────────────────────────────────────────────
-- 026: Permission codes are unique PER SERVICE, not globally.
--
-- THE PROBLEM THIS FIXES. `permissions.code` carried a global UNIQUE
-- constraint, so two applications could never both define an obvious name
-- like `reports.publish`. Worse, the failure was SILENT rather than a
-- conflict: the upsert was `ON CONFLICT (code) DO UPDATE SET service = …`,
-- so the second app's registration quietly took OWNERSHIP of the first
-- app's row. The first app's next sync then DELETED it, because
-- SyncForService prunes `WHERE service = $1 AND code != ALL($2)` and the
-- row now belonged to someone else. One app could erase another's
-- permission — and every role still pointing at it lost that grant.
--
-- Scoping the key to (service, code) removes the shared namespace, so the
-- conflict cannot arise at all rather than being something operators must
-- avoid by convention.
--
-- `service` is the right scope, not a new `app_code` column: it already
-- means "who owns this definition", `apps.service_codes` already records
-- which services an app consumes, and a second column naming the same fact
-- would be one more thing to keep in sync — and eventually disagree.
--
-- role_permissions references permissions by ID, so no grant is affected.
-- ─────────────────────────────────────────────────────────────────────────

BEGIN;

-- Safety: refuse to proceed if a duplicate would already violate the new key.
-- (Impossible under the old global constraint, but this migration must be
-- safe to re-run against a database that has diverged.)
DO $$
DECLARE dupes INT;
BEGIN
    SELECT count(*) INTO dupes FROM (
        SELECT service, code FROM permissions GROUP BY service, code HAVING count(*) > 1
    ) d;
    IF dupes > 0 THEN
        RAISE EXCEPTION 'Cannot apply: % duplicate (service, code) pairs exist', dupes;
    END IF;
END $$;

-- The constraint name is whatever Postgres generated for the inline UNIQUE
-- in 001 (`permissions_code_key`); drop defensively either way.
ALTER TABLE permissions DROP CONSTRAINT IF EXISTS permissions_code_key;
DROP INDEX IF EXISTS permissions_code_key;

ALTER TABLE permissions
    ADD CONSTRAINT permissions_service_code_key UNIQUE (service, code);

-- The old lone-code index stays useful for lookups that legitimately scan
-- every service (the admin catalog view), it is simply no longer unique.
CREATE INDEX IF NOT EXISTS idx_permissions_code ON permissions(code);

COMMIT;
