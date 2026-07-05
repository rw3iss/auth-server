-- ─────────────────────────────────────────────────────────────────────────
-- 015: Per-app frontend URL
--
-- Adds apps.frontend_url so transactional emails (verify-email,
-- password-reset, magic-link, invitation) can link back to the
-- originating app's frontend rather than the global CLIENT_URL.
--
-- Why this exists: the auth-server is multi-tenant. A user who
-- registers via the demo at auth-demo.vendidit.com shouldn't get a
-- verify link pointing at vendidit.com (or any other app's domain).
-- Each app declares its canonical frontend; the email layer reads
-- that and constructs links like `${frontend_url}/auth/verify-email`.
--
-- frontend_url is OPTIONAL: when NULL the email layer falls back to
-- the CLIENT_URL env var, preserving single-tenant behaviour for
-- deployments that haven't onboarded specific frontends.
--
-- Backfill: the auth-client-demo app is the only known consumer
-- today, so we set its URL inline.
--
-- Note: no inline BEGIN/COMMIT — the boot-time migrator
-- (internal/repository/postgres/migrator.go) wraps every .up.sql in
-- its own transaction. An inline COMMIT inside the body would close
-- that outer tx and trip "unexpected transaction status idle" on the
-- migrator's own Commit() call.
-- ─────────────────────────────────────────────────────────────────────────

ALTER TABLE apps
    ADD COLUMN frontend_url VARCHAR(500);

UPDATE apps
   SET frontend_url = 'https://auth-demo.vendidit.com'
 WHERE code = 'auth-client-demo';
