-- ─────────────────────────────────────────────────────────────────────────
-- 021: User default color mode (email/UI theme preference)
--
-- Adds users.default_color_mode so downstream surfaces can render in the
-- recipient's preferred theme. The immediate consumer is the transactional
-- email layer (internal/email): when sending to a KNOWN user it selects the
-- light or dark branded shell variant matching this value. Product clients
-- may also read/write it as a profile preference (exposed on the user
-- profile GET + PATCH DTOs).
--
-- Values are constrained to 'dark' | 'light'. Dark is the default — it
-- matches the CivicGate default theme. Existing rows backfill to 'dark'
-- via the column DEFAULT + NOT NULL, so no separate UPDATE is needed.
--
-- Note: no inline BEGIN/COMMIT — the boot-time migrator
-- (internal/repository/postgres/migrator.go) wraps every .up.sql in its
-- own transaction.
-- ─────────────────────────────────────────────────────────────────────────

ALTER TABLE users
    ADD COLUMN default_color_mode VARCHAR(10) NOT NULL DEFAULT 'dark'
        CHECK (default_color_mode IN ('dark', 'light'));
