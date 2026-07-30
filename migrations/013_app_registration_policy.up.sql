-- Migration 013: per-app registration policy + rw3iss org seed + auth-client-demo app seed.
--
-- The "policy" columns let an app declare its registration rules:
--
--   - allowed_email_domains TEXT[]
--       If non-empty, only emails ending in one of these domains may
--       register through this app. Stored as bare domain strings (no
--       "@") and matched case-insensitively. Empty = any domain.
--
--   - allowed_auth_methods TEXT[]
--       Which authentication methods are accepted for register / login
--       through this app. Values mirror the SSO provider names plus
--       "password" for credential flow. Empty = all enabled methods
--       (the server's SSO_*_ENABLED config remains the upper bound).
--
--   - default_organization_id UUID
--       When set, users registered through this app are auto-added as
--       members of this org with the org_member role (or whatever roles
--       the org's invitation system would normally assign). Lets us
--       run "rw3iss-internal" apps that funnel every new user into
--       the rw3iss org without an explicit invitation step.
--
-- Design choice — why on apps, not organizations:
--   Apps already carry registration-adjacent settings (auto_grant_on_signup,
--   service_codes). A single org can power multiple apps with different
--   policies (e.g. a rw3iss-internal admin app + a future public-facing
--   app sharing the same org but with looser rules). Keeping policy on
--   the app lets each consumer dictate its own UX without rebuilding org
--   structure.
--
-- Seeds:
--   - "rw3iss" organization — the default internal namespace.
--   - "auth-client-demo" app — points at rw3iss org, restricted to
--     @ryanweiss.net emails, password-only.

-- 1. Policy columns on apps. -------------------------------------------
--
-- Idempotent. `IF NOT EXISTS` heals a previously-drifted state where the
-- DDL committed but the `_migrations` tracker row never landed (this
-- happened on at least one dev DB when an INSERT below failed mid-file
-- under the old shell migrator that didn't wrap apply+track in a
-- transaction). The Go boot-time migrator and the patched shell
-- migrator both wrap the whole file + tracker insert atomically going
-- forward, so a fresh DB would never hit this branch — but the guard
-- costs nothing and keeps the migration safely re-runnable.
ALTER TABLE apps
    ADD COLUMN IF NOT EXISTS allowed_email_domains  TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS allowed_auth_methods   TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS default_organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL;

COMMENT ON COLUMN apps.allowed_email_domains IS
    'If non-empty, only emails ending in one of these domains may register through this app. Bare domains, case-insensitive. Empty = any.';
COMMENT ON COLUMN apps.allowed_auth_methods IS
    'Auth methods accepted by this app: password, google, apple, microsoft, github, custom. Empty = all enabled methods.';
COMMENT ON COLUMN apps.default_organization_id IS
    'Users registered through this app are auto-added as members of this org. NULL = no auto-membership.';

CREATE INDEX IF NOT EXISTS idx_apps_default_org ON apps(default_organization_id)
    WHERE deleted_at IS NULL AND default_organization_id IS NOT NULL;

-- 2. Demo seeds removed (2026-07). ------------------------------------
-- This migration previously ALSO seeded the "rw3iss" organization
-- (00000000-0000-0000-0000-000000000001) and the "auth-client-demo" app
-- pointing at it. Those are demo/internal data that shouldn't exist in any
-- deployment (CivicGate uses no default org). The seeds are removed at the
-- source; existing DBs are cleaned by 024_remove_demo_seed_data. Only the
-- policy COLUMNS above are retained (they're real schema). Real apps/orgs
-- are registered by operators or the product, not seeded here.
