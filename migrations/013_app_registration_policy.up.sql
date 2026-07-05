-- Migration 013: per-app registration policy + Vendidit org seed + auth-client-demo app seed.
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
--       run "Vendidit-internal" apps that funnel every new user into
--       the Vendidit org without an explicit invitation step.
--
-- Design choice — why on apps, not organizations:
--   Apps already carry registration-adjacent settings (auto_grant_on_signup,
--   service_codes). A single org can power multiple apps with different
--   policies (e.g. a Vendidit-internal admin app + a future public-facing
--   app sharing the same org but with looser rules). Keeping policy on
--   the app lets each consumer dictate its own UX without rebuilding org
--   structure.
--
-- Seeds:
--   - "Vendidit" organization — the default internal namespace.
--   - "auth-client-demo" app — points at Vendidit org, restricted to
--     @vendidit.com emails, password-only.

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

-- 2. Seed the Vendidit organization. -----------------------------------
-- Owner is sourced from the existing admin user, matching the pattern
-- in 004_demo_organizations.up.sql (organizations.owner_id is NOT
-- NULL). When admin@vendidit.com isn't present (some non-demo
-- deployments), the SELECT returns 0 rows and the INSERT is a clean
-- no-op — operators on such deployments seed the org manually.
--
-- ON CONFLICT matches `organizations_slug_unique` which is a PARTIAL
-- unique index — Postgres requires the same predicate in the conflict
-- target (otherwise "no unique or exclusion constraint matching").
INSERT INTO organizations (id, slug, name, description, owner_id, status, created_at, updated_at)
SELECT
    '00000000-0000-0000-0000-000000000001',
    'vendidit',
    'Vendidit',
    'Default Vendidit-internal organization. Houses all internal employee accounts.',
    u.id,
    'active',
    NOW(),
    NOW()
FROM users u WHERE u.email = 'admin@vendidit.com'
ON CONFLICT (slug) WHERE deleted_at IS NULL DO NOTHING;

-- 3. Seed the auth-client-demo app. ------------------------------------
-- Points at the Vendidit org, password-only, @vendidit.com domain.
INSERT INTO apps (
    id, code, name, description,
    allowed_redirect_urls, service_codes,
    auto_grant_on_signup,
    allowed_email_domains, allowed_auth_methods, default_organization_id,
    status, metadata, created_at, updated_at
)
VALUES (
    '00000000-0000-0000-0000-000000000002',
    'auth-client-demo',
    'Auth Client Demo',
    'Live demo + feature catalog for @vendidit/auth-client. Internal Vendidit employees only; password authentication only.',
    ARRAY['https://auth-demo.vendidit.com', 'https://auth-demo.vendidit.com/*', 'http://localhost:3010', 'http://localhost:3010/*'],
    ARRAY['auth-client-demo'],
    true,                                                             -- auto_grant_on_signup
    ARRAY['vendidit.com'],                                            -- allowed_email_domains
    ARRAY['password'],                                                -- allowed_auth_methods
    (SELECT id FROM organizations WHERE slug = 'vendidit'),           -- default_organization_id
    'active',
    '{}'::jsonb,
    NOW(),
    NOW()
)
ON CONFLICT (code) DO UPDATE SET
    allowed_email_domains  = EXCLUDED.allowed_email_domains,
    allowed_auth_methods   = EXCLUDED.allowed_auth_methods,
    default_organization_id = EXCLUDED.default_organization_id,
    updated_at             = NOW();
