-- Reverses 013. Drops the policy columns + index. The rw3iss org +
-- auth-client-demo app rows are left in place — they're data, not
-- schema; an operator who wants them gone can DELETE manually after
-- confirming no users depend on them.

DROP INDEX IF EXISTS idx_apps_default_org;

ALTER TABLE apps
    DROP COLUMN IF EXISTS allowed_email_domains,
    DROP COLUMN IF EXISTS allowed_auth_methods,
    DROP COLUMN IF EXISTS default_organization_id;
