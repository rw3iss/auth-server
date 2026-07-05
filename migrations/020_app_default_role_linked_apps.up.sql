-- 020 — app auto-provisioning config (§7.2 of the GlobalSKU integration).
-- default_role_code: org role granted in the app's default org (replaces the
--   hardcoded org_member). NULL = org_member fallback.
-- linked_app_codes: additional app codes whose user_apps membership is also
--   granted when this app provisions a user. Empty = none.
ALTER TABLE apps ADD COLUMN IF NOT EXISTS default_role_code TEXT;
ALTER TABLE apps ADD COLUMN IF NOT EXISTS linked_app_codes TEXT[] NOT NULL DEFAULT '{}';
