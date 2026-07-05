-- Undo 007: app scoping.

BEGIN;

DROP INDEX IF EXISTS idx_refresh_tokens_user_app;

ALTER TABLE sessions       DROP COLUMN IF EXISTS app_id;
ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS app_id;

DROP INDEX IF EXISTS idx_user_apps_app;
DROP INDEX IF EXISTS idx_user_apps_user;
DROP TABLE  IF EXISTS user_apps;

DROP INDEX IF EXISTS idx_apps_status;
DROP INDEX IF EXISTS idx_apps_code;
DROP TABLE  IF EXISTS apps;

COMMIT;
