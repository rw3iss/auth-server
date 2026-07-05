-- Undo AUDIT 1.9 refresh-token family columns.

DROP INDEX IF EXISTS idx_refresh_tokens_family_live;
ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS parent_id;
ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS family_id;
