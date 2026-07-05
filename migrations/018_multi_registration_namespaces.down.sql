-- Revert migration 018 (multiple registration namespaces).
-- Dropping user_namespaces loses membership tags (home namespaces on
-- users.namespace are untouched, so identity itself survives).

DROP INDEX IF EXISTS idx_user_namespaces_namespace;
DROP TABLE IF EXISTS user_namespaces;

ALTER TABLE apps DROP COLUMN IF EXISTS registration_namespaces;
