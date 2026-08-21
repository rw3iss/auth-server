BEGIN;
ALTER TABLE permissions DROP CONSTRAINT IF EXISTS permissions_service_code_key;
-- Reverting requires that no two services share a code; this will fail loudly if they do.
ALTER TABLE permissions ADD CONSTRAINT permissions_code_key UNIQUE (code);
COMMIT;
