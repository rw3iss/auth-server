-- Reverse of 028. Dropping owner_user_id does NOT delete the clients it pointed
-- at — they simply become administrator-owned again, which is the pre-028 state.
DROP INDEX IF EXISTS oauth_clients_owner_idx;
ALTER TABLE oauth_clients DROP COLUMN IF EXISTS client_secret_prefix;
ALTER TABLE oauth_clients DROP COLUMN IF EXISTS owner_user_id;
