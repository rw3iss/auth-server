-- ─────────────────────────────────────────────────────────────────────────
-- 028: self-service OIDC client registration — give a relying party an OWNER.
--
-- Until now registering a client was system_admin only, so a developer who
-- wanted to add "Login with CivicGate" to their site had no way to obtain a
-- client id. This column is what makes self-service possible SAFELY: every
-- self-service read and write filters on it in the WHERE clause, so a caller
-- can only ever see and change rows that are already theirs.
--
-- NULL means "created by an administrator". That is deliberate and load-bearing:
-- `owner_user_id = $caller` never matches NULL, so first-party and admin-created
-- clients — including the trusted `civicgate-web` client — are invisible and
-- untouchable through the self-service endpoints without a single extra check.
-- ─────────────────────────────────────────────────────────────────────────

ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS owner_user_id UUID REFERENCES users(id) ON DELETE CASCADE;

-- The account goes, its applications go with it. An orphaned client is a live
-- credential nobody can see in a UI to revoke.
COMMENT ON COLUMN oauth_clients.owner_user_id IS
    'Self-service owner. NULL = administrator-created; invisible to /oidc/clients.';

-- The first few characters of the client secret, so a UI can say WHICH secret is
-- live without being able to reproduce it. Mirrors the api_keys hash+prefix
-- posture: the secret itself exists in plaintext exactly once, in the response
-- to create/rotate.
ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS client_secret_prefix TEXT;

-- Partial: the overwhelming majority of rows will be self-service, but the index
-- only ever answers "this owner's clients", so admin rows have no business in it.
CREATE INDEX IF NOT EXISTS oauth_clients_owner_idx
    ON oauth_clients (owner_user_id) WHERE owner_user_id IS NOT NULL;
