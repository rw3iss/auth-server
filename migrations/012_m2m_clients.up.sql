-- Migration 012: M2M (machine-to-machine) OAuth2 client_credentials
-- registry.
--
-- Adds the credential store backing POST /oauth/token. Each row is one
-- registered consumer (a service / cron / batch job / CI runner) that
-- can mint short-lived service-principal access tokens by presenting
-- its client_id + client_secret.
--
-- Closes the AUTH_REGISTRATION_TOKEN shim that auth-server-client used
-- as a stopgap (see auth-server-client/README.md). Replaces a long-lived
-- pre-issued system_admin JWT with proper rotatable, revocable,
-- scope-limited credentials.
--
-- Design choices:
--   - client_id is operator-chosen + globally unique (e.g. "rm-prod").
--     Easier to read in logs than a UUID. Indexed for hot-path lookup
--     during /oauth/token.
--   - client_secret is bcrypt-hashed at rest (cost configured by the
--     server's BCRYPT_COST). Plaintext is shown ONCE on creation and
--     never recoverable — operator must rotate to recover from loss.
--   - scopes TEXT[] enumerates the permission strings this client may
--     assert. The issued token's `scopes` claim is the intersection of
--     this list and any `scope` request parameter. Empty means "all
--     scopes the client owns" (full grant).
--   - allowed_audiences TEXT[] — optional restriction on which audiences
--     the issued tokens may target. Empty means "the auth-server's
--     default audience". Mostly defensive; downstream services already
--     validate aud locally.
--   - status: 'active' | 'disabled'. Disabled clients fail the grant
--     immediately without leaking whether the secret was right.
--   - last_used_at: stamped on every successful grant. Useful for
--     "what's still consuming this credential?" hygiene checks before
--     revocation.
--   - revoked_at: soft-revoke. Hard delete is fine too (no FK depends
--     on m2m_clients) but soft makes audit-log lookups easier.

CREATE TABLE m2m_clients (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id           TEXT NOT NULL UNIQUE,
    client_secret_hash  TEXT NOT NULL,
    name                TEXT NOT NULL,
    description         TEXT,
    scopes              TEXT[] NOT NULL DEFAULT '{}',
    allowed_audiences   TEXT[] NOT NULL DEFAULT '{}',
    status              TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'disabled')),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at        TIMESTAMPTZ,
    revoked_at          TIMESTAMPTZ,
    created_by          UUID REFERENCES users(id) ON DELETE SET NULL
);

-- Hot-path index: every /oauth/token lookup is by client_id.
CREATE INDEX idx_m2m_clients_client_id ON m2m_clients(client_id)
    WHERE revoked_at IS NULL;

-- For admin listing — ordering by created_at DESC.
CREATE INDEX idx_m2m_clients_created_at ON m2m_clients(created_at DESC)
    WHERE revoked_at IS NULL;

COMMENT ON TABLE  m2m_clients IS 'OAuth2 client_credentials registry. Each row is a machine consumer authorized to mint service-principal access tokens via POST /oauth/token.';
COMMENT ON COLUMN m2m_clients.client_id          IS 'Operator-chosen unique identifier shown to consumers (e.g. "rm-prod"). Indexed for grant-time lookup.';
COMMENT ON COLUMN m2m_clients.client_secret_hash IS 'bcrypt-hashed secret. Plaintext only visible on creation response.';
COMMENT ON COLUMN m2m_clients.scopes             IS 'Permission strings this client may assert in issued tokens. Intersected with any scope request parameter.';
COMMENT ON COLUMN m2m_clients.allowed_audiences  IS 'Audiences the issued tokens may target. Empty = server default audience.';
COMMENT ON COLUMN m2m_clients.status             IS 'active | disabled. Disabled clients fail grant without leaking secret correctness.';
COMMENT ON COLUMN m2m_clients.last_used_at       IS 'Stamped on every successful grant — useful for "what is still consuming this?" hygiene.';
COMMENT ON COLUMN m2m_clients.revoked_at         IS 'Soft-revoke timestamp. Revoked clients are filtered out of the hot-path lookup index.';
