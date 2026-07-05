-- Migration 014: magic-link sign-in.
--
-- One row per outstanding magic-link request. The user receives a
-- one-tap sign-in URL containing the bare random token; submitting it
-- exchanges the token for a token-pair the same way a password login
-- would.
--
-- Design:
--   - Tokens are stored as SHA-256 hashes (token_hash) so the row is
--     useless in isolation if the table is dumped.
--   - One-use: `consumed_at` is stamped on success; subsequent
--     verifications reject. We don't auto-delete consumed rows so
--     audit / abuse-detection can read them.
--   - Short TTL: 15 minutes by default (configurable per call).
--   - Email-keyed so a malicious requester floods their own inbox
--     instead of the user's — the request endpoint normalises + looks
--     up by email; we don't reveal whether the email exists.
--   - The grant request can carry an `app_code` so the resulting
--     token-pair is scoped to the requesting app (same as login flow).

CREATE TABLE magic_links (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email         VARCHAR(320) NOT NULL,
    token_hash    VARCHAR(255) NOT NULL,
    app_code      VARCHAR(100),
    expires_at    TIMESTAMP WITH TIME ZONE NOT NULL,
    consumed_at   TIMESTAMP WITH TIME ZONE,
    created_at    TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    ip_address    VARCHAR(45),
    user_agent    TEXT
);

CREATE UNIQUE INDEX idx_magic_links_token_hash ON magic_links(token_hash);
CREATE INDEX idx_magic_links_email_pending ON magic_links(email)
    WHERE consumed_at IS NULL;
CREATE INDEX idx_magic_links_user_pending ON magic_links(user_id)
    WHERE consumed_at IS NULL;

COMMENT ON TABLE magic_links IS
    'Outstanding magic-link sign-in tokens. Single-use, 15m TTL by default. Tokens stored hashed.';
