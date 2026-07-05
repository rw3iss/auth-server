-- AUDIT 1.9: refresh-token family + reuse detection (RFC 6819 §5.2.2.3).
--
-- Add a family_id and parent_id to refresh_tokens so we can detect
-- refresh-token theft and revoke the entire chain rooted at the original
-- issuance, not just the single row that was reused.
--
-- Today: rotating a stolen refresh token revokes the presented row; the
-- attacker's descendant tokens (T2, T3, ...) keep working until expiry.
-- After: presenting a revoked refresh token triggers RevokeAllInFamily, so
-- every rotation downstream from the theft is killed at once.

ALTER TABLE refresh_tokens
    ADD COLUMN family_id UUID,
    ADD COLUMN parent_id UUID REFERENCES refresh_tokens(id) ON DELETE SET NULL;

-- Backfill: every existing row is its own family root. Doing this in one
-- statement (rather than per-row UPDATE) keeps the migration fast even on
-- large tables.
UPDATE refresh_tokens SET family_id = id WHERE family_id IS NULL;

-- Tighten the column once the backfill is in.
ALTER TABLE refresh_tokens ALTER COLUMN family_id SET NOT NULL;

-- Lookup index for family revocation. Partial (revoked = false) keeps it
-- small — the only query against this index is "revoke every live token in
-- this family," which by definition only cares about non-revoked rows.
CREATE INDEX idx_refresh_tokens_family_live ON refresh_tokens(family_id) WHERE revoked = false;
