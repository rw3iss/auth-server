-- AUDIT C4 — TOTP 2FA enrollment lifecycle. The schema already has
-- `two_factor_enabled` and `two_factor_secret` (migration 001) but no way to
-- distinguish "secret provisioned but never verified" from "fully enabled".
-- two_factor_confirmed_at fills the gap: it's set at the moment the user
-- first submits a valid TOTP code after Setup, and cleared on Disable.
--
-- Why both `two_factor_enabled` and `two_factor_confirmed_at`? Because
-- there's a third state — "the user opted out but the row hasn't been
-- garbage-collected." Keeping the timestamp on disable would mislead anyone
-- tracing when 2FA was last active vs the user's current opt-in state.

ALTER TABLE users
    ADD COLUMN two_factor_confirmed_at TIMESTAMP WITH TIME ZONE;
