-- ─────────────────────────────────────────────────────────────────────────
-- 025: OIDC provider — relying-party registry + authorization codes.
--
-- Turns this server from an account system into an identity PROVIDER: other
-- applications send a person here to log in and receive a verifiable token,
-- without ever handling the person's credentials.
-- ─────────────────────────────────────────────────────────────────────────

-- Registered relying parties ("clients" in OAuth terms).
CREATE TABLE IF NOT EXISTS oauth_clients (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id           TEXT NOT NULL UNIQUE,
    -- NULL for a PUBLIC client (a SPA or mobile app, which cannot keep a secret).
    -- Public clients are REQUIRED to use PKCE — see the authorize handler.
    client_secret_hash  TEXT,
    name                TEXT NOT NULL,
    description         TEXT,
    logo_url            TEXT,

    -- THE redirect allow-list. This is the single most security-critical column here: without exact
    -- matching, an attacker appends their own redirect_uri and the authorization code — and therefore the
    -- user's session — is delivered to them. Matching is exact; no wildcards, no prefix matching.
    redirect_uris       TEXT[] NOT NULL DEFAULT '{}',
    post_logout_uris    TEXT[] NOT NULL DEFAULT '{}',

    -- What this client may ever ask for. An authorization request is intersected with this, so a
    -- compromised client cannot escalate its own scope.
    allowed_scopes      TEXT[] NOT NULL DEFAULT '{openid,profile,email}',
    grant_types         TEXT[] NOT NULL DEFAULT '{authorization_code,refresh_token}',

    -- Which app/namespace this client authenticates against.
    app_code            TEXT,
    -- Skip the consent screen. ONLY for first-party clients we operate ourselves; never for a third party.
    trusted             BOOLEAN NOT NULL DEFAULT FALSE,
    require_pkce        BOOLEAN NOT NULL DEFAULT TRUE,

    status              TEXT NOT NULL DEFAULT 'active',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS oauth_clients_app_idx ON oauth_clients (app_code);

-- Authorization codes. Short-lived, SINGLE-USE, bound to one client and one redirect_uri.
CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
    code                TEXT PRIMARY KEY,          -- stored HASHED, never in the clear
    client_id           TEXT NOT NULL,
    user_id             UUID NOT NULL,
    redirect_uri        TEXT NOT NULL,
    scopes              TEXT[] NOT NULL DEFAULT '{}',
    nonce               TEXT,
    -- PKCE (RFC 7636). Without this, an intercepted code on a public client can be redeemed by the
    -- interceptor; with it, redemption also requires the verifier only the real client holds.
    code_challenge      TEXT,
    code_challenge_method TEXT,
    auth_time           TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ NOT NULL,
    -- Set on redemption. A code presented twice is treated as compromised, not merely stale.
    consumed_at         TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS oauth_codes_expiry_idx ON oauth_authorization_codes (expires_at);
CREATE INDEX IF NOT EXISTS oauth_codes_user_idx ON oauth_authorization_codes (user_id);

-- A person's standing grant to one client. Lets us skip re-consent for scopes already approved, while
-- still forcing a fresh prompt when a client asks for something NEW.
CREATE TABLE IF NOT EXISTS oauth_consents (
    user_id             UUID NOT NULL,
    client_id           TEXT NOT NULL,
    scopes              TEXT[] NOT NULL DEFAULT '{}',
    granted_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, client_id)
);

-- The first-party client: CivicGate's own web app.
INSERT INTO oauth_clients (client_id, name, description, redirect_uris, post_logout_uris,
                           allowed_scopes, app_code, trusted, require_pkce)
VALUES ('civicgate-web', 'CivicGate', 'The CivicGate web application',
        ARRAY['https://www.civicgate.org/auth/callback', 'http://localhost:4321/auth/callback'],
        ARRAY['https://www.civicgate.org/', 'http://localhost:4321/'],
        ARRAY['openid','profile','email','civic:location','civic:interests','civic:positions','civic:activity'],
        'civicgate', TRUE, TRUE)
ON CONFLICT (client_id) DO NOTHING;
