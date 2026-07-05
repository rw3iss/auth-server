-- ─────────────────────────────────────────────────────────────────────────
-- 007: App scoping
--
-- A user-facing app is a consumer of rw3iss auth: a frontend, a backend
-- API, or any client that initiates logins or holds access tokens. Apps
-- declare which permission *services* their tokens should carry; the
-- JWT-issuance path computes the permission union from those services'
-- slices of the catalog.
--
-- service_codes is a Postgres TEXT[] rather than a junction table because
-- the 1:N is shallow (usually 1:1; occasional 1:2 once a future
-- microservice splits out). When the cardinality grows we can promote
-- this to a real junction; the access pattern is "load app row → get
-- code list" either way.
--
-- See: docs/APP_REGISTRATION.md, AUDIT.md §8.3–8.7
-- ─────────────────────────────────────────────────────────────────────────

BEGIN;

CREATE TABLE apps (
    id                       UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    code                     VARCHAR(100) NOT NULL UNIQUE,
    name                     VARCHAR(200) NOT NULL,
    description              TEXT,
    allowed_redirect_urls    TEXT[] NOT NULL DEFAULT '{}',
    service_codes            TEXT[] NOT NULL DEFAULT '{}',
    auto_grant_on_signup     BOOLEAN NOT NULL DEFAULT false,
    status                   VARCHAR(20) NOT NULL DEFAULT 'active',
    metadata                 JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at               TIMESTAMPTZ
);

CREATE INDEX idx_apps_code ON apps(code) WHERE deleted_at IS NULL;
CREATE INDEX idx_apps_status ON apps(status) WHERE deleted_at IS NULL;

CREATE TABLE user_apps (
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    app_id      UUID NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    granted_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    granted_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    status      VARCHAR(20) NOT NULL DEFAULT 'active',   -- active | revoked
    PRIMARY KEY (user_id, app_id)
);

CREATE INDEX idx_user_apps_user ON user_apps(user_id) WHERE status = 'active';
CREATE INDEX idx_user_apps_app  ON user_apps(app_id)  WHERE status = 'active';

-- refresh_tokens + sessions gain an app_id so refresh-token policy is
-- scoped per (user, app, org) instead of per (user, org). Revoking a user
-- from app A no longer affects their app B session.
ALTER TABLE refresh_tokens
    ADD COLUMN app_id UUID REFERENCES apps(id) ON DELETE SET NULL;
ALTER TABLE sessions
    ADD COLUMN app_id UUID REFERENCES apps(id) ON DELETE SET NULL;

CREATE INDEX idx_refresh_tokens_user_app ON refresh_tokens(user_id, app_id)
    WHERE revoked = false;

COMMIT;
