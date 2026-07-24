# new/auth — rw3iss Auth Server (Go)

Standalone multi-tenant authentication and identity service. Single source of truth for users, organizations, roles, permissions, sessions, and refresh tokens across the rw3iss platform. Issues short-lived HS256 JWTs carrying roles + permissions as claims so downstream services (`../../auction/api/`) can validate locally without a network round-trip.

**Status:** production. Phase 1 is feature-complete for password + SSO auth, multi-tenant orgs, refresh-token rotation, rate limiting, session management, and account-security primitives. Integration test coverage via a real-Postgres + real-Redis harness. Horizontally scalable (stateless; shared Redis + Postgres).

**Live at:** `https://auth.ryanweiss.net/` (health: `/health`, API: `/api/v1/...`). Deployed to **ven-internal** EC2 (3.12.0.133) as a native systemd service `auth-server`, port 8090, nginx-fronted. CI/CD via `.github/workflows/deploy.yml` — push to `production` branch -> build + test + scp + restart. See `README.md` §Deployment for the full operator runbook.

---

## Stack

- Go **1.25.5** (`go.mod`)
- Std-lib `net/http` + custom `ServeMux` router (no Gin/Chi/Gorilla — minimal deps)
- PostgreSQL 13+ via `jmoiron/sqlx` + `lib/pq` (no ORM; raw SQL in repositories)
- Raw SQL migrations under `migrations/` (`NNN_name.up.sql` / `.down.sql`)
- `golang-jwt/jwt/v5` for HS256 issue/validate
- `golang.org/x/crypto/bcrypt` for password hashing (cost 12)
- `redis/go-redis/v9` — optional; graceful no-op fallback when unavailable
- Email providers pluggable (SMTP / SendGrid / Mailgun / SES / NoOp) behind `EmailService` interface
- Single static binary via multi-stage Docker (`CGO_ENABLED=0`, `alpine:3.21` runtime)

Entry point: `cmd/server/main.go`. Seed CLI: `cmd/seed/main.go` (not currently used in Phase 1).

---

## Running it

### Docker (recommended for local dev)

```bash
make docker-up        # postgres:5433, redis:6380, auth-server:8080
make docker-logs
make docker-down      # stop, preserve data
make docker-clean     # stop + wipe volumes

curl http://localhost:8080/health    # → {"status":"healthy"}
```

### Native Go (faster iterate loop)

```bash
docker compose up -d postgres redis         # deps only
go run ./cmd/server                         # runs against localhost:5432/6379
# or `air` for hot reload if configured
```

### Build

```bash
make build           # → ./bin/auth-server
./bin/auth-server    # reads .env in cwd
```

### Migrations

They run automatically on Docker startup via `scripts/entrypoint.sh`:
1. Wait for Postgres (30×2s)
2. Apply every `.sql` in `migrations/` in order
3. Non-blocking Redis check (server starts even if Redis is down)

Manual run:

```bash
migrate -path ./migrations \
        -database "postgres://postgres:postgres@localhost:5432/auth?sslmode=disable" up
```

### Tests

```bash
go test ./internal/... -v -count=1        # unit (mocks, no infra)
make test-integration                      # scripts/run-tests.sh — spins up docker deps, runs build-tagged tests
```

Integration tests at `tests/specs/*.go` are tagged `//go:build integration`. They hit a **real** Postgres + Redis (cleaned between runs via helpers in `tests/specs/helpers/setup.go`).

### Ports, env

- Auth server `:8080`, docker-compose Postgres `:5433`, Redis `:6380`.
- API prefix `/api/v1` (configurable via `API_PREFIX`).

**Required env** (no defaults — `config.Validate()` refuses to start without these):

```
DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME, DB_SSL_MODE
JWT_ACCESS_SECRET      # ≥32 chars, shared with ../../auction/api/
JWT_REFRESH_SECRET     # ≥32 chars, must differ from access secret
JWT_ISSUER=ven-auth
```

Boot-time validation also refuses obvious placeholders (`secret`, `changeme`, `test`, etc.) for both secrets, and refuses `CORS_ORIGINS=*` in production.

**Optional** with defaults. Grouped by concern; full list in `internal/config/config.go`.

```bash
# Tokens
JWT_ACCESS_EXPIRY=15m
JWT_REFRESH_EXPIRY=168h          # 7d
JWT_REMEMBER_ME_EXPIRY=720h      # 30d
JWT_AUDIENCE=ven-platform        # validated on every token
JWT_ACCESS_SECRET_PREVIOUS=      # AUDIT C5 — previous-slot for zero-downtime rotation; empty = no rotation in flight
JWT_REFRESH_SECRET_PREVIOUS=     # AUDIT C5 — same, refresh side. Each rotates independently.
AUTH_REFRESH_IDLE_TIMEOUT=0      # Server-side idle policy. When >0, /auth/refresh
                                 # rejects (and family-revokes) any refresh chain
                                 # whose presented row was created more than this
                                 # ago. created_at is "time of last rotation", so
                                 # this measures inactivity of the whole chain.
                                 # 0 (default) = disabled. Pairs with the SDK's
                                 # client-side IdleTracker: SDK gates whether to
                                 # refresh, server enforces by rejecting too-old
                                 # chains even if the SDK lies.

# Password policy
AUTH_PASSWORD_MIN_LENGTH=8
AUTH_PASSWORD_MAX_LENGTH=128     # also enforced inside HashPassword to cap CPU per login
AUTH_PASSWORD_REQUIRE_UPPER=true
AUTH_PASSWORD_REQUIRE_LOWER=true
AUTH_PASSWORD_REQUIRE_DIGIT=true
AUTH_PASSWORD_REQUIRE_SPECIAL=false
BCRYPT_COST=12                   # honored (was ignored pre-A1)

# Rate limiting
RATE_LIMIT_REQUESTS=100          # per-IP per window
RATE_LIMIT_WINDOW=1m
AUTH_ACCOUNT_ATTEMPTS_LIMIT=20   # per-email per window
AUTH_ACCOUNT_ATTEMPTS_WINDOW=1h
TRUSTED_PROXIES=                 # comma-separated CIDRs; empty = ignore XFF

# CORS
CORS_ORIGINS=http://localhost:3001,https://next.ryanweiss.net  # `*` refused in production

# App scoping
AUTH_ALLOW_BASE_USER_LOGIN=false # if true, /auth/login may omit app_code
AUTH_DEFAULT_APP_CODE=           # fallback app_code when login request omits one

# SSO
SSO_GOOGLE_ENABLED=true          # + SSO_GOOGLE_CLIENT_ID / SSO_GOOGLE_CLIENT_SECRET
SSO_APPLE_ENABLED=false          # "Sign in with Apple". Client secret is an ES256
                                 # JWT signed from the .p8 — needs SSO_APPLE_CLIENT_ID
                                 # (Service ID) + SSO_APPLE_TEAM_ID + SSO_APPLE_KEY_ID
                                 # + SSO_APPLE_PRIVATE_KEY (.p8 PEM, raw or base64).
SSO_ALLOWED_REDIRECT_URLS=       # comma-separated; trailing `*` for prefix match

# Audit
AUDIT_ENABLED=true
AUDIT_BUFFER_SIZE=1024

# Cognito auto-migrate (optional drop-in; see docs/How_It_Works.md)
COGNITO_AUTO_MIGRATE_ENABLED=false
COGNITO_REGION=
COGNITO_USER_POOL_ID=
COGNITO_CLIENT_ID=
COGNITO_CLIENT_SECRET=

# Misc
ENVIRONMENT=development
LOG_LEVEL=debug                  # debug | info | warn | error
```

Never commit real secrets — `.env.docker` is dev-only with dummies. Prod secrets live in AWS Secrets Manager / 1Password.

---

## Directory layout

```
cmd/
├── server/main.go        HTTP server entry — boot order: config → logger → DB →
│                         Redis → trusted-proxies → repos → JWT → SSO store +
│                         manager → email → audit writer → scheduler →
│                         services → routes → http.Server
└── seed/main.go          Bootstrap system_admin user (one-shot CLI)

internal/
├── api/
│   ├── dto/              Request/response types (auth.go, organization.go, user.go, role.go, permission.go)
│   ├── handlers/         HTTP handlers (auth, user, organization, permission, app, job)
│   ├── middleware/       Auth + RBAC gates, CORS, rate limiting, logging,
│   │                     bodylimit, idempotency, cookie/CSRF, trusted-proxy IP
│   └── routes/routes.go  Route registration. adminChain = system_admin OR super_admin;
│                         systemAdminChain = system_admin only (apps, perms/register).
│
├── audit/                Async audit-log writer + Postgres sink. Records
│                         login.success/failed, password.change/reset,
│                         logout.all, refresh.reuse_detected,
│                         user.migrated_from_legacy. Drop-on-overflow with a
│                         periodic stats line so silent loss is visible.
│
├── auth/
│   ├── jwt/              HS256 token issue + validate. Purpose-derived secrets
│   │                     for reset/verify (HMAC over access secret).
│   │                     Refresh-token family + theft detection.
│   │                     Per-user token-version (tv claim) for logout-all.
│   │                     App scoping (app_id + app_code claims).
│   └── sso/              OAuth provider adapters + StateStore (Redis-backed
│                         in prod, in-memory fallback) + redirect-URL allowlist.
│
├── background/           Job registry + scheduler. Manageable via /admin/jobs
│                         (list/trigger/pause/resume). Houses the four cleanup
│                         jobs: refresh tokens, sessions, password-reset,
│                         email-verify.
│
├── cache/
│   ├── redis.go          Singleton client, graceful fallback (slog-logged).
│   └── token_cache.go    TokenCache interface: cached claims, blacklist,
│                         rate-limit primitives, per-account attempts,
│                         per-user token-version. RedisTokenCache +
│                         NoOpTokenCache. NoOp silently degrades when Redis
│                         is unavailable — audit logout-all still revokes
│                         refresh tokens via DB; access tokens persist until
│                         natural exp.
│
├── config/config.go      Env loader + Validate(). Boot fails on weak secrets,
│                         out-of-range BCRYPT_COST, DB pool misconfig,
│                         CORS=* in production.
│
├── domain/               Business entities (user, organization, token, role, app).
│
├── email/                EmailService impls (SMTP, SendGrid, Mailgun, SES, NoOp).
│
├── logging/              slog-based structured logger + ctx propagation for
│                         request_id + user_id. JSON in prod, text in dev.
│
├── repository/
│   ├── interfaces.go     Repo contracts (User, Organization, Role, Permission,
│   │                     Invitation, Token, App). Postgres impls implement;
│   │                     other backends could swap in.
│   └── postgres/         sqlx-based implementations.
│                         sort.go = SQL-injection-safe ORDER BY allowlists.
│
└── service/              Business logic orchestration.
    ├── auth/                  package `auth` — the auth DOMAIN service,
    │   │                      split by purpose (one *AuthService; decoupled
    │   │                      from sibling services via the AppDirectory
    │   │                      interface — no parent-package import cycle):
    │   ├── auth_service.go        core: struct/ctor/builders + shared helpers
    │   ├── auth_registration.go   Register (+ per-app webhooks), register-or-login,
    │   │                          email verification send/verify/resend
    │   ├── auth_login.go          Login, RefreshTokens, Logout/All, own sessions
    │   ├── auth_sso.go            SSO URL/callback/PKCE exchange, provider list
    │   ├── auth_password.go       reset request/complete, ChangePassword
    │   ├── auth_2fa.go            TOTP setup/enable/disable (AUDIT C4)
    │   ├── auth_admin.go          CheckEmail, AdminSetPassword, Impersonate,
    │   │                          HardDeleteUser, DeleteMyAccount
    │   ├── auth_migration.go      legacy (Cognito) login fallback
    │   └── magic_link_service.go  magic-link request/verify (migration 014)
    ├── user_service.go        user CRUD + role management
    ├── organization_service.go orgs + members + invitations (default org_member fallback)
    ├── role_service.go        role + permission management
    ├── app_service.go         apps + user_apps memberships
    └── email_service.go       interface

pkg/
├── shared/              Exportable models/types/errors/utils.
└── migration/           Legacy-auth migration adapters.
    ├── migration.go     LegacyAuthProvider interface + DefaultRoleMapper.
    └── cognito/         AWS Cognito impl. Only loaded when
                         COGNITO_AUTO_MIGRATE_ENABLED=true.

migrations/              Raw SQL, applied in filename order. Current set:
                         001 initial schema, 002 seed roles+perms,
                         003 demo users, 004 demo orgs,
                         005 service-scoped perms + super_admin rename,
                         006 refresh-token family + theft detection,
                         007 apps + user_apps + refresh_tokens.app_id,
                         008 org:* perms + super_admin + org_member roles,
                         009 permissions.org_assignable + org:roles:* perms,
                         010 users.two_factor_confirmed_at,
                         011 audit-preserving FK relaxation for hard-delete,
                         012 m2m_clients (OAuth2 client_credentials registry),
                         013 per-app registration policy + rw3iss/demo seeds,
                         014 magic links, 015 apps.frontend_url,
                         016 admin role short-form names,
                         017 user pools / namespaces (users.namespace +
                         apps.registration_namespace/read_namespaces; email
                         unique per (namespace, email)) — see docs/USER_POOLS.md,
                         018 user_namespaces membership tags +
                         apps.registration_namespaces (legacy plural).
                         Current model (2026-06-10): apps have ONE default
                         pool (registration_namespace → users.namespace) +
                         other pools (read_namespaces) which are both the
                         login-match set AND the tag set for new users;
                         lookups match home OR tag.
                         019 apps.webhooks, 020 apps.default_role_code +
                         apps.linked_app_codes (§7 auto-provisioning).

scripts/
├── entrypoint.sh        Docker startup: wait-for-DB, migrate, launch.
└── run-tests.sh         Integration test harness.

tests/
├── specs/               Integration tests (`//go:build integration`) +
│                        Cognito migration tests (`//go:build integration_cognito`).
├── .env.test.cognito.example  Template for Cognito test env (gitignored real).
└── README.md            Test layers: unit / integration / integration_cognito.

docker-compose.yml       postgres:5433, redis:6380, auth-server:8080.
Dockerfile               Multi-stage Go build.
Makefile                 build, test, docker-*, migration targets.
```

Package responsibilities in short: `internal/api` = HTTP I/O, `internal/audit` = async event sink, `internal/auth` = crypto, `internal/background` = managed jobs, `internal/cache` = Redis, `internal/config` = env, `internal/domain` = entities, `internal/email` = dispatch, `internal/logging` = structured logger, `internal/repository` = data access, `internal/service` = orchestration. `pkg/migration` = opt-in legacy-auth migration.

---

## How it works

### Request flow

```
client → handler (DTO validate) → service (orchestrate)
        → repository (SQL) → Postgres
                           → cache/Redis (optional)
                           → email service (optional)
```

### Token lifecycle (HS256)

1. **Issue** via `internal/auth/jwt.Service.GenerateTokenPair`:
   - **Access claims**: `{ sub, user_id, email, org_id, app_id, app_code, roles, permissions, tv, exp, iat, nbf, jti, aud, iss }` — 15m TTL.
   - **Refresh claims**: `{ sub, user_id, org_id, token_type: "refresh", tid, exp }` — 7d (or 30d with `remember_me`).
   - Refresh-token row stores `token_hash` + `family_id` + `parent_id` (so reuse detection can revoke the whole chain — AUDIT 1.9).
   - **Purpose-specific tokens** (password reset, email verification) are signed with **distinct secrets** derived from the access secret via HMAC-SHA256(secret, "ven-auth:purpose:<name>"). They carry their own audience (`<issuer>:reset`, `<issuer>:verify`) plus a `purpose` claim — three layers of defense against cross-purpose presentation.

2. **Validate**: every validator opts into audience + issuer + leeway + algorithm checks via preconstructed `jwt.Parser` instances. Downstream services (`../../auction/api/`) verify signature locally using `JWT_ACCESS_SECRET`. When `JWT_ACCESS_SECRET_PREVIOUS` is set (rotation in progress), the validator tries the active secret first and falls back to the previous secret **only on signature mismatch** — non-signature failures (exp/aud/iss) never re-attempt, because the active secret's verdict is final. Refresh tokens use the same pattern with their own slot. For immediate revocation:
   - Per-token: Redis `auth:blacklist:{jti}` (legacy path; rarely needed).
   - Per-user: bump `auth:user_tv:{user_id}` in Redis; outstanding access tokens with `tv` below the current value are rejected at validation time. This is how `LogoutAll` and role changes take immediate effect.

3. **Refresh** (`POST /auth/refresh`): family-aware rotation. Look up the presented row by `tid` claim. If it's already revoked → **family reuse detected** → revoke every live row sharing `family_id` and return `TokenRevoked` (RFC 6819 §5.2.2.3). Otherwise revoke this row, mint a child row carrying the parent's `family_id` and pointing back via `parent_id`. Optional `app_code` and `organization_id` switch app/org context without re-login (membership re-verified each time).

4. **Revoke**: per-session (`revoked=true`), per-user-all (terminate sessions + revoke refresh rows + bump token-version → access tokens cross-replica invalid), or via family revoke when reuse is detected.

### Multi-tenant model

A user has **global identity** + optional memberships in N organizations + optional memberships in M apps. A JWT is scoped to **at most one org + at most one app** at a time:

- No org context → base roles only; no `org_*` claims.
- With org context → base roles ∪ org-scoped roles, plus `org_id`, `org_slug`, `org_name` claims.
- No app context (only when `AUTH_ALLOW_BASE_USER_LOGIN=true`) → base-user mode for tracking/form-submission flows; no `app_*` claims.
- With app context → `app_id` + `app_code` claims; permissions are the union across services in `app.service_codes` plus `core`.

`system_admin` base role implicitly bypasses every gate — platform owner. `super_admin` is a softer cross-org admin (data + ops) that doesn't reach platform internals.

**User pools / namespaces (migration 017).** Orthogonal to orgs: a `users.namespace` places each user in a *pool* (default `default`), and email is unique **per (namespace, email)** — the same address can be a distinct identity in two pools. An app opts in via `apps.registration_namespace` (the WRITE pool new registrants land in) + `apps.read_namespaces` (the READ pools login/register authenticate against; the write pool is always readable). Unconfigured apps read+write `default` ⇒ identical to pre-017. So an app can capture *new* users into its own pool while still recognizing *existing* users from shared pools (no duplicate identity). `Login` resolves the app — hence its read pools — *before* the user lookup; `Register` writes to the app's write pool but dedupes across its read pools. Full design + worked examples: `docs/USER_POOLS.md`.

### RBAC

Seeded roles (migrations `002_seed_data.up.sql` + `008_org_perms_and_super_admin.up.sql`), ordered by privilege (lower `level` = more privileged):

| Code | Level | Scope | Use |
|---|---|---|---|
| `system_admin` | 0 | platform | Platform owner; bypass everywhere. Reserved — never auto-granted via migration. |
| `super_admin` | 5 | platform | Cross-org data administration (users, orgs, members, jobs). Cannot register apps or services. |
| `org_admin` | 10 | org | Full admin within one organization. |
| `org_manager` | 20 | org | Manages users + their roles in the org. |
| `org_member` | 80 | org | Fallback role on `AddMember` when no specific role specified — read-only org access. |
| `base_user` | 100 | platform | Default for any registered user without org context. |

Permissions are `resource:action` strings. Two parallel namespaces:

- `organizations:*`, `users:*`, etc. — **platform-admin** scope, gated to `system_admin` / `super_admin` on `/admin/*` routes.
- `org:*` (`org:read`, `org:update`, `org:members:invite`, etc.) — **org self-service** scope, gated by `RequireOrgContext + RequirePermission` on `/orgs/{orgId}/*` routes.

Each consuming service self-registers its slice of the catalog via `POST /admin/permissions/register { service, permissions }`. The auth-server reconciles — upserts + prunes — so a service's catalog stays in sync with what it actually exposes.

Custom per-org roles (AUDIT C3) are implemented under `/orgs/{orgId}/roles`. An org admin (or system/super admin) can create custom roles inside their org with a curated set of permissions. The `permissions.org_assignable` boolean column gates which permissions are eligible to be granted from a custom role; system-level permissions (`organizations:delete`, `users:impersonate`, …) stay reserved to platform admins even when an org admin authors a custom role. System role codes are reserved and refuse to be shadowed.

### App scoping

Migration 007 introduced first-class consuming apps. Every `/auth/login` request resolves an `app_code` to an `apps` row; the issued token carries `app_id` + `app_code`. See `docs/APP_REGISTRATION.md` for the full onboarding flow.

Key behaviors:
- `app_code` required by default. Falls back to `AUTH_DEFAULT_APP_CODE` when not supplied; otherwise rejected unless `AUTH_ALLOW_BASE_USER_LOGIN=true` (base-user mode for tracking).
- User must have an active `user_apps` membership. Apps with `auto_grant_on_signup=true` self-grant on first login.
- Token's `permissions` claim is the union across services in `app.service_codes` plus `core`. `service_codes` defaults to `[app.code]` for the 1:1 common case.
- **Auto-provisioning (§7, migration 020).** On first contact through an `auto_grant_on_signup` app (register / first login / JIT migration), `AuthService.ensureAppEntitlements` (in `auth_entitlements.go`) idempotently grants `user_apps` for the app **and** each `apps.linked_app_codes`, and — when `default_organization_id` is set — an org membership with `apps.default_role_code` (default `org_member`; platform roles refused). A client may override per request via `role_code` + `linked_app_codes` in the login/register body; `role_code` is re-validated as an org-scoped role server-side (no privilege escalation). All steps are idempotent + best-effort (failures logged, never block login).

### SSO

Supported providers in `internal/auth/sso/`: **Google, Apple, Facebook, LinkedIn, Custom** are implemented + registered; Microsoft / GitHub are config-recognized but log "not implemented" at boot (no adapter yet). Facebook is OAuth2 + Graph `/me` (email optional — tolerated like Apple); LinkedIn is OIDC via the userinfo endpoint. Both honor the app-context user-pool upsert (write namespace + tag + auto-grant). All off by default — enable per-provider with `SSO_<PROVIDER>_ENABLED=true` + credentials. **Apple** verifies the id_token signature against Apple's JWKS (RS256, cached 1h), signs the client secret as an ES256 JWT from the `.p8` key, handles `response_mode=form_post`, and captures the name from the first-login `user` field (tolerating its absence on later logins). The SSO callback resolves the consuming app via `X-App-Code` (carried through the SSO `state`) and upserts the user into the app's user pool (write namespace + tags + auto-grant).

Flow:
1. `POST /api/v1/auth/sso/url { provider, redirect_url, organization_id?, invite_code?, code_challenge?, code_challenge_method? }` → server validates the redirect URL against `SSO_ALLOWED_REDIRECT_URLS`, mints opaque state (Redis-backed when Redis is connected; in-memory fallback otherwise, 10m TTL), returns `{ auth_url, state }`. Public clients **should** pass PKCE fields (AUDIT C2); confidential clients (server-to-server) can omit.
2. Client navigates to `auth_url`; provider redirects back to `redirect_url` with `?code=...&state=...`.
3. `GET|POST /api/v1/auth/sso/callback` consumes state atomically (Redis `GETDEL` or single-locked in-memory), exchanges code with the provider, fetches user info, upserts user + `user_auth_providers` row. **Terminal branch depends on PKCE:** if the original `/sso/url` carried a challenge, the callback returns `{ auth_code, expires_in: 60 }` and **defers token issuance**; otherwise it returns `{ user, tokens, ... }` as before.
4. (PKCE only) `POST /api/v1/auth/sso/exchange { auth_code, code_verifier }` → server consumes the one-shot auth_code (Redis `GETDEL` or in-memory mutex), verifies `BASE64URL(SHA256(verifier)) == stored challenge`, mints token pair from fresh user/org/role state, returns `{ user, tokens, ... }`.

Per-org custom SSO providers are schema-prepared (`organizations.sso_provider` / `sso_config`) but the manager isn't wired yet.

### Cognito auto-migrate (optional)

When `COGNITO_AUTO_MIGRATE_ENABLED=true` and a pool is configured, `AuthService.Login` consults `pkg/migration/cognito` as a fallback when the email isn't in the internal store. On successful Cognito authentication the user is auto-created locally with the submitted password (bcrypt-hashed), legacy roles mapped via `DefaultRoleMapper` (Cognito `SUPER_ADMIN` → internal `super_admin`; `SYSTEM_ADMIN` always dropped). Failures surface as a plain `InvalidCredentials` — never reveal which side broke.

Drop-in: the auth-server core has zero AWS SDK dependency at runtime when the flag is off.

**Per-app legacy providers (JIT migration, §5).** Beyond the single global Cognito fallback, providers can be registered per `app_code` via `AuthService.WithLegacyAuthFor(appCode, provider, mapper)` — each consuming app brings its own `migration.LegacyAuthProvider`. **GlobalSKU** (`pkg/migration/globalsku`) is wired this way: enabled by `GLOBALSKU_LEGACY_MIGRATION_ENABLED`, it verifies a live password attempt against GlobalSKU's HMAC-signed `POST /api/internal/verify-legacy-password` (headers `X-Auth-Timestamp` + `X-Auth-Signature`, secret = `GLOBALSKU_LEGACY_VERIFY_SECRET`); a `{valid:true}` response migrates the user (passwordless GlobalSKU — the typed password is bcrypt-hashed locally), `{valid:false}` → clean `InvalidCredentials`, and 401/5xx fail the login closed. On login, the app-specific provider wins, falling back to the global one; an app with neither pays zero cost. A JIT-migrated user is provisioned into the **app's write pool + namespace tags** (not bare `default`). If the email already exists in the auth-server but the submitted password authenticates against the legacy store with *different* internal creds, login halts with **`LEGACY_MIGRATION_CONFLICT`** (409, carries `email` + `app_code`) rather than overwriting either side. The GlobalSKU adapter itself is not yet built — it needs a signed `verify-legacy-password` endpoint on GlobalSKU; wire it in `cmd/server/main.go` once that exists.

---

## API surface

Base path: `${API_PREFIX}` (default `/api/v1`).

**Public auth** (no token):

| Method | Path | Purpose |
|---|---|---|
| POST | `/auth/register` | Create account. `mode` field: `register` (default) / `register_or_login` / `register_or_return` (service-only). Optional `app_code`, `organization_name`, `invite_code`, `invite_token`. |
| POST | `/auth/login` | Password login. `app_code` required unless `AUTH_ALLOW_BASE_USER_LOGIN` is true. Optional `organization_id`, `remember_me`, `two_factor_code`. Responds 401 + `{requires_2fa: true}` when account has 2FA active and code is missing/wrong. |
| POST | `/auth/refresh` | Refresh tokens (family-aware rotation). Optional `organization_id` / `app_code` for context switching. |
| POST | `/auth/logout` | Revoke current refresh token. **Authenticated** (AUDIT 1.23) — caller's bearer must match the refresh token's user. |
| POST | `/auth/password/reset-request` | Request password reset email. |
| POST | `/auth/password/reset` | Complete password reset (single-use — AUDIT 1.1). |
| GET\|POST | `/auth/verify-email` | Verify email via token (single-use — AUDIT 1.2). |
| POST | `/auth/verify-email/resend` | Re-issue a verification token (AUDIT 5.4). Always 200 to avoid email enumeration. |
| POST | `/auth/sso/url` | Get OAuth URL (redirect URL allowlisted — AUDIT 1.13). Optional PKCE: `code_challenge` + `code_challenge_method=S256`. |
| GET\|POST | `/auth/sso/callback` | OAuth callback (atomic state validation — AUDIT 1.14). Returns `{ auth_code, expires_in }` instead of tokens when PKCE was initiated. |
| POST | `/auth/sso/exchange` | Redeem a PKCE `auth_code` for a token pair using `code_verifier` (AUDIT C2). |
| GET | `/auth/sso/providers` | List enabled providers. |
| POST | `/auth/validate` | Validate an access token (for services without the secret). |
| POST | `/oauth/token` | OAuth2 client_credentials grant (RFC 6749 §4.4). Body: `grant_type=client_credentials`, `client_id`, `client_secret`, optional `scope`. Accepts form-encoded (spec) or JSON. Issues a service-principal token (`token_type: "service"`); failures collapse to a single `invalid_client` envelope to prevent enumeration. |

**Protected** (`Authorization: Bearer`):

| Method | Path | Purpose |
|---|---|---|
| GET | `/auth/me` | Current user + roles/permissions/org/app context. |
| POST | `/auth/password/change` | Change password. |
| POST | `/auth/logout/all` | Revoke refresh tokens + bump token-version (AUDIT 1.10). |
| POST | `/auth/2fa/setup` | Begin TOTP enrollment — returns provisioning URI + base32 secret (AUDIT C4). |
| POST | `/auth/2fa/enable` | Submit the first TOTP code to complete enrollment. |
| POST | `/auth/2fa/disable` | Turn 2FA off — requires password + current code. |
| GET | `/auth/sessions` | List active sessions. |
| DELETE | `/auth/sessions/{sessionId}` | Terminate one session. |
| GET | `/me/apps` | List app memberships for the current user. |
| GET | `/me/orgs` | List organization memberships for the current user. Self-service mirror of `/me/apps`; shape matches `/admin/users/{id}/organizations` so shared renderers work. |
| GET | `/me/invitations` | List pending invitations addressed to the authenticated user's email. |
| POST | `/me/invitations/{id}/accept` | Accept a pending invitation. Verifies email match server-side (constant-time NotFound on mismatch). Creates org_member + assigns roles. |
| POST | `/me/invitations/{id}/decline` | Decline a pending invitation. Same email-match guard. |

**Service-only** (`system_admin` token; future M2M):

| Method | Path | Purpose |
|---|---|---|
| POST | `/auth/check-email` | `{exists: bool}`. Gated to service callers; never exposed to public clients (AUDIT 8.2). |
| POST | `/auth/admin/set-password` | Set a user's password without current-password check. |

**Org self-service** (`RequireOrgContext` + per-action permission; `system_admin` bypasses):

| Method | Path | Permission |
|---|---|---|
| GET | `/orgs/{orgId}` | `org:read` |
| PUT | `/orgs/{orgId}` | `org:update` |
| GET | `/orgs/{orgId}/members` | `org:members:read` |
| POST | `/orgs/{orgId}/members` | `org:members:invite` |
| DELETE | `/orgs/{orgId}/members/{userId}` | `org:members:remove` |
| PUT | `/orgs/{orgId}/members/{userId}/status` | `org:members:update` |
| GET | `/orgs/{orgId}/roles` | `org:roles:read` |
| GET | `/orgs/{orgId}/roles/{roleId}` | `org:roles:read` |
| POST | `/orgs/{orgId}/roles` | `org:roles:create` |
| PUT | `/orgs/{orgId}/roles/{roleId}` | `org:roles:update` |
| DELETE | `/orgs/{orgId}/roles/{roleId}` | `org:roles:delete` |
| GET | `/orgs/{orgId}/permissions/assignable` | `org:roles:read` |
| POST | `/orgs/{orgId}/invitations` | `org:members:invite` — invite by email. Creates invitation row + sends email synchronously. |
| GET | `/orgs/{orgId}/invitations` | `org:members:read` — list pending invitations for the org. |
| DELETE | `/orgs/{orgId}/invitations/{id}` | `org:members:invite` — revoke a pending invitation. |

**Admin** (`system_admin` OR `super_admin` for data ops; `system_admin` only for platform internals):

- `/admin/users` — list, get, roles, orgs, list all roles, session management (data ops). Session ops: `GET /admin/users/{userId}/sessions` lists a target user's active sessions; `DELETE /admin/users/{userId}/sessions/{sessionId}` terminates one; `POST /admin/users/{userId}/revoke-sessions` terminates every session at once (bumps token-version cross-replica). `POST /admin/users/lookup` (AUTH-PHP-LARAVEL-DESIGN §5): bulk-resolve users by `{ emails?, ids? }` in a single round-trip; up to 200 keys combined; soft-deleted users excluded; returns each user's `namespace` for pool disambiguation. `POST /admin/users/bulk-import` (**system_admin only**; GlobalSKU integration §4): import users with **pre-hashed** passwords stored verbatim (bcrypt verifies on the normal login path immediately — no reset). Body `{ app_code?, default_namespace?, update?, users: [{ email, password_hash, hash_algo?, first_name?, last_name?, namespace_tags? }] }`; idempotent upsert keyed by (namespace, email); ≤500 rows/request; per-row `{ status: created|updated|skipped|error, uid }` so the caller backfills its own FK (e.g. GlobalSKU `ven_user_id`). Hash formats are pluggable via `internal/auth/password` (bcrypt default). `POST /admin/users/{userId}/impersonate` (AUDIT C7): authenticated callers only; service-layer gate allows `system_admin` / `super_admin` for any target, `org_admin` for targets in their org. `DELETE /admin/users/{userId}/hard` (AUDIT C8): system_admin only; refuses self-delete + users who own orgs (operator must transfer ownership first). Audit-preserving FKs from migration 011 keep historical audit_log / invitation rows alive with NULL user pointers.
- `/admin/organizations` — CRUD + members (data ops). `PUT .../members/{userId}/roles` replaces a member's org-role set (set semantics; org-scoped roles only) — backs org-admin reassignment UIs. `GET /admin/users` supports `?organization_id=` and `?app_id=` membership filters (fixed/added 2026-06-10 — previously parsed but never applied).
- `/admin/jobs` — list / get / trigger / pause / resume background jobs (data ops).
- `/admin/apps` — CRUD apps + grant/revoke `user_apps` membership (**system_admin only**).
  - **Per-app webhooks (migration 019, 2026-06-11):** `apps.webhooks` JSONB — `[{name, url, events, enabled}]`, settable on create + PATCH (non-nil replaces the whole list). On NEW-user registration through an app, the server fans `user.registered` out to every enabled subscribed hook: async goroutines, 3 attempts (5s timeout each, linear backoff, permanent-4xx no-retry), never blocks/fails the registration. Payload = event + app + user (incl. pools) + org + the FULL registration body (password redacted, extra/unknown client fields passed through verbatim) + request context (ip, user-agent, issuer). `hooks.slack.com` URLs get a Slack-formatted `{"text"}` summary instead; everyone else gets the JSON envelope + `X-rw3iss-Event` header. Dispatch code: `internal/webhooks/app_webhooks.go`; wiring: `AuthService.dispatchRegistrationWebhooks`. `GET /admin/users/{userId}/apps` lists a user's memberships (adminChain). PATCH also accepts the registration-policy fields (`frontend_url` — "" clears to NULL, `allowed_email_domains`, `allowed_auth_methods`, `default_organization_id` — "" clears) since 2026-06-10; only `code` stays immutable.
- `/admin/namespaces` + `/admin/users/{userId}/namespace(s)` — user-pool administration (**system_admin only**, 2026-06-10). `GET /admin/namespaces` aggregates every pool (users by home/tag + referencing app codes; zero-user pools included). Per-user: `GET .../namespaces` (home + tags), `PUT .../namespace` (move home pool; 409 on per-pool email conflict; redundant tag cleaned), `POST .../namespaces` + `DELETE .../namespaces/{ns}` (tags; the home pool is refused — move it instead).
- `/admin/permissions/register` — service self-registration (**system_admin only**).
- `/admin/m2m-clients` — OAuth2 client_credentials registry. `POST` creates a client (returns plaintext secret ONCE); `GET` lists non-revoked; `GET /{id}` fetches one; `DELETE /{id}` soft-revokes. **system_admin only** — these credentials authorize platform-internal service calls and live below every other admin tier. Backed by migration 012 (`m2m_clients` table). Closes the `AUTH_REGISTRATION_TOKEN` shim noted in `auth-server-client/README.md`.

**Health:** `GET /health` → `{"status":"healthy"}`.

---

## Integration points

### With `../../auction/api/` (NestJS)

- **Shared Postgres** (db name `auth`). Auth owns: `users`, `organizations`, `organization_members`, `roles`, `permissions`, `refresh_tokens`, `sessions`, `user_auth_providers`, `invitations`. `../../auction/api/` reads from these via raw SQL. Schema changes are joint PRs; never let the API run migrations against these tables.
- **Shared JWT secrets** (`JWT_ACCESS_SECRET`, `JWT_REFRESH_SECRET`). The API validates tokens locally — no per-request call to this service.
- **Optional revocation check** via Redis `auth:blacklist:{jti}` for immediate logouts before expiry.
- **Fallback endpoint:** `POST /auth/validate` for consumers that don't share the secret.

### With `../../auction/client/` (Preact)

- Standard OAuth + email/password flow against `/api/v1/auth/*`.
- Tokens returned as `{ access_token, refresh_token, token_type, expires_in, expires_at }`.
- **Cognito migration**: handled server-side via `pkg/migration/cognito` (auto-fallback during `/auth/login` when the email isn't in the internal store yet — opt-in via `COGNITO_AUTO_MIGRATE_ENABLED`). The client doesn't need a header for this; it works transparently. The previous header-based bridge has been replaced.

### With `../../auction/shared/`

- `../../auction/shared/` is TS-only, so the Go server can't consume it. Instead, `pkg/shared/` and `internal/domain/` mirror the TS contracts (notably `JwtPayload` in `../../auction/shared/src/auth/jwt.ts` mirrors this server's token claims). Any change to token shape needs coordinated updates on both sides.

---

## Gotchas

1. **Migrations are one-way via filename order.** Add new files as `NNN_description.up.sql` / `.down.sql`. No UI rollback — use `migrate` CLI or manual SQL. Never alter API-owned tables from here.
2. **TTL surprises.** Access 15m, refresh 7d (30d with `remember_me`), password reset 1h, email verify 24h, invitation 7d, account lockout 15m after 5 failed attempts. Per-account rate limit window: 1h / 20 attempts.
3. **Secrets rotation is dual-slot.** Set `JWT_ACCESS_SECRET_PREVIOUS` / `JWT_REFRESH_SECRET_PREVIOUS` to the old values while rolling in the new ones — validators try active first, fall back to previous on signature mismatch only. Signing always uses active. Purpose-derived secrets (reset/verify) rotate in lockstep with the access master because the previous-slot also derives its own parallel pair. Clear the previous-slot env after max-token-lifetime (7d / 30d remember-me) to complete the rotation. See `docs/Development.md` for the runbook.
4. **Per-IP rate limiter falls open in-memory when Redis is unavailable.** Per-account limiter (`auth:account_attempts:*`) is Redis-only and degrades to "no per-account cap" when Redis is down — refresh-token revocation still works via DB. Multi-replica deployments **need** Redis to be effective.
5. **Redis is optional, not critical.** If down: token cache becomes no-op (signature-only validation downstream), token-version invalidation can't take effect (access tokens persist to natural exp), SSO state falls back to in-memory (single-replica only), idempotency middleware passes through. Server boots fine.
6. **Email is synchronous.** Sends happen inside handlers — a slow provider slows the response. Async goroutine dispatch is on the roadmap.
7. **Email templates are operator-provided.** Not in repo; point `EMAIL_TEMPLATES_PATH` at your HTML files.
8. **SSO state uses Redis when connected.** Atomic GETDEL prevents double-submit races (AUDIT 1.14). Falls back to single-mutex in-memory when Redis is down. Server restart with in-memory state = user retries login.
9. **React strict-mode double-mount** can cause SSO callback double-invocation; atomic state validation now handles this server-side, but be aware client-side that two requests may hit before the second sees the state cleared.
10. **No OIDC / JWKS endpoint.** First-party only, HS256. Adding OIDC support is a significant refactor.
11. **TOTP 2FA** lives at `/auth/2fa/{setup,enable,disable}` (AUDIT C4). Setup writes the secret + flags `two_factor_enabled=true` but defers requiring 2FA at login until Enable stamps `two_factor_confirmed_at`. Login that hits an active-2FA account returns 401 `{requires_2fa: true}` when `two_factor_code` is missing or wrong; clients resubmit with the code populated. Disable requires password AND code, bumps the user's token-version. Secret is stored plaintext in `users.two_factor_secret`; encryption-at-rest with a KEK is a follow-up.
12. **Integration tests have two layers.** `//go:build integration` runs against Docker Postgres + Redis. `//go:build integration_cognito` runs against a real AWS Cognito pool; skips silently when `tests/.env.test.cognito` isn't present. See `tests/README.md`.
13. **Cognito `PreventUserExistenceErrors`** (default on) collapses not-found and wrong-password into the same NotAuthorizedException. The migration adapter handles both shapes; AuthService surfaces InvalidCredentials regardless so the response shape never leaks.
14. **The `tv` claim is your immediate-logout primitive.** Bump `auth:user_tv:{user_id}` to invalidate every outstanding access token for that user cross-replica. `LogoutAll` does this automatically. When Redis is down, falls back to refresh-token revocation only.
15. **`system_admin` vs `super_admin`.** `system_admin` is a bypass on every gate (platform owner). `super_admin` is permission-based — it can use `/admin/users/*`, `/admin/organizations/*`, `/admin/jobs/*` (gated by `RequirePlatformAdmin`) but cannot reach `/admin/apps/*`, `/admin/permissions/register`, or `/admin/m2m-clients/*` (gated by `RequireSystemAdmin`). M2M client credentials in particular live below every other admin tier — mistakenly delegating them to `super_admin` would let a data-tier role mint credentials capable of executing `system_admin`-level actions.

---

## Roadmap (not yet implemented)

- Per-org custom SSO providers — schema ready, design stub in `internal/auth/sso/per_org.go` (AUDIT C9)
- Async email via background goroutine
- Webhook events — interface stub in `internal/webhooks/` (AUDIT C6); no live dispatch yet
- Rate-limit IP whitelisting / trusted-tester bypass

---

## Docs

- `README.md` — overview
- `Quickstart.md` — minimal setup
- `docs/Development.md` — setup, workflow, migration policy, shared-DB ownership
- `docs/How_It_Works.md` — architecture, token lifecycle, multi-tenant model, SSO
- `docs/APP_REGISTRATION.md` — onboarding a new consuming app (CLI + API)
- `docs/USER_POOLS.md` — user pools / namespaces (migration 017): read/write pool config, register/login semantics, worked examples
- `tests/README.md` — test layers (unit / integration / integration_cognito) + Cognito harness setup
- `.claude/audits/AUDIT-2026-05-11.md` — closed security audit (originally written 2026-05-02; all Phases A–D verified complete on 2026-05-11). All Critical / High findings closed; remaining items deferred-by-design (orchestrator restart strategy, platform-layer metrics) or design-only stubs (webhooks, per-org SSO).
