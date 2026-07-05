# Development — Vendidit Auth Server

Deeper development reference for `new/auth`. For the high-level architecture see [`How_It_Works.md`](./How_It_Works.md) and the canonical reference [`../README.md`](../README.md).

---

## 1. Prerequisites

- **Go 1.25+** (strict — the module uses `go 1.25` in `go.mod`).
- **Docker + Docker Compose** for running Postgres + Redis locally.
- **golang-migrate CLI** (optional — `docker-compose` runs migrations via the entrypoint script automatically).
- **`make`** — every common operation is wrapped in a Makefile target.

If you only want to run the full stack and not touch Go code, Docker alone is enough.

---

## 2. Initial setup

```bash
cd new/auth

# Bring up Postgres (:5432), Redis (:6379), auth server (:8080)
make docker-up
```

On first boot, the entrypoint waits for Postgres to be ready and runs all migrations (`migrations/*.up.sql`), which creates the schema and seeds the default roles + permissions.

Verify:

```bash
curl http://localhost:8080/health
# → {"status":"healthy"}
```

Create a test user:

```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
    -H "Content-Type: application/json" \
    -d '{
        "email": "test@vendidit.com",
        "password": "TestPass123",
        "first_name": "Test",
        "last_name": "User"
    }'
```

---

## 3. Running in development

### Option 1: Everything in Docker (simplest)

```bash
make docker-up       # builds + starts all three containers
make docker-logs     # tail logs from all services
make docker-down     # stop containers (volumes preserved)
make docker-clean    # stop containers + delete volumes (fresh start)
make docker-build    # rebuild the auth-server image (e.g. after a Go code change)
```

### Option 2: Dependencies in Docker, auth server in Go (fastest iteration loop)

```bash
# Start just Postgres + Redis
docker compose up -d postgres redis

# Run the server directly with Go — fast restart on changes
go run ./cmd/server
```

With `air` (a Go reloader; `go install github.com/air-verse/air@latest`):

```bash
air
```

`air` watches `.go` files and rebuilds on save. Config lives in `.air.toml` (not committed in phase 1 — create one locally if you want the reload loop).

### Inspecting Redis state

```bash
# What's in the token cache?
docker exec -it ven-auth-redis redis-cli keys 'auth:*'
docker exec -it ven-auth-redis redis-cli get 'auth:token:<jti>'

# Rate limit counters
docker exec -it ven-auth-redis redis-cli keys 'auth:ratelimit:*'

# Blacklist (revoked tokens still within their natural exp)
docker exec -it ven-auth-redis redis-cli keys 'auth:blacklist:*'
```

### Inspecting Postgres state

```bash
docker exec -it ven-auth-postgres psql -U postgres -d auth

# Once in psql:
\dt                                  -- list tables
SELECT email, status FROM users;
SELECT * FROM organizations;
SELECT * FROM refresh_tokens WHERE revoked = false ORDER BY created_at DESC LIMIT 10;
```

---

## 4. Scripts and Makefile targets

| Target | What it does |
|---|---|
| `make docker-up` | Build images + start Postgres, Redis, auth-server. Runs migrations on first boot. |
| `make docker-down` | Stop containers. Volumes preserved. |
| `make docker-clean` | Stop containers + delete volumes. Next `docker-up` is a fresh install. |
| `make docker-build` | Rebuild the auth-server Docker image (after Go code changes). |
| `make docker-logs` | Tail logs from all three containers. |
| `make test` | Run Go unit tests with `go test ./... -short` (no DB required). |
| `make test-integration` | Run integration tests via `scripts/run-tests.sh` — starts Postgres + Redis, sets env vars, runs `go test ./tests/... -v -tags=integration`, cleans up. |
| `make migrate` | Manually run pending migrations (only needed if you skipped the entrypoint). |
| `make build` | `go build -o bin/auth-server ./cmd/server` — local binary. |
| `make lint` | `golangci-lint run` (install separately). |
| `make fmt` | `gofmt -w .` |

### Running a single test

```bash
# By name
go test ./tests/... -v -run TestAuthRegister

# By file
go test ./tests/auth_login_test.go -v

# With integration tag (requires Docker deps up)
go test ./tests/... -v -tags=integration -count=1
```

### Running tests against dependencies manually (faster iteration)

```bash
# Start deps once
docker compose up -d postgres redis

# Set env vars (these match the defaults in .env.docker)
export DB_HOST=localhost DB_PORT=5432 DB_USER=postgres DB_PASSWORD=postgres DB_NAME=auth DB_SSL_MODE=disable
export REDIS_HOST=localhost REDIS_PORT=6379
export JWT_ACCESS_SECRET=dev-access-secret-key-change-in-production-minimum-32-chars
export JWT_REFRESH_SECRET=dev-refresh-secret-key-change-in-production-minimum-32-chars
export RATE_LIMIT_REQUESTS=1000 RATE_LIMIT_WINDOW=1m

# Run tests repeatedly without restarting deps
go test ./tests/... -v -tags=integration -count=1
```

---

## 5. Environment variables

All config lives in `internal/config/config.go` and is loaded from env vars via `github.com/joho/godotenv`. A `.env.docker` template ships with the repo for the Docker Compose stack.

### Required

```env
# Database
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=postgres
DB_NAME=auth
DB_SSL_MODE=disable

# JWT signing secrets — MUST be at least 32 chars
JWT_ACCESS_SECRET=<long random secret>
JWT_REFRESH_SECRET=<another long random secret>
JWT_ISSUER=ven-auth
JWT_AUDIENCE=ven-platform

# HTTP
SERVER_PORT=8080
API_PREFIX=/api/v1
```

### Optional

```env
# Redis (graceful fallback if omitted)
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_DB=0

# JWT lifetimes
JWT_ACCESS_EXPIRY=15m
JWT_REFRESH_EXPIRY=168h
JWT_REMEMBER_ME_EXPIRY=720h

# Password reset / email verify lifetimes
AUTH_PASSWORD_RESET_EXPIRY=1h
EMAIL_VERIFICATION_EXPIRY=24h
AUTH_INVITATION_EXPIRY=168h

# Password policy
AUTH_PASSWORD_MIN_LENGTH=8
AUTH_PASSWORD_MAX_LENGTH=128
AUTH_PASSWORD_REQUIRE_UPPER=true
AUTH_PASSWORD_REQUIRE_LOWER=true
AUTH_PASSWORD_REQUIRE_DIGIT=true
AUTH_PASSWORD_REQUIRE_SPECIAL=false
BCRYPT_COST=12

# Rate limiting
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=1m
AUTH_ACCOUNT_ATTEMPTS_LIMIT=20      # per-account login limit
AUTH_ACCOUNT_ATTEMPTS_WINDOW=1h

# Trusted proxies (comma-separated CIDRs). Empty = ignore X-Forwarded-For.
TRUSTED_PROXIES=

# App scoping
AUTH_ALLOW_BASE_USER_LOGIN=false    # if true, /auth/login may omit app_code
AUTH_DEFAULT_APP_CODE=

# Email provider
EMAIL_PROVIDER=smtp           # 'smtp' | 'sendgrid' | 'mailgun' | 'ses' | 'noop'
EMAIL_FROM_ADDRESS=noreply@vendidit.com
EMAIL_FROM_NAME=Vendidit
EMAIL_TEMPLATES_PATH=./templates/email
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
SMTP_SECURE=true
CLIENT_URL=http://localhost:3001

# SSO providers (enabled flags + credentials)
SSO_GOOGLE_ENABLED=false
SSO_GOOGLE_CLIENT_ID=
SSO_GOOGLE_CLIENT_SECRET=
SSO_GOOGLE_REDIRECT_URL=http://localhost:8080/api/v1/auth/sso/callback
SSO_GOOGLE_SCOPES=openid,email,profile

SSO_APPLE_ENABLED=false
SSO_APPLE_CLIENT_ID=
SSO_APPLE_CLIENT_SECRET=
SSO_APPLE_TEAM_ID=
SSO_APPLE_KEY_ID=
SSO_APPLE_PRIVATE_KEY=

SSO_MICROSOFT_ENABLED=false
SSO_MICROSOFT_CLIENT_ID=
SSO_MICROSOFT_CLIENT_SECRET=

SSO_GITHUB_ENABLED=false
SSO_GITHUB_CLIENT_ID=
SSO_GITHUB_CLIENT_SECRET=

# SSO redirect URL allowlist (AUDIT 1.13). Exact match or trailing `*`
# for prefix match. Empty = accept anything (dev only).
SSO_ALLOWED_REDIRECT_URLS=

# Audit log writer
AUDIT_ENABLED=true
AUDIT_BUFFER_SIZE=1024

# Cognito auto-migrate adapter (drop-in; off by default)
COGNITO_AUTO_MIGRATE_ENABLED=false
COGNITO_REGION=
COGNITO_USER_POOL_ID=
COGNITO_CLIENT_ID=
COGNITO_CLIENT_SECRET=

# CORS — refuse `*` in production
CORS_ORIGINS=http://localhost:3001,https://next.vendidit.com

# Logging
LOG_LEVEL=debug                # debug | info | warn | error
```

### Secret hygiene

- **Never commit production secrets.** `.env.docker` is a dev-only template with obviously-fake values.
- Production secrets live in 1Password + the deployment platform's secret manager (AWS Secrets Manager, SSM Parameter Store, etc.).
- **The JWT secrets are the crown jewels.** If one leaks, every issued token is compromised. Rotation procedure is in section 9.

---

## 6. Database migrations

Migrations live in `migrations/*.up.sql` + `migrations/*.down.sql`, numbered + named. Current set:

```
migrations/
├── 001_initial_schema                            schema (users, orgs, roles, perms, tokens, sessions, ...)
├── 002_seed_data                                 system_admin / org_admin / seller / buyer / base_user + perm catalog
├── 003_demo_users                                seeded demo accounts
├── 004_demo_organizations                        seeded demo orgs
├── 005_service_scoped_permissions_and_sysadmin_rename
│                                                 permissions.service column; renamed super_admin → system_admin
├── 006_refresh_token_family                      family_id + parent_id on refresh_tokens (AUDIT 1.9)
├── 007_apps                                      apps + user_apps tables; app_id on refresh_tokens + sessions
└── 008_org_perms_and_super_admin                 org:* catalog + super_admin (level 5) + org_member fallback
```

### Applying migrations

The Docker entrypoint runs migrations automatically on container start. To run them manually:

```bash
# Using golang-migrate (install: brew install golang-migrate)
migrate -path ./migrations \
        -database "postgres://postgres:postgres@localhost:5432/auth?sslmode=disable" \
        up

# Or from inside the auth-server container:
docker exec -it ven-auth-server ./scripts/entrypoint.sh migrate-only
```

### Creating a new migration

```bash
# Next number is 003
touch migrations/003_add_two_factor_totp.up.sql
touch migrations/003_add_two_factor_totp.down.sql
```

Write raw SQL. No ORM. No code generation. Two rules:

1. **Always write a `.down.sql`** that reverses the `.up.sql`. Even if you're confident you won't roll back. Untested rollbacks fail.
2. **Never alter a `new/api`-owned table.** If you need a change that crosses the project boundary, coordinate it as a joint PR against both projects.

### Rolling back

```bash
migrate -path ./migrations \
        -database "postgres://postgres:postgres@localhost:5432/auth?sslmode=disable" \
        down 1
```

In production, rollbacks are a manual procedure run by an admin with DB credentials. See section 9.

---

## 7. Adding a feature

### Example: TOTP 2FA

The schema already has `users.two_factor_enabled` + `users.two_factor_secret` fields from migration 001. To wire up the flow:

1. **Add endpoints** in `internal/api/routes/routes.go`:
    ```
    POST   /auth/2fa/enroll         (protected — generates + returns a TOTP secret)
    POST   /auth/2fa/verify         (protected — confirms the code, enables 2FA)
    POST   /auth/2fa/disable        (protected — disables 2FA)
    ```
2. **Add handler** in `internal/api/handlers/2fa_handler.go` implementing enrollment + verification.
3. **Update login flow** in `internal/api/handlers/auth_handler.go` — if a user has `two_factor_enabled=true`, the login response includes `{ challenge: "2fa_required", challenge_token }`, and a separate `POST /auth/2fa/login` endpoint takes `{ challenge_token, code }` and issues the real token pair.
4. **Add DTOs** in `internal/api/dto/auth.go` for all of the above.
5. **Add unit tests** in `internal/auth/totp/` for the TOTP library integration.
6. **Add integration tests** in `tests/auth_2fa_test.go`.
7. **Update the client** in `new/client`'s `AuthModule.login()` to handle the new `2fa_required` challenge response.

### Example: New SSO provider (LinkedIn)

1. Implement `Provider` interface in `internal/auth/sso/linkedin.go`.
2. Register in `internal/auth/sso/manager.go`'s `Manager.buildProviders()`.
3. Add env vars: `SSO_LINKEDIN_ENABLED`, `SSO_LINKEDIN_CLIENT_ID`, `SSO_LINKEDIN_CLIENT_SECRET`, `SSO_LINKEDIN_REDIRECT_URL`.
4. Update `AuthProvider` enum in `internal/domain/user.go` and add a migration if the enum is stored as a DB type.
5. Register LinkedIn as a new OAuth app in LinkedIn's developer console.
6. Tests in `tests/sso_linkedin_test.go` (or exercise the existing SSO test pattern).

---

## 8. Testing

### Unit tests

`go test ./internal/... -v` — tests inside each package, mock dependencies via interfaces.

```go
// internal/auth/jwt/service_test.go
func TestGenerateAccessToken(t *testing.T) {
    svc := jwt.NewService(jwtConfig, nil)
    token, err := svc.GenerateAccessToken(user, org, roles, permissions)
    require.NoError(t, err)
    claims, err := svc.ValidateAccessToken(ctx, token)
    require.NoError(t, err)
    require.Equal(t, user.ID, claims.UserID)
}
```

### Integration tests

Three layers — see `tests/README.md` for the full breakdown:

| Layer | Tag | Needs | Run |
|---|---|---|---|
| Unit | (none) | nothing | `go test ./internal/... ./pkg/...` |
| Integration | `integration` | Docker (Postgres + Redis) | `make test-integration` |
| Cognito migration | `integration_cognito` | `tests/.env.test.cognito` (gitignored) | `go test -tags integration_cognito ./tests/specs/...` |

`tests/specs/*_test.go` files tagged with `//go:build integration` spin up a real HTTP server on a random port, hit real Postgres + Redis, and exercise the full auth flow. The `integration_cognito` tag adds tests that hit a real AWS Cognito pool via `pkg/migration/cognito` — they skip silently when the env file is absent.

Helpers in `tests/helpers/`:

- `NewTestEnvironment(t)` — constructs the full service stack and an HTTP test server
- `UniqueEmail()` — generates a unique email per test so parallel runs don't collide
- `TestClient` — typed methods for every auth endpoint (`Register`, `Login`, `Refresh`, `Logout`, etc.)
- `RegisterAndLogin(email, password)` — two-liner to get a fresh session

Coverage:

- `auth_register_test.go` — success, duplicate email, weak password, missing fields
- `auth_login_test.go` — success, wrong password, lockout, remember me
- `auth_token_test.go` — refresh success, revoked, invalid, validate endpoint
- `auth_password_test.go` — reset request, invalid reset token, change password
- `auth_session_test.go` — list sessions, terminate session, logout all, unauthenticated
- `auth_ratelimit_test.go` — under limit, exceeds limit, Retry-After header

---

## 9. Admin vs. developer actions

### Regular developers can

- Run the full stack locally via `make docker-up`.
- Write new endpoints, handlers, services, migrations.
- Run unit + integration tests.
- Create test users via `POST /auth/register`.
- Inspect their local Postgres and Redis.
- Deploy to scratch staging environments with non-production secrets.

### Admin / release manager actions (privileged, coordinated)

- **Rotate JWT signing secrets in production** (AUDIT C5 — zero downtime). The auth server holds an active secret slot and an optional previous slot for both access and refresh tokens. Validators try active first and fall back to previous only on signature mismatch. Signing always uses active. The runbook:

    1. Generate two new high-entropy secrets — at least 32 characters, must not be in the denylist (`secret`, `changeme`, `test`, etc.). `openssl rand -base64 48 | tr -d '+/=' | head -c 64` is fine.

    2. Roll the auth server config: move the current values into the previous slot, set the new values as active.

       ```bash
       # Before:                            # During rotation:
       JWT_ACCESS_SECRET=OLD_VALUE          JWT_ACCESS_SECRET=NEW_VALUE
       JWT_REFRESH_SECRET=OLD_VALUE         JWT_REFRESH_SECRET=NEW_VALUE
                                            JWT_ACCESS_SECRET_PREVIOUS=OLD_VALUE
                                            JWT_REFRESH_SECRET_PREVIOUS=OLD_VALUE
       ```

       Apply the same change to every downstream service that holds `JWT_ACCESS_SECRET` (e.g. `new/api`) — they need the previous slot too so they accept old tokens during the rollover. `JWT_REFRESH_SECRET_PREVIOUS` is only relevant for the auth server itself; downstream services don't validate refresh tokens.

    3. Rolling restart all replicas. Outstanding tokens continue to validate; brand-new tokens are signed under the new secret.

    4. Wait out the longest live token: refresh-token TTL is 7d (30d with `remember_me`). Schedule the cleanup step beyond that horizon. Access tokens (15m) expire long before refresh tokens, so the refresh-token window is what matters.

    5. Clear the previous slot and roll again. Rotation complete.

       ```bash
       JWT_ACCESS_SECRET=NEW_VALUE
       JWT_REFRESH_SECRET=NEW_VALUE
       # JWT_ACCESS_SECRET_PREVIOUS — unset / cleared
       # JWT_REFRESH_SECRET_PREVIOUS — unset / cleared
       ```

    **Independence:** access and refresh secrets each have their own previous slot, so you can rotate one without the other. **Purpose-derived secrets** (password-reset, email-verify) derive from the access master via HMAC, so rotating the access master also rotates them — the previous-slot derivation runs at boot in parallel, keeping outstanding reset / verify links valid for the rotation window. **Validation:** boot refuses an empty active secret, a previous slot under 32 chars, a denylisted previous value, or a previous slot equal to the active one (typo / no-op rotation).

- **Run production migrations.** Against prod DB with prod credentials from 1Password.
- **Revoke all tokens for a user.** `POST /auth/logout/all` as that user, OR a direct SQL update to set `refresh_tokens.revoked=true` where `user_id=?`.
- **Unlock a locked account** — `UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE email = ?`.
- **Delete a user** — soft-delete via `UPDATE users SET deleted_at = NOW() WHERE id = ?`. Hard-delete is manual and requires coordination with `new/api` to clean up cross-referenced rows.
- **Enable / disable an SSO provider** in production via env var flip + redeploy.
- **Update the seeded role-permission table** — new permissions or roles require a migration (e.g. `003_add_livestream_permissions.up.sql`), not a hot change.
- **Read from the production Redis** to debug rate-limit issues, token blacklist state, or session activity.
- **Grant a user system-admin** — manually insert into `user_base_roles` with the `system_admin` role id, or `PUT /admin/users/{id}/roles` with that role. Reserved; never auto-granted via migration.
- **Grant a user super-admin** — same shape, role code `super_admin`. Use for ops / customer-success / support staff who need cross-org data access but shouldn't be able to register apps or touch platform internals.
- **Cognito auto-migrate operations** (legacy cutover only):
    - Set `COGNITO_AUTO_MIGRATE_ENABLED=true` + pool config to enable the drop-in adapter at `/auth/login`.
    - Migration runs server-side, transparently; no client-side header anymore.
    - When the cutover finishes, set `COGNITO_AUTO_MIGRATE_ENABLED=false` and the adapter never loads at runtime.

### What NEVER happens in the auth server

- Business logic specific to auctions, bids, or orders. If it's domain logic, it belongs in `new/api`.
- Direct reads from `new/api`-owned tables. The auth server only reads its own tables.
- Emails with embedded tokens that aren't time-limited. Every token has an `exp` claim.
- Logging of full password values. Bcrypt hashes don't leak the password; raw passwords in logs would.
- Storing API keys for external services (EasyPost, Stripe, etc.) — those belong in `new/api`'s config. The auth server should only hold auth-related secrets (JWT keys, SMTP creds, SSO client secrets).

---

## 10. Production deployment

### Single-instance (simplest)

AWS ECS task running the Docker image with:

- RDS Postgres 14+
- ElastiCache Redis 7+
- ALB with HTTPS termination
- SSM Parameter Store for secrets → `envFrom`
- CloudWatch logs

Task definition reads secrets via `secrets:` (ARN references), not `environment:` (plaintext).

### Multi-instance (recommended for prod)

Multiple ECS tasks behind the same ALB. Postgres and Redis are shared, which is why Redis-backed rate limiting and token blacklist matter — without them, per-instance in-memory state diverges.

### Zero-downtime deploys

1. ECS rolling update — new task comes up, health check passes, old task drains.
2. No DB schema changes in the same deploy as new binary (migrations first, then code).
3. No secret rotation in the same deploy as new code (rotations first, code second).

---

## 11. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `make docker-up` fails with "port already in use" | Something else is using `:5432`, `:6379`, or `:8080` | Stop the other thing, or edit `docker-compose.yml` port mappings. |
| `health` returns but login fails | Migrations haven't run | `make docker-clean && make docker-up` for a fresh install. |
| Login works in dev, fails in prod with "invalid token" | `JWT_ACCESS_SECRET` differs between `new/auth` and `new/api` | Both must share the same value. Check the secrets manager. |
| Rate limiting blocks legitimate traffic | `RATE_LIMIT_REQUESTS` too low for the current load | Raise it via env var + redeploy. Default 100/min is conservative. |
| Tokens aren't being revoked on logout | Redis is down; server is using `NoOpTokenCache` | Restart Redis and verify the server's startup logs mention "redis connected". |
| SSO callback fails with "invalid state" | State TTL (5 min) elapsed before the user completed the flow | Retry. If systemic, check clock drift between server and user. |
| User is locked out after a few failed logins | Expected — the lockout threshold is 5 failures in 15 min | Wait 15 min, or manually unlock via SQL (admin action). |
| Can't connect to Postgres from Go code | `DB_HOST` is `localhost` but you're inside Docker | Inside Docker, use `postgres` as the hostname (the service name in docker-compose). |

---

## 12. See also

- [`How_It_Works.md`](./How_It_Works.md) — architecture narrative, token lifecycle, multi-tenant model
- [`../README.md`](../README.md) — the canonical full architecture + API reference (pre-existing, authoritative)
- `../../client/docs/auth-integration.md` — the endpoint + DTO contract shared with `new/client`
- `../../client/docs/How_It_Works.md` — the client side of the token story
- `../../api/docs/How_It_Works.md` — how `new/api` validates tokens issued here
- `../../client/docs/cutover-runbook.md` — operational procedures for the legacy Cognito decommission
