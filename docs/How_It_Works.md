# How It Works — rw3iss Auth Server

The Go auth server is the **single source of truth** for identity on the rw3iss platform. Every client and every backend service that cares about "who is this user and what can they do?" ultimately gets its answer from here. This doc covers the domain flow — how a request turns into a JWT, how that JWT carries enough claims for the rest of the platform to avoid a second network call, and why the multi-tenant org model looks the way it does.

For dev setup + commands see [`Development.md`](./Development.md). For the full architecture diagram and API reference, the root [`../README.md`](../README.md) is authoritative.

---

## 1. The one job

Issue JWTs, validate JWTs, store the users + organizations + roles + permissions those JWTs describe. Everything else in the system delegates identity to this service. `new/api` doesn't have its own user table in any meaningful sense; the `new/client` never touches Cognito or any other identity provider directly.

That means **every design choice here is shaped by two pressures:**

1. **Don't be a bottleneck.** Every API request downstream depends on being able to validate a token cheaply — so token validation has to be local (HMAC signature) or cache-backed (Redis blacklist lookup), not a database hit per request.
2. **Carry enough claims in the token to answer the common questions inline.** Roles, permissions, org context, and user identity are all in the access token, so `new/api` can answer "is this user a seller in this org?" without asking `new/auth`.

---

## 2. The big picture

```
                     ┌─────────────────────────────────┐
                     │         new/auth (Go)           │
                     │                                 │
       clients ──────▶   /api/v1/auth/*                │
       (browser,      │                                │
        mobile,       │   /api/v1/auth/sso/*  ────┐    │
        new/api)      │                           │    │
                     │   /api/v1/auth/sessions/*  │    │
                     │                           │    │
                     │   /api/v1/auth/validate    │    │
                     │   (called only from        │    │
                     │    other backends)         │    │
                     │                            │    │
                     │   /health                  │    │
                     └──────────┬─────────────────┼────┘
                                │                 │
                                ▼                 ▼
                     ┌──────────────────┐  ┌──────────────────┐
                     │  Postgres        │  │  Redis           │
                     │                  │  │                  │
                     │  users           │  │  token cache     │
                     │  organizations   │  │  blacklist       │
                     │  memberships     │  │  rate limits     │
                     │  roles           │  │  SSO state       │
                     │  permissions     │  └──────────────────┘
                     │  refresh_tokens  │
                     │  sessions        │
                     └──────────────────┘
                                ▲
                                │
                                │  shared DB
                                │
                     ┌──────────┴────────┐
                     │  new/api (NestJS) │
                     │                   │
                     │  reads memberships│
                     │  + auctions etc.  │
                     └───────────────────┘
```

The auth server is a **stateless HTTP service**. No persistent connections, no WebSockets, no long-polling. Every request is independent. Horizontal scaling is "run more replicas".

Redis is optional at the interface level (the server has a graceful `NoOpTokenCache` fallback if Redis is down), but every production deployment uses it — without Redis, rate limiting falls back to in-memory per-instance counting (which multi-replica setups can bypass) and token revocation can't be enforced across replicas.

---

## 3. The JWT lifecycle

### Issuance

When a user authenticates (password, SSO, refresh), the JWT service builds claims from:

- The user's row in `users` (uid, email, names).
- If an `organization_id` was supplied, the matching `organization_members` row + its linked roles. Login + refresh both fail-loud if the org isn't found, the user isn't a member, or the org is suspended (AUDIT 2.2 / 2.7).
- If no org was supplied, the user's global roles via `user_base_roles`.
- If an `app_code` was supplied, the matching `apps` row. The user must have an active `user_apps` membership (auto-granted on first login when `apps.auto_grant_on_signup=true`).
- Permissions: the union across services in `app.service_codes` plus the always-included `core` service, filtered by the user's roles.
- The current per-user token-version counter (`auth:user_tv:{user_id}` in Redis) → `tv` claim.

These claims go into an HS256-signed JWT with `JWT_ACCESS_SECRET`. Access token lifetime is 15 minutes (configurable). The refresh token is a separate HS256 JWT signed with `JWT_REFRESH_SECRET`, lifetime 7 days (or 30 days with `remember_me=true`). Both tokens carry `aud`/`iss` claims that validators enforce.

Password-reset and email-verification tokens use **distinct purpose-derived secrets** (HMAC-SHA256 of the access secret with `"ven-auth:purpose:password_reset"` / `"ven-auth:purpose:email_verification"`) and distinct audiences (`<issuer>:reset` / `<issuer>:verify`). A reset token cryptographically cannot pass an access-token audience check — three layers (secret, audience, `purpose` claim) protect against cross-purpose presentation.

**Zero-downtime rotation.** When `JWT_ACCESS_SECRET_PREVIOUS` / `JWT_REFRESH_SECRET_PREVIOUS` are set, validators try the active secret first and fall back to the previous secret on signature mismatch only — never on exp/aud/iss failures. Signing always uses the active secret. Each side rotates independently. Purpose-derived secrets rotate in lockstep with the access master because the previous slot derives its own parallel pair at boot, so outstanding reset / verify links keep validating until the previous slot is cleared. See `docs/Development.md` §"Rotate JWT signing secrets" for the operator runbook.

**Why embed roles and permissions in the token?** Because downstream services (`new/api`) need to answer "can this user do X?" on every request. If that answer required a roundtrip, every downstream request would double in latency. With claims in the token, `new/api` verifies the HMAC signature locally (~microseconds) and reads `user.permissions` from the payload.

**Why 15-minute access tokens + a token-version claim?** Short lifetime bounds blast radius. The `tv` claim is the cross-replica immediate-revocation lever: bump the user's counter in Redis and every outstanding access token fails validation on the next request, without per-`jti` blacklist writes.

### Refresh + rotation (family-aware)

Refresh-token rotation follows OAuth 2.0 best practice with theft-detection (RFC 6819 §5.2.2.3). Each `refresh_tokens` row carries `family_id` (the original issuance this chain descends from) and `parent_id` (the row it rotated from). On `POST /auth/refresh`:

1. Validate the JWT cryptographically (signature + aud + iss + leeway + algorithm).
2. Look up the stored row by the `tid` claim.
3. **If the row is already revoked**: this is reuse → presumed theft. Revoke every live row sharing `family_id` and return `TokenRevoked`. The legitimate user and the attacker both lose access; the user re-authenticates from scratch.
4. Otherwise: revoke the presented row and mint a child with the same `family_id` + `parent_id` pointing back. The new row is the family's new tip.

Concurrent refresh of the same token: one wins, the other sees the now-revoked row on its lookup and trips the family-revoke path. Belt-and-suspenders against the race.

### Revocation

Four mechanisms:

1. **Per-row `refresh_tokens.revoked=true`**. Used on logout, "terminate this session," and rotation.
2. **Family revoke** — bulk revoke every live row sharing a `family_id`. Triggered automatically on reuse detection.
3. **Per-user token-version bump** (`auth:user_tv:{user_id}` INCR in Redis). The `tv` claim on every outstanding access token now trails the current value → validation rejects. Triggered by `LogoutAll` and role/permission changes. This is what makes "logout everywhere" actually take effect on access tokens.
4. **Redis access-token blacklist** (`auth:blacklist:{jti}`). Legacy per-jti path, rarely needed now that token-version exists; still supported.

Downstream services (`new/api`) check the cached/blacklist state via the shared `TokenCache` interface. When Redis is unavailable they fall back to signature-only validation, which accepts revoked-but-not-yet-expired access tokens. Trade-off: availability over immediate revocation. Refresh-token revocation still works via the DB regardless.

### Validation

Two paths:

1. **Local validation** — downstream services share `JWT_ACCESS_SECRET` and verify HMAC + audience + issuer locally. Fast (~microseconds).
2. **`POST /auth/validate`** — send the token to the auth server, get back parsed claims (or `valid: false`). Used when downstream services don't have the secret. Adds a network hop.

`new/api` and `new/client` use local validation. `/auth/validate` is for third parties.

---

## 4. The multi-tenant model

Users live independently of organizations. A user can belong to zero, one, or many organizations, with different roles in each.

```
User (jane@acme.com)
  ├── base role: "base_user"  (global — what she is outside any org)
  │
  ├── membership in Org "Acme"
  │     └── roles: ["org_admin", "seller"]
  │
  └── membership in Org "BuildCo"
        └── roles: ["buyer"]
```

The access token is scoped to **at most one organization** at a time:

- **No org context:** the token carries only `base_user` global roles. Used for the first-time login and for users who don't belong to any org.
- **Org context:** the user passed `organization_id` to `/auth/login` or `/auth/refresh`. The token claims include `org_id`, `org_slug`, `org_name` + the roles and permissions they have **in that org**.

Switching orgs means calling `POST /auth/refresh` with a different `organization_id`. The server issues a new token pair scoped to the new org. The client doesn't need to log out and back in.

**Why scope the token to one org?** Because the alternative is embedding every org membership in every token, which (a) bloats the token, and (b) forces downstream services to handle cross-org permission resolution on every request. Scoping to one org means `new/api` gets to check `user.permissions` directly without first asking "in which org?".

### User pools / namespaces (migration 017)

Orthogonal to organizations, a user has a **home pool** (`users.namespace`, default `default`). This is *identity* segregation, not membership grouping: email is unique **per `(namespace, email)`**, so `alice@x.com` in `default` and `alice@x.com` in `wristleo` are *different users*. Orgs group one global identity for RBAC; pools split identity itself.

An app opts in via two columns:

- **`registration_namespace`** — the *write* pool. New users registered through this app are created here. Omit ⇒ `default`.
- **`read_namespaces`** — the *read* pools. `Login` and the register collision-check resolve the user by email **across this set** (the write pool is always implicitly readable), so an account already living in a readable pool — typically the shared `default` — is reused rather than duplicated.

Because the read pools depend on the app, `Login` resolves the app *before* the user lookup, then scopes the lookup to that app's read pools. The upshot: an app can capture brand-new users into its own private pool while still letting existing platform users in without re-registering — and a user in pool A simply doesn't exist to an app that only reads pool B (try-login → `InvalidCredentials`). Apps that set neither column read+write `default` and behave exactly as they did pre-017. The access token carries a `namespace` claim for non-default pools. Full design + worked examples: [`USER_POOLS.md`](./USER_POOLS.md).

### Org vs. base roles

- **Base roles** (e.g. `system_admin`, `base_user`, `developer`) are attached to a user globally, via `user_base_roles`. They apply regardless of org context.
- **Org roles** (e.g. `org_admin`, `org_manager`, `seller`, `buyer`) are attached to a user within a specific organization, via `organization_member_roles`.

When issuing a token:

- **No org context:** include the user's base roles only.
- **Org context:** include BOTH the base roles AND the org roles for that membership.

A system-admin belongs to every org implicitly — they can always switch context and act inside any organization, regardless of membership. This is enforced by the query that hydrates the token claims: if the user has the `system_admin` base role, the org-membership check is skipped.

### The seeded role/permission set

Migration `002_seed_data.up.sql` populates:

- **Roles:** `system_admin`, `org_admin`, `org_manager`, `seller`, `buyer`, `base_user`
- **Permissions:** namespaced as `resource:action` (e.g. `auctions:create`, `users:invite`, `bids:create`)
- **Role-permission mapping:** static, hardcoded in the migration. System admin gets everything. Each lesser role gets a subset.

Custom roles and custom per-role permissions are on the roadmap but not implemented in phase 1 — an org can't create its own roles yet. If you need different access, use one of the seeded roles and pair with permission-level granularity.

### Service-scoped permissions

Every permission carries a `service` column identifying which service owns the definition. Auth-owned permissions (users, organizations, roles) are `service='core'`. Other services — `release-manager`, `auction`, etc. — own their own slices of the catalog.

**Registration** is declarative and idempotent. A service POSTs its full permission manifest at boot:

```
POST /api/v1/admin/permissions/register
Authorization: Bearer <system_admin token>

{
    "service": "release-manager",
    "permissions": [
        { "code": "releases:create", "resource": "releases", "action": "create",
          "name": "Create Releases", "description": "..." },
        { "code": "releases:delete", ... }
    ]
}
```

Auth reconciles: upserts every declared permission (`INSERT ... ON CONFLICT (code) DO UPDATE`), then deletes rows where `service='release-manager'` AND `code` is not in the declared set. The service's manifest is the source of truth for its slice.

**Gotchas:**

- `code` is still **globally unique** — two services can't register the same code. Use service-prefixed codes (`release-manager:releases:create`) if you need to avoid collision with existing ones.
- `service='core'` is reserved — callers can't claim it.
- `ON DELETE CASCADE` on `role_permissions` means pruning a permission silently removes it from every role. Reconciliation with a shrunken manifest is destructive.
- Requires `system_admin` today. When service-to-service auth lands, switch the gate to a dedicated machine principal.

---

## 5. SSO flow

Google, Apple, Microsoft, and GitHub OAuth 2.0 providers are supported. The flow:

1. **Client requests an auth URL:**
    ```
    POST /auth/sso/url
    {
      "provider": "google",
      "redirect_url": "https://app.ryanweiss.net/auth/sso/callback",
      "organization_id": null,         // optional
      "invite_code": null,             // optional, for joining an org via invite
      "code_challenge": "...",         // optional — public clients SHOULD send PKCE
      "code_challenge_method": "S256"  // only S256 accepted; plain is refused
    }
    ```
2. **Server generates an opaque state token** and stores the SSO intent (provider, redirect URL, org context, invite, PKCE challenge if present) in the `StateStore` (Redis when available, in-memory fallback, 10-minute TTL) keyed by the state.
3. **Server builds the provider's authorization URL** with the state as a query parameter.
4. **Response** returns `{ auth_url, state }` — the client navigates to `auth_url`.
5. **User authenticates at the provider** (Google, etc.) and is redirected back to `redirect_url` with `?code=...&state=...` in the query string.
6. **Client posts the callback:**
    ```
    POST /auth/sso/callback
    { "code": "...", "state": "...", "provider": "google" }
    ```
7. **Server validates the state** against the StateStore (one-time use — immediately removed via atomic GETDEL).
8. **Server exchanges the code** with the provider for an access token.
9. **Server fetches the provider's user info** (email, name, profile photo, etc.).
10. **Server finds or creates the user** in `users`, linked via `user_auth_providers` (one row per provider account per user). Invitation acceptance, last-login update, and other side effects happen here unconditionally.
11. **Terminal branch:**
    - **Without PKCE** — server generates application tokens and returns the same `LoginResponse` shape as a password login.
    - **With PKCE** — server mints a one-shot `auth_code` (Redis or in-memory, 60s TTL) carrying the user_id, org_id, provider, and the stored challenge. Response is `{ auth_code, expires_in: 60 }`. The public client then redeems:
      ```
      POST /auth/sso/exchange
      { "auth_code": "...", "code_verifier": "..." }
      ```
      Server atomically consumes the auth_code, verifies `BASE64URL(SHA256(verifier)) == challenge`, re-fetches the user / org / roles / permissions at exchange-time so any change between callback and exchange is reflected, mints the token pair, and returns the standard `LoginResponse`. AUDIT C2.

The provider-specific adapters live in `internal/auth/sso/`. Adding a new provider is (a) registering its client id/secret in config, (b) implementing the `Provider` interface, (c) wiring into the `Manager`'s provider map.

### Why state is in Redis (when available)

The state exists for up to 10 minutes between the initial request and the callback, and SSO is one of the few flows where a callback can land on a different replica than the one that minted the state. AUDIT 1.12 promoted state to Redis-backed (one-shot via `GETDEL`, atomic) so cluster routing doesn't break the flow. The in-memory fallback runs single-locked so the one-shot guarantee holds within one replica. PKCE auth_codes (60s TTL) use the same Redis pattern with a distinct key prefix (`auth:sso:authcode:`).

### SSO hardening lessons from the legacy cutover

The legacy Cognito integration used a `?user=verify` query parameter in the redirect URL as a "we're in the middle of an SSO roundtrip" signal. That parameter had to be registered verbatim in Cognito's allowlist, and any drift caused a silent `redirect_mismatch` error that manifested as "An error occurred with the requested page". When we built `new/client`'s SSO flow, we learned from that:

1. The redirect URL is clean (`/auth/sso/callback`, no flags).
2. "SSO in progress" state lives in client-side `sessionStorage`, not in the URL.
3. The client has an in-flight guard so React strict-mode double-mounts can't consume the code twice.

See `../client/docs/auth-integration.md` §7.5 for the client side of the SSO flow.

---

## 6. Rate limiting

Three independent layers:

1. **Per-IP rate limit** (`middleware.RateLimiter.Limit`). Redis-backed `INCR auth:ratelimit:{client_ip}` with a TTL matching the window. Falls back to in-memory per-replica if Redis is unavailable (single-replica only — multi-replica deployments need Redis). Default `100/min`.

2. **Per-account login limit** (`AuthService.Login`, AUDIT 1.17). Redis-backed sliding-window counter keyed on `sha256(email)` — so the cache key never carries PII. Default 20 attempts/hour. Defeats botnets that rotate IPs to bypass the per-IP limit. Resets on successful login so legitimate users aren't penalized by a trailing window of failures. NoOp when Redis is unavailable.

3. **Account lockout** (`users.failed_login_attempts` + `users.locked_until`). After 5 failed attempts within 15 minutes, the row's `locked_until` is set 15 minutes in the future. The DB is the source of truth; survives Redis outages.

The first IP-layer can also be reinforced by the **trusted-proxy XFF filter** (`TRUSTED_PROXIES`). When set, the middleware honors `X-Forwarded-For` only when it arrives through a trusted CIDR; otherwise the connection's `RemoteAddr` wins. Default empty list = ignore XFF entirely.

When any layer trips, the server returns `429 Too Many Requests` with a `Retry-After` header.

---

## 7. Password handling

- **Bcrypt** with the **configured** cost (`BCRYPT_COST`, default 12). Boot-time validation refuses costs outside `[10, 14]`. `HashPassword` and `CheckPassword` both cap input at `MaxPasswordLength` (128 bytes) so a multi-MB password can't burn CPU on every login.
- **Account lockout**: 5 failed attempts / 15 minutes (configurable) → 15-minute lockout, on top of the per-account rate limit above.
- **Password policy** is configurable per character class via `AUTH_PASSWORD_REQUIRE_UPPER` / `LOWER` / `DIGIT` / `SPECIAL` — defaults match the previous hard-coded behavior. Operators can relax for environments that allow it.
- **Password reset tokens** are signed with a purpose-derived secret (HMAC-SHA256 over `JWT_ACCESS_SECRET` with `"ven-auth:purpose:password_reset"`), carry the `<issuer>:reset` audience and a `purpose` claim. **Single-use**: `ResetPassword` looks up the stored row by the JWT's `jti`, refuses if `used=true`, marks it used in the same transaction as the password update (AUDIT 1.1).
- **Email verification tokens** mirror the same pattern with their own purpose secret + audience + single-use enforcement (AUDIT 1.2).

The password reset flow returns `200 OK` regardless of whether the email exists, to prevent enumeration. The real side effect (email sent or not) is best-effort and logged.

---

## 8. Email + notifications

The `EmailService` is an interface with four implementations:

- **SMTP** — for local dev and small deployments
- **SendGrid, Mailgun, SES** — for production
- **NoOp** — logs emails instead of sending them; used in integration tests and as a fallback when `EMAIL_PROVIDER` isn't configured

Templates are HTML files under `templates/email/` (not included in the repo in phase 1 — operators ship their own branded templates). The service fills them with user/provider-specific data at send time.

Emails are sent **synchronously** in phase 1, inside the HTTP handler. If email sending is slow or the provider is down, the request is slow. Phase 2 moves email sending to a goroutine that logs errors but doesn't block the response.

---

## 9. Cognito auto-migrate (legacy auth fallback)

The legacy header-based bridge has been replaced. Migration now happens **server-side** during `/auth/login` via the `pkg/migration` package — clients don't need to know it exists.

When `COGNITO_AUTO_MIGRATE_ENABLED=true` and a valid pool is configured:

1. `/auth/login` looks up the email in the internal `users` table.
2. If absent AND a legacy adapter is wired in, call `cognito.Adapter.TryLogin` with the submitted password.
3. **Cognito accepts**: gather the user's profile + groups, create the internal user with the just-validated password (bcrypt-hashed at the configured cost), map legacy groups → internal role codes via `DefaultRoleMapper`, record an audit event (`user.migrated_from_legacy`), then continue the normal login flow.
4. **Cognito rejects** (user-not-found OR wrong-password): return the same `InvalidCredentials` shape as any other failed login. The wire response never distinguishes "user doesn't exist anywhere" from "wrong password on legacy" from "wrong password on internal."

### Role mapping safety

`migration.DefaultRoleMapper` translates Cognito group names to internal role codes case-insensitively:

| Cognito group | Internal role(s) |
|---|---|
| `SELLER` | `seller` |
| `SELLERADMIN` | `seller`, `org_admin` |
| `ADMIN` | `org_admin` |
| `SUPER_ADMIN` | `super_admin` (cross-org admin; **not** platform owner) |
| `CUSTOMER`, `BUYER` | `customer` |
| `LISTER`, `MANAGER`, `SELLERTESTER`, `BUYERTESTER` | direct match |
| `SYSTEM_ADMIN` | **dropped** — never inherited from legacy |

The `system_admin` role is the platform-owner gate. An attacker who managed to create a `SYSTEM_ADMIN` group in the legacy Cognito pool would otherwise gain platform control through migration; the mapper hard-refuses every variant. Unit-tested.

### Architectural isolation

The adapter lives in `pkg/migration/cognito` — outside `internal/`. The auth-server core depends only on the `migration.LegacyAuthProvider` interface; the AWS SDK is reachable only when `COGNITO_AUTO_MIGRATE_ENABLED=true`. Adding a future Auth0/Okta migration is "drop a new package alongside `cognito/`" with no auth-server changes.

See `pkg/migration/migration.go` for the interface and `pkg/migration/cognito/cognito.go` for the Cognito-specific implementation. Integration tests under `tests/specs/cognito_migration_test.go` (build tag `integration_cognito`) exercise the adapter against a real pool when `tests/.env.test.cognito` is present.

---

## 10. What the auth server doesn't do

Listed explicitly because these questions come up:

- **Not an OIDC provider.** No `/.well-known/openid-configuration`, no JWKS, no RS256. We use HS256 with a shared secret because all clients are first-party — there's no need for asymmetric signing.
- **No WebSockets.** Auth is request/response, not subscribe. Downstream services that want "tell me when this user logs in" should listen on `new/api`'s event bus, which is fed by webhook calls from `new/auth` (not currently wired — phase 2).
- **No 2FA.** The schema has `two_factor_enabled` and `two_factor_secret` fields, but the TOTP flow isn't implemented. On the roadmap.
- **No per-org custom SSO.** The schema supports `organizations.sso_config` JSONB with a provider name, but the Manager doesn't yet route to per-org provider adapters.
- **No native multi-environment pooling.** One Go binary talks to one Postgres. Different environments (dev/stage/prod) run separate deployments against separate databases. A future enhancement could add a `X-Auth-Pool` header that picks a connection from a pool-of-pools at runtime — deferred.
- **No impersonation endpoint.** Super-admins who want to "view as user X" do it on the client via a role override, not by getting a token for another user.
- **No user deletion.** Users are soft-deleted (`deleted_at` column). Hard deletion requires a manual SQL script + a cascading wipe across tables both `new/auth` and `new/api` own.

---

## 11. Development considerations

### The shared DB boundary

`new/api` shares the same Postgres. The contract is:

- `new/auth` **owns** the auth tables (users, organizations, memberships, roles, permissions, refresh_tokens, sessions, invitations, verification tokens).
- `new/api` **reads** from those tables via raw SQL — never via ORM entity mappings that would imply "I can alter this schema".
- Neither project alters the other's tables in a migration. **Coordinated schema changes are the exception, not the rule**, and when they do happen they ship as a joint PR.

### Why Go?

The auth server predated the rest of `new/`. It was written in Go because:

1. The original author had Go expertise and wanted a small, statically-compiled binary for the most security-sensitive service.
2. JWT + bcrypt are well-covered by mature Go libraries.
3. Single-binary deployments are easy to run, easy to audit, and deterministic across environments.

The downside: `new/api` developers who want to make a change here have to context-switch into Go. The upside: the auth surface is tiny, the codebase is small, and the boundary is clear.

### Testing

Integration tests in `tests/` spin up a real Postgres + Redis via Docker and a real HTTP server on a random port, then exercise the full auth flow (register → verify → login → refresh → logout). The `TestEnvironment` + `TestClient` helpers make writing a new test one or two lines:

```go
func TestMyFlow(t *testing.T) {
    env := helpers.NewTestEnvironment(t)
    defer env.Cleanup()

    email, password := helpers.UniqueEmail(), "TestPass123"
    env.Client.Register(email, password)
    tokens := env.Client.Login(email, password)
    // ... assertions
}
```

Unit tests in `internal/*/` cover the JWT service, the password hasher, the SSO manager, etc. These don't touch the DB.

---

## 12. See also

- [`Development.md`](./Development.md) — scripts, Docker setup, admin vs. developer workflows for this project
- [`../README.md`](../README.md) — the full architecture, API reference, and deployment guide (pre-existing, authoritative)
- `../../client/docs/auth-integration.md` — the endpoint + DTO reference shared between `new/client` and `new/auth`
- `../../client/docs/How_It_Works.md` — the client side: how tokens from this server are stored, refreshed, and propagated across tabs
- `../../api/docs/How_It_Works.md` — how the NestJS API validates tokens issued here (shared JWT secret, local HMAC verification)
