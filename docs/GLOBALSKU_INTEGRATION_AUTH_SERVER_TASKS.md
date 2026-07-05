# Auth-server work for GlobalSKU integration (app-agnostic)

> ## Implementation status (2026-06-22)
>
> Implemented in the auth-server. Build + unit tests green.
>
> | § | Item | Status |
> |---|---|---|
> | 1 | App-context resolution for the 4 `default`-only flows | **Done** |
> | 2 | Login: ensure app-namespace membership (password + SSO) | **Done** |
> | 3 | Apple SSO | **Done** (provider hardened + registered) |
> | 4 | Bulk pre-hashed import | **Done** (`POST /admin/users/bulk-import`) |
> | 5 | JIT legacy migration registry by `app_code` | **Done** — incl. the GlobalSKU adapter (`pkg/migration/globalsku`, §5.1) wired in main.go via `GLOBALSKU_LEGACY_MIGRATION_ENABLED`. |
> | 6 | Facebook + LinkedIn SSO providers | **Done** — `internal/auth/sso/{facebook,linkedin}.go`, registered in manager, config `SSO_FACEBOOK_*` / `SSO_LINKEDIN_*`. |
> | 7 | Auto-provision app + org(role) + linked app on globalsku login/register/migrate | **Done** — migration 020 adds `apps.default_role_code` + `apps.linked_app_codes`; `ensureAppEntitlements` (idempotent) called from register / login-auto-grant / (JIT via the login branch). Per-request `role_code` + `linked_app_codes` overrides on login/register, role re-validated org-scoped (no escalation). |
>
> **Deviations from this spec (it was written before verifying the code):**
> 1. **Apple was not a stub.** `internal/auth/sso/apple.go` already had
>    client-secret signing, code exchange, and id_token parsing. The actual
>    gaps fixed: it was never *registered* (manager logged "not implemented");
>    `ValidateIDToken` used `ParseUnverified` (no signature check) — now
>    verifies against Apple's **JWKS** (RS256, cached, base64/PEM key support);
>    the first-login `form_post` **`user` name** field is now captured; config
>    gained `SSO_APPLE_TEAM_ID` / `SSO_APPLE_KEY_ID` / `SSO_APPLE_PRIVATE_KEY`.
> 2. **No app-context middleware existed to extend.** The system threads
>    `app_code` via the request **body** (login/reset/resend already did). So
>    §1 was implemented along the existing channel + an **`X-App-Code` header**
>    fallback, resolved in the handlers — no new middleware. Precedence:
>    unauthenticated flows → header > body; authenticated `/auth/check-email`
>    → JWT `app_code` claim > header > body.
> 3. **`POST /admin/users/lookup` left cross-pool.** It's a bulk resolver and
>    returns each user's `namespace`; scoping it would break the existing
>    super_admin "all matches" behavior. The `ven_user_id` backfill now gets
>    uids directly from bulk-import (§4), which is the primary backfill path.
> 4. **Migration interface is `TryLogin`** (not `VerifyCredentials`). §5 added
>    `WithLegacyAuthFor(appCode, provider, mapper)` (per-app registry) +
>    `LEGACY_MIGRATION_CONFLICT` error; JIT-migrated users now land in the
>    app's **write pool + tags** (were bare `default`). The **GlobalSKU
>    `LegacyAuthProvider` adapter is not built** — it requires a signed
>    `verify-legacy-password` endpoint on GlobalSKU (a GlobalSKU-side
>    decision; see §5 below). Register it via `WithLegacyAuthFor("globalsku", …)`
>    in `cmd/server/main.go` once that channel exists.
>
> **Key files touched:** `internal/auth/sso/{apple,manager}.go`,
> `internal/auth/password/hasher.go`, `internal/config/config.go`,
> `internal/service/auth/{auth_sso,auth_login,auth_migration,auth_password,
> auth_admin,auth_registration,auth_import,auth_service}.go`,
> `internal/api/handlers/auth_handler.go`, `internal/api/dto/auth.go`,
> `internal/api/routes/routes.go`, `pkg/shared/errors/errors.go`. Tests:
> `internal/auth/sso/apple_test.go`, `internal/auth/password/hasher_test.go`.
>
> ---

**Status:** spec / handoff. Nothing in the auth-server has been changed yet.
**Audience:** the auth-server (Go) agent.
**Origin:** derived from `auth-server-laravel/docs/GLOBALSKU_NEW_AUTH_INTEGRATION.md`
+ `auth-server/docs/USER_POOLS.md` §6, after verifying the current code.

This scopes five pieces of auth-server work. **Every item must be built
app-agnostic** — GlobalSKU is the first consumer, but ClaimLeo/WristLeo/
marketplace must be able to use the same machinery with only config + a small
per-app adapter. Where a behavior is GlobalSKU-specific it lives in a pluggable
strategy keyed by `app_code`, never in core.

---

## 0. Canonical identity model (read first — it constrains everything below)

We are committing to **one core user identity, many namespaces**. A person is a
single `users` row (one credential set), and namespaces are **access/membership
tags**, not separate identities.

- **Home namespace stays `default`** for shared identities. The same human's
  GlobalSKU login and (future) marketplace login are the **same core user**.
- **App namespaces (`globalsku`, `marketplace`, …) are tags** in
  `user_namespaces`, granting that user access to that app's surface.
- The `globalsku` app is therefore configured as:
  ```jsonc
  {
    "code": "globalsku",
    "registration_namespace": "default",          // home = shared core identity
    "read_namespaces": ["default", "globalsku"],   // tag new users "globalsku"
    "allowed_auth_methods": ["password", "google", "apple"],
    "auto_grant_on_signup": true
  }
  ```
- **Login via `globalsku`:** resolve the core user by credentials across the
  app's read namespaces, then **ensure the user carries the `globalsku`
  namespace tag** — grant it on the fly when `auto_grant_on_signup` is true,
  otherwise deny. This is the "find the core user, ensure they're in the
  globalsku namespace" behavior the integration calls for.
- **Do NOT** create a second identity for an email that already exists in a
  read namespace. The existing `register_or_login` reuse path
  (`auth_registration.go`, `GetByEmailInNamespaces`) already does this — keep it.

> Model (A) per-namespace uniqueness stays in the schema, but the *operating
> convention* for the Vendidit suite is home=`default` + tags. The work below
> makes the auxiliary flows honor that convention instead of silently assuming
> a bare global `default` lookup.

---

## 1. App-context resolution for the four `default`-only flows

**Problem (USER_POOLS.md §6).** `SSO upsert`, `password-reset-request`,
`/auth/check-email`, and `admin-lookup-by-email` still resolve users via the
global/`default` `GetByEmail` path. For any app whose users live outside a bare
`default` lookup, these misresolve (wrong identity) or fail.

**Required behavior.** These flows must resolve the app context the *same way
authenticated routes already do*, then use the app's read namespaces:

1. **Derive the app code** in this precedence:
   - `X-App-Code` request header (for unauthenticated flows: reset-request,
     check-email, SSO start/callback), then
   - the JWT claim `app_code` / `namespace` (for authenticated flows:
     admin-lookup-by-email), then
   - **fall back to `default`** when neither is present (preserves today's
     behavior for un-namespaced callers).
2. **Load it into request context** via middleware. Check whether an
   app-context middleware already exists for login/register; if so, **extend it
   to cover these four routes** rather than adding a parallel mechanism. If not,
   add one shared middleware and apply it platform-wide.
3. **Resolve namespaces from the app** (`App.ReadNamespaces()` /
   `App.WriteNamespace()`) and swap the global `GetByEmail` for
   `GetByEmailInNamespaces(ctx, email, app.ReadNamespaces())` in:
   - SSO upsert (callback/exchange) — thread the resolved namespaces through the
     SSO `state` so the upsert writes/links in the right pool.
   - `password-reset-request` handler.
   - `/auth/check-email` handler.
   - admin-lookup-by-email (and verify `POST /admin/users/lookup` is
     namespace-aware too — it's the `ven_user_id` backfill path).

**Acceptance:**
- A `globalsku` user (home `default`, tag `globalsku`) can request a password
  reset, pass `check-email`, and complete Google/Apple SSO, all resolving to the
  one core identity.
- No `X-App-Code`/claim ⇒ behaves exactly as today (`default`).
- Add table tests covering header-present, claim-present, neither, and
  header/claim disagreement (header wins for unauthenticated; claim is
  authoritative for authenticated admin routes — document the precedence).

**Files:** `internal/api/handlers/auth_handler.go` (reset-request, check-email),
`internal/api/handlers/user_handler.go` (lookup, lines ~406–461),
`internal/auth/sso/*` (callback/exchange upsert),
`internal/service/auth/auth_*.go`, `internal/repository/postgres/user_repository.go`
(`GetByEmailInNamespaces` already exists), middleware under `internal/api/middleware/`.

---

## 2. Login: ensure app-namespace membership

Covered by §0, called out separately because it's a concrete code change.

- On password + SSO login resolved through an app, after authenticating the core
  user: **ensure the user is tagged into the app's namespace(s)**.
- `auto_grant_on_signup = true` ⇒ create the missing `user_namespaces` tag
  (idempotent) and continue.
- `auto_grant_on_signup = false` ⇒ deny with a clear error
  (`APP_ACCESS_NOT_GRANTED`) — the user exists but isn't entitled to this app.
- Reconcile with the existing `user_apps` access check so we don't end up with
  two parallel access gates; pick one as authoritative and document it.

**Files:** `internal/service/auth/auth_login.go` (~124–146), `user_service.go`
(tagging helpers exist: `POST /admin/users/{id}/namespaces`).

---

## 3. Implement Apple SSO

**Problem.** `internal/auth/sso/manager.go` (~280–310) registers Google + Custom;
**Apple is a stub** (`apple.go` skeleton) and logs "not implemented" at boot.
GlobalSKU needs Apple in Phase 1 (its current Socialite set is Google/Apple/
Facebook/LinkedIn).

**Required behavior.** Full Apple "Sign in with Apple" provider matching the
shape of `google.go`:
- Authorization-code + PKCE flow via the SSO manager.
- **Apple specifics:** client secret is a **JWT signed with an ES256 `.p8`
  key** (Team ID, Key ID, Service/Client ID), regenerated before expiry (≤6
  months). Parse the `id_token` for the user identifier; **email/name arrive
  only on first authorization** — persist them then, tolerate their absence on
  subsequent logins. Handle the `form_post` response mode Apple uses.
- Config keys mirroring the others: `SSO_APPLE_ENABLED`, `SSO_APPLE_CLIENT_ID`
  (Service ID), `SSO_APPLE_TEAM_ID`, `SSO_APPLE_KEY_ID`,
  `SSO_APPLE_PRIVATE_KEY` (the `.p8`, base64 or path).
- Register it in the manager alongside Google; remove the
  `logSSONotImplemented("Apple")` path.
- The SSO upsert must honor the app-context namespaces from §1.

**Acceptance:** an Apple login through `globalsku` resolves/creates the one core
user, tags `globalsku`, and round-trips PKCE. Unit-test the client-secret JWT
signing and id_token parsing (incl. the no-email-on-Nth-login case).

**Files:** `internal/auth/sso/apple.go`, `internal/auth/sso/manager.go`,
`internal/config/config.go`.

> Facebook / LinkedIn: **superseded.** Originally punted to a GlobalSKU-side
> Socialite passthrough — but provisioning a passwordless social identity has no
> clean path on the auth-server (register requires a password; bulk-import
> requires a hash). Decision (2026-06-22): **add Facebook + LinkedIn as
> first-class SSO providers here** so they flow through the bridge like
> Google/Apple. See **§6 below** — this is the remaining auth-server work.

---

## 4. Bulk pre-hashed import (app-agnostic)

**Problem.** No way to load existing users with their **existing bcrypt hashes**.
Only `AdminSetPassword` (plaintext) and the `system_admin` seed exist. Needed for
a one-shot cutover where users keep their current passwords with no reset.

**Required behavior.**
- New `system_admin` endpoint: `POST /api/v1/admin/users/bulk-import`.
- Request: an array of rows
  ```jsonc
  {
    "app_code": "globalsku",            // resolves write namespace + tags (optional; else use explicit namespace/default)
    "default_namespace": "default",     // optional override
    "users": [
      {
        "email": "alice@x.com",
        "password_hash": "$2y$12$....", // pre-hashed; stored AS-IS, never re-hashed
        "hash_algo": "bcrypt",          // selects the verifier; default "bcrypt"
        "first_name": "Alice",
        "last_name": "Doe",
        "namespace_tags": ["globalsku"],
        "metadata": { }                  // optional passthrough
      }
    ]
  }
  ```
- **Stores the hash verbatim.** bcrypt hashes are portable (cost embedded), so
  imported passwords verify immediately on login with no user-visible change.
- **App-agnostic strategy.** Decouple the hash format from core via a
  `PasswordHasher` / `LegacyHashStrategy` registry keyed by `hash_algo`:
  - `bcrypt` (default) → store as-is; the login verify path already uses
    `bcrypt.CompareHashAndPassword`, so it Just Works for any bcrypt app
    (GlobalSKU, ClaimLeo, etc.).
  - Other algos (argon2id, pbkdf2, scrypt, …) → register a verifier OR mark the
    row `rehash_on_next_login` so it falls through to the JIT path (§5). This is
    the "custom method if necessary" escape hatch; **do not** hard-code any
    single app's scheme into core.
- **Idempotent upsert** keyed by `(namespace, email)`: existing rows are
  `skipped` (don't clobber a live credential) unless an explicit
  `--update` flag is set. New rows land in the resolved write namespace and are
  tagged per `namespace_tags` (honoring §0: home `default` + tags).
- **Response:** per-row status (`created` / `skipped` / `error` + reason) **and
  the resulting `uid`** for each, so the caller can backfill GlobalSKU's
  `users.ven_user_id` in one pass (pairs with `POST /admin/users/lookup`).
- Validate hash format per algo; cap batch size (e.g. 500/req) and document it;
  audit-log as `user.bulk_imported`.

**Acceptance:** import a GlobalSKU export `(email, bcrypt_hash, name)` into
`default` with `globalsku` tags; those users log in via `globalsku` with their
**original** passwords; response uids backfill `ven_user_id`. Re-running is a
no-op (all `skipped`). A non-bcrypt row routes to JIT or a registered verifier,
never silently corrupts.

**Files:** new `internal/api/handlers/user_handler.go` route + `routes.go`,
`internal/service/user_service.go` (or a new `import_service.go`),
`internal/auth/password/*` for the hasher registry,
`cmd/seed/main.go` for reference on hashing/cost.

---

## 5. JIT legacy migration (app-agnostic)

**Problem.** Bulk import (§4) covers a planned cutover; JIT covers stragglers and
no-export scenarios — a user logs in for the first time post-cutover and is
silently migrated from the legacy store. The pluggable plumbing already exists
(`pkg/migration/`, used by Cognito); generalize it beyond Cognito and wire a
per-app registry.

**Required behavior.**
- Reuse the existing `LegacyAuthProvider` interface
  (`pkg/migration/migration.go` ~36–51) + `RoleMapper`. **Register providers by
  `app_code`** so each app supplies its own legacy backend
  (`pkg/migration/globalsku/`, `pkg/migration/cognito/`, …). `nil` ⇒ no JIT for
  that app (zero cost), exactly like today's `WithLegacyAuth(nil)`.
- **Flow** (extends `auth_login.go` ~129–146 / `auth_migration.go`): on login,
  resolve the app context (§1). Look up the core user in the app's read
  namespaces.
  - **Not found** + the app has a legacy provider ⇒ call
    `provider.VerifyCredentials(email, password)` against the legacy store. On
    success, create the core user in the app's **write namespace** (`default`)
    with the app namespace **tag**, hashing the now-known password at the
    configured bcrypt cost (12), map roles via the app's `RoleMapper`, audit
    `user.migrated_from_legacy`, and continue login.
  - **Found** (user already exists in the auth-server):
    - **Passwords match** (the supplied legacy password verifies against the
      existing auth-server credential) ⇒ proceed; ensure the app namespace tag
      (reconnect / link). This is the benign "same person re-arriving" case.
    - **Passwords differ** ⇒ **do NOT migrate or overwrite.** Return a clear,
      specific error — `LEGACY_MIGRATION_CONFLICT` — whose message states
      exactly what happened: *"An account with this email already exists in the
      central auth system with different credentials; legacy migration was
      halted pending a merge strategy."* Include `email` + the app code in the
      structured error so we can build a reconciliation strategy later. Log it
      at warn with enough context to find these cases.
- **GlobalSkuLegacyProvider** needs to reach GlobalSKU's password store. Decide
  and document the channel (note for the GlobalSKU side too): a small **signed
  `verify-legacy-password` endpoint on GlobalSKU** (preferred — no shared DB
  coupling) or a read-only shared DB connection. The provider only ever
  *verifies* a password and reads name/role; it never writes to GlobalSKU.

**Acceptance:** with the GlobalSku provider registered, an un-imported existing
user logs in via `globalsku` with their current password ⇒ migrated, tagged,
role-mapped, audited, logged in. A second attempt finds them locally (no
re-migrate). An email that already exists with a *different* password yields the
explicit `LEGACY_MIGRATION_CONFLICT` error, untouched data. Cognito path
unchanged (regression-test it).

**Files:** `pkg/migration/migration.go` (provider registry by app_code),
`pkg/migration/globalsku/` (new adapter), `internal/service/auth/auth_login.go`,
`internal/service/auth/auth_migration.go`, `internal/service/auth/auth_service.go`
(`WithLegacyAuth` → multi-provider registration), `main.go` wiring.

### 5.1 The GlobalSKU adapter + `LEGACY_AUTH_VERIFY_SECRET` (build this)

> **This is the concrete §5 work the auth-server still owes, and it's the ONLY
> thing that gives `LEGACY_AUTH_VERIFY_SECRET` any meaning on this side.** The
> GlobalSKU endpoint and secret already exist (built on `feature/ven-auth-bridge`);
> the auth-server has no adapter that calls them yet. Until this ships, the JIT
> half of the migration does nothing for GlobalSKU.

**Why the secret exists (the concept).** GlobalSKU's user passwords are bcrypt
hashes — **not reversible**. So the auth-server can't "import and decrypt" them
for JIT; it must verify a *live* password attempt against GlobalSKU. GlobalSKU
exposes exactly one internal endpoint for that:

```
POST {GLOBALSKU_BASE_URL}/api/internal/verify-legacy-password
Content-Type: application/json
Body: {"email": "...", "password": "..."}
→ 200 {"valid": true, "user": {"email": "...", "name": "..."}}   // correct creds
→ 200 {"valid": false}                                            // wrong pw OR unknown email (uniform, by design)
```

That endpoint is effectively a **password oracle**, so it is HMAC-gated.
`LEGACY_AUTH_VERIFY_SECRET` is a **shared random secret** (NOT GlobalSKU's
password-hashing key — bcrypt has none) whose only job is to prove the caller is
the real auth-server. Every request must carry:

```
X-Auth-Timestamp: <unix seconds>          // rejected if >300s skew
X-Auth-Signature: SHA256:<base64( HMAC_SHA256( secret, "{timestamp}.{rawBody}" ) )>
```

`rawBody` is the exact JSON bytes sent. Wrong/missing signature → `401`; the
endpoint returns `500` if GlobalSKU itself has no secret configured. The value
is identical on both sides; for the current dev environment it is already set in
GlobalSKU's `.env`.

**What to build.** A `pkg/migration/globalsku/` adapter implementing
`migration.LegacyAuthProvider`, mirroring `pkg/migration/cognito`:

```go
type Config struct { BaseURL, VerifySecret string; HTTPTimeout time.Duration }
func New(cfg Config) (*Adapter, error)        // validates BaseURL + VerifySecret non-empty
func (a *Adapter) Name() string { return "globalsku" }
func (a *Adapter) TryLogin(ctx, email, password) (*migration.LegacyUser, error)
```

`TryLogin` must:
1. Marshal `{"email","password"}`, capture the **exact bytes** for signing.
2. Compute `ts := now.Unix()`, `sig := "SHA256:"+base64(hmac_sha256(secret, ts+"."+body))`.
3. POST with the two headers above + JSON content-type, honoring `ctx` + timeout.
4. Map the response:
   - `200 {"valid":true}` → return `&migration.LegacyUser{Email: resp.user.email,
     FirstName/LastName: split(resp.user.name), EmailVerified: true}`
     (GlobalSKU returns a single `name`; split on first space. Roles: none —
     GlobalSKU keeps roles local in Spatie, so leave `Roles` empty → the user
     gets the default `base_user`; that's correct for Phase 1.)
   - `200 {"valid":false}` → return `migration.ErrLegacyLoginFailed` (GlobalSKU
     can't distinguish unknown-email from wrong-password by design; either way
     "no migration", and `AuthService` surfaces a clean `InvalidCredentials`).
   - `401`/`5xx`/transport/timeout → return a wrapped transient error (NOT
     `ErrLegacyUserNotFound`), so a GlobalSKU outage fails the login closed
     rather than silently skipping migration.

**Config + wiring** (mirror `COGNITO_AUTO_MIGRATE_*` in `internal/config` +
`cmd/server/main.go`):

```
GLOBALSKU_LEGACY_MIGRATION_ENABLED=true
GLOBALSKU_BASE_URL=https://globalsku.app           # or the env's host
GLOBALSKU_LEGACY_VERIFY_SECRET=<same value as GlobalSKU's LEGACY_AUTH_VERIFY_SECRET>
```

```go
// cmd/server/main.go, alongside the Cognito block
if cfg.GlobalSkuMigration.Enabled {
    gsk, err := globalsku.New(globalsku.Config{
        BaseURL:      cfg.GlobalSkuMigration.BaseURL,
        VerifySecret: cfg.GlobalSkuMigration.VerifySecret,
    })
    if err != nil { logger.Error("globalsku migration adapter init failed", "err", err) }
    else { authService.WithLegacyAuthFor("globalsku", gsk, nil) }   // per-app registry (§5)
}
```

Registering it under `app_code = "globalsku"` means the JIT path fires only for
logins resolved to the `globalsku` app — every other app is unaffected
(`legacyProviderFor` returns nil → no fallback).

**Acceptance (adds to §5):** with `GLOBALSKU_LEGACY_VERIFY_SECRET` matching
GlobalSKU's, an un-imported GlobalSKU user logging in via `globalsku` with their
real password is verified over the signed endpoint, migrated (passwordless-free —
the password the user just typed is what gets bcrypt-hashed locally), tagged
`globalsku`, and logged in. A tampered/missing signature is rejected by GlobalSKU
(`401`) and the login fails transiently. A wrong password → `{"valid":false}` →
clean `InvalidCredentials`.

---

## Cross-cutting

- **Ordering.** §1 (app-context) is the foundation — do it first; §2/§3/§5 all
  depend on correct namespace resolution. §4 can proceed in parallel. §5 depends
  on §1 + the GlobalSKU verify channel.
- **Config.** New env: `SSO_APPLE_*` (§3); `SSO_FACEBOOK_*` / `SSO_LINKEDIN_*`
  (§6). No new env for §1/§2/§4 (namespaces are app config). §5 per-provider env
  lives with each adapter (mirror `COGNITO_AUTO_MIGRATE_*`) — for GlobalSKU that's
  `GLOBALSKU_LEGACY_MIGRATION_ENABLED` / `GLOBALSKU_BASE_URL` /
  `GLOBALSKU_LEGACY_VERIFY_SECRET` (§5.1).
- **Migrations.** None expected for §1/§2/§3/§5 (pools stay virtual). §4 may add
  an audit/import-log table if desired; the `users`/`user_namespaces` schema is
  already sufficient.
- **Backward compatibility.** Every change must no-op for apps with no namespace
  config and no legacy provider — un-namespaced callers keep resolving `default`,
  `WithLegacyAuth(nil)` keeps JIT off. Confirm existing Cognito + default-pool
  tests stay green.
- **Docs to update in the same change:** `USER_POOLS.md` §6 (remove/limit the
  "default only" caveat as flows become app-aware), `APP_REGISTRATION.md`
  (Apple auth method; bulk-import + JIT for app onboarding), and any SSO provider
  list / env reference.

## File pointers (verified)

- Routes: `internal/api/routes/routes.go` (apps `:247`, users/lookup `:195`)
- Auth handlers: `internal/api/handlers/auth_handler.go`
- User handler: `internal/api/handlers/user_handler.go` (~406–461)
- App handler: `internal/api/handlers/app_handler.go` (~26–96)
- Auth service: `internal/service/auth/{auth_service.go,auth_login.go,auth_migration.go,auth_registration.go,auth_password.go}`
- User service: `internal/service/user_service.go`
- Repo: `internal/repository/postgres/user_repository.go` (`GetByEmailInNamespaces`)
- Domain: `internal/domain/{app.go,user.go}` (`WriteNamespace`/`ReadNamespaces`)
- SSO: `internal/auth/sso/{manager.go,google.go,custom.go,apple.go}`
- JWT: `internal/auth/jwt/service.go` (HS256)
- Migration framework: `pkg/migration/migration.go`, `pkg/migration/cognito/cognito.go`
- Config: `internal/config/config.go` (bcrypt cost 12, range 10–14)
- Seed: `cmd/seed/main.go`
- Pools design: `docs/USER_POOLS.md`

---

## 6. Facebook / LinkedIn SSO adapters (added 2026-06-22 — remaining work)

**Decision.** GlobalSKU's FB/LinkedIn logins federate by becoming **first-class
auth-server SSO providers**, flowing through the existing SSO bridge exactly like
Google/Apple. The earlier "GlobalSKU Socialite passthrough" idea is dropped — it
required provisioning a passwordless identity, which no current endpoint supports
cleanly (`/auth/register` forces a password; `bulk-import` forces a hash). Adding
the providers reuses the SSO user-creation path (`auth_sso.go:94-117`) that
already creates passwordless `auth_provider`/`provider_user_id` users correctly.

**Required behavior.** Two new providers in `internal/auth/sso/`, modeled on
`google.go` / `apple.go` and registered in `manager.go` (drop any
`logSSONotImplemented` path for them):

- **Facebook** (`facebook.go`): OAuth2 authorization-code + PKCE. Auth/token
  endpoints on `facebook.com`/`graph.facebook.com`; fetch profile from
  `GET /me?fields=id,email,first_name,last_name` (Graph API). Scopes
  `email,public_profile`. Map `id`→`provider_user_id`, `email`→email
  (⚠️ email can be absent if the user registered by phone — tolerate it like
  Apple's no-email case). `email_verified` is implicitly true for FB-returned
  emails.
- **LinkedIn** (`linkedin.go`): OIDC (LinkedIn "Sign In with LinkedIn using
  OpenID Connect"). Scopes `openid profile email`; discovery/userinfo via
  LinkedIn's OIDC endpoints; parse the `id_token`/userinfo for `sub`
  (→`provider_user_id`), `email`, `email_verified`, `given_name`/`family_name`.
- Config keys mirroring the others, wired in `internal/config/config.go`:
  `SSO_FACEBOOK_ENABLED|CLIENT_ID|CLIENT_SECRET`,
  `SSO_LINKEDIN_ENABLED|CLIENT_ID|CLIENT_SECRET`.
- The SSO upsert must honor app-context namespaces from §1/§2 (new user → app's
  write namespace `default` + `globalsku` tag), same as Google/Apple.
- Add `facebook` + `linkedin` to the `globalsku` app's `allowed_auth_methods`.

**Acceptance:** a Facebook login and a LinkedIn login through `globalsku` each
resolve/create the one core user (passwordless, `auth_provider` set), tag
`globalsku`, round-trip PKCE/OIDC, and return the standard token pair. Unit-test
profile/id_token parsing incl. the no-email-from-Facebook case.

**Files:** `internal/auth/sso/{facebook,linkedin,manager}.go`,
`internal/config/config.go`, plus provider registration where Google/Apple are
registered.

**GlobalSKU side (already done):** `feature/ven-auth-bridge` renders
`Continue with Facebook` / `Continue with LinkedIn` bridge buttons
(`route('vauth.bridge.redirect', ['provider' => 'facebook'|'linkedin'])`), gated
on `AUTH_BRIDGE_ENABLED`. No `SocialLoginController` passthrough was built. Once
these adapters ship and are enabled on the `globalsku` app, the buttons work;
GlobalSKU's local FB/LinkedIn Socialite is retired in Phase 3.

---

## 7. Auto-provision app + org + role on globalsku login/registration/migration (added 2026-06-22)

**Trigger.** A password login sending `app_code=globalsku` validated credentials
but returned `403 "user is not authorized for this app"`
(`auth_login.go:309`). Root cause: the user had no active `user_apps` row for
`globalsku` and the app's `auto_grant_on_signup=false`. The GlobalSKU side is
correct — `app_code` is sent in the login body. This is all auth-server work.

### 7.0 Immediate unblock (config only, no code)

Register/patch the `globalsku` app with `auto_grant_on_signup=true` (and the auth
methods + pools from §0). First login then auto-grants the `user_apps` row
(`auth_login.go:312 → appService.GrantUser`). This fixes the 403 for new and
existing users. Does NOT, by itself, give org membership / Seller role / a second
app — that's §7.2.

### 7.1 Current behavior (verified) — the gaps

| Provisioning step | Registration (`auth_registration.go`) | First login (`auth_login.go` ~300-314) | JIT migration (`auth_migration.go`) |
|---|---|---|---|
| `user_apps` membership | **not granted** | granted iff `auto_grant_on_signup` | relies on the login grant |
| namespace tags | yes (`AddUserToNamespaces`) | yes | yes |
| org membership | only if `default_organization_id` set | **no** | **no** |
| org role | **always `org_member`** (not configurable) | — | — |
| additional apps | **none** (no linked-apps concept) | none | none |

So no single path delivers "app membership + `vendidit-marketplace` org as
**seller** + `vendidit-marketplace` app". `seller` role code exists
(`pkg/shared/models/role.go`), `GetOrganizationBySlug` exists — building blocks
are present; the config + wiring are net-new.

### 7.2 Net-new work (app-agnostic — config-driven, no hardcoded globalsku/seller)

1. **App config fields** (`domain.App` + apps migration + POST/PATCH `/admin/apps`
   DTO in `app_handler.go`):
   - `default_role_code *string` — role for the default-org membership
     (replaces the hardcoded `org_member`; e.g. `"seller"`). Validate it's an
     org-scoped role; never `system_admin`.
   - `linked_app_codes []string` — additional app codes whose `user_apps`
     membership is also granted when this app provisions a user.
2. **One idempotent helper** `ensureAppEntitlements(ctx, tx, user, app)` that:
   - grants `user_apps` for `app.ID` **and** each resolved `linked_app_codes`
     (code→id; skip unknown with a warn) via `appRepo.Grant` (idempotent upsert);
   - if `app.DefaultOrganizationID != nil`, ensures org membership via
     `organizationService.AddMember(orgID, user.ID, [roleID(default_role_code ?? org_member)], nil)`
     — idempotent (no-op if already a member; reconcile role via `SetMemberRoles`);
   - ensures namespace tags (already done; keep).
3. **Call it from all three paths**, gated by `auto_grant_on_signup` (or a new
   `auto_provision` flag if you want app-grant and org/role to be independently
   switchable):
   - registration (after user create, inside the txn);
   - login auto-grant branch (`auth_login.go`, replacing the bare `GrantUser`);
   - JIT migration (`auth_migration.go`, after user create) — so auto-migrated
     users get the full entitlement set, not just `base_user`.
   All idempotent so repeated logins are no-ops.

### 7.3 The `globalsku` end-state config (after 7.2 ships)

Pre-reqs: the `vendidit-marketplace` **org** and **app** exist (create via
`POST /admin/organizations` and `POST /admin/apps` if not).

```jsonc
PATCH /api/v1/admin/apps/<globalsku_id>      // system_admin
{
  "auto_grant_on_signup": true,
  "allowed_auth_methods": ["password","google","apple","facebook","linkedin"],
  "registration_namespace": "default",
  "read_namespaces": ["default","globalsku"],
  "default_organization_id": "<vendidit-marketplace org id>",
  "default_role_code": "seller",                 // NEW (§7.2)
  "linked_app_codes": ["vendidit-marketplace"]   // NEW (§7.2)
}
```

Result: any user who logs in / registers / is JIT-migrated through `globalsku`
becomes a member of the `globalsku` **and** `vendidit-marketplace` apps, and a
**seller** in the `vendidit-marketplace` org — automatically, idempotently.

### 7.4 Acceptance

- Existing auth-server user logs in via `globalsku` → no 403; gains `globalsku` +
  `vendidit-marketplace` app membership + seller org membership. Re-login = no-op.
- Brand-new register via `globalsku` → same entitlements at registration time
  (not deferred to a second login).
- JIT-migrated user (via the GlobalSKU `LegacyAuthProvider`, §5.1) → same set.
- An app with none of the new fields set behaves exactly as today (backward-compat).
- Unknown `linked_app_codes` / bad `default_role_code` → warn + skip, never 500.

### 7.5 GlobalSKU side

**No change.** `app_code=globalsku` is already sent in the login body
(`AuthClient::login` → `config.appCode`). The `X-App-Code` header is unnecessary
(body is authoritative and accepted); adding it would be an upstream
`auth-server-php` transport change, not a GlobalSKU app change.
