# User Pools / Namespaces — audit + design

Status: **implemented + verified** — 2026-06-08 (migration 017),
extended 2026-06-09 (migration 018: multiple registration namespaces).
Model **(A) per-namespace uniqueness** was chosen (§4). Captures the
current identity model, answers the namespacing questions, and
documents the shipped read/write user-pool feature. Verified
end-to-end against Postgres (see §7). `wristleo` and `claimleo` are
the first real non-default pools.

## The pool model: one default pool + other pools (migration 018, simplified 2026-06-10)

An app's pool configuration is:

- **Default pool (registration)** — `apps.registration_namespace`
  (single value). New users registered through the app get this as
  their **home namespace** (`users.namespace`, the per-pool
  email-uniqueness anchor and the `namespace` JWT claim). Empty ⇒
  `default`.
- **Other pools (login)** — `apps.read_namespaces`. Two jobs:
  1. login + register match existing users across `[default pool,
     ...other pools]` (home namespace OR `user_namespaces` tag);
  2. new registrants are **tagged** (`user_namespaces` rows) into
     every other pool, so they belong to the app's whole pool set.

Worked example — **claimleo** with default pool `default` and other
pools `[wristleo, claimleo]`: a new user lives in the shared `default`
pool (every future default-reading app picks them up) and carries
`wristleo` + `claimleo` tags; existing `default` or `wristleo` users
log straight in — no duplicate identity.

Notes:
- Tags are created only for **new registrations**. Reusing an existing
  user (e.g. `register_or_login` of a `default` user via claimleo)
  does **not** tag them — a possible future opt-in
  (`tag_existing_on_login`).
- `apps.registration_namespaces` (plural) is a legacy column from the
  original 018 shape — when non-empty its first entry acts as the
  default pool. New configs use the singular field; the admin UI
  clears the plural on save.
- Resolution helpers: `App.WriteNamespace()` = the default pool;
  `App.EffectiveReadNamespaces()` = `[default pool, ...other pools]`
  (ordered, de-duplicated) — element 0 is always the home pool for
  new users, elements 1..n are the tag set.

## Pool administration (2026-06-10)

Pools are managed at runtime via system_admin endpoints (no migration
needed — pools stay virtual):

| Method | Path | Behavior |
|---|---|---|
| GET | `/admin/namespaces` | Every known pool: distinct `user_count` + `home_count`/`tag_count` breakdown + `app_codes` referencing it. Pools referenced only by app config appear with zero users ("empty"). |
| GET | `/admin/users/{id}/namespaces` | `{ namespace: <home>, namespaces: [<tags>] }` |
| PUT | `/admin/users/{id}/namespace` | Move the home pool. 409 `CONFLICT` when the email already exists in the target pool (per-(pool,email) uniqueness). A tag equal to the new home is cleaned up. |
| POST | `/admin/users/{id}/namespaces` | Tag the user into an extra pool (idempotent; tagging the home pool → 400). |
| DELETE | `/admin/users/{id}/namespaces/{ns}` | Remove a tag. Removing the home pool → 400 ("set a different default pool instead"). |

SDK: `@vendidit/auth-client` `NamespacesFlow` (`listNamespaces` is
cached 60s client-side for type-ahead pool pickers; mutations
invalidate). Demo UI: Applications & Services → **User pools** tab
(catalog), the app editor's pool pickers, and the admin user page's
**User pools** section.

## 1. Audit — how identity works today

**There is no user "pool" or "namespace" concept today. Users are a
single global identity space.**

- **`users.email` is globally unique.** `migrations/001` declares
  `CREATE UNIQUE INDEX users_email_unique ON users(email) WHERE
  deleted_at IS NULL`. One email = exactly one user row, forever,
  across the entire platform.
- **`userRepo.GetByEmail(email)` is global.** Both `AuthService.Register`
  and `AuthService.Login` resolve the user with a single global
  `GetByEmail` — no app/namespace scoping in the lookup.
- **Apps are an *access + policy* layer, not an identity namespace.**
  An `apps` row carries `service_codes`, `auto_grant_on_signup`,
  `allowed_redirect_urls`, and the migration-013 *registration policy*
  (`allowed_email_domains`, `allowed_auth_methods`,
  `default_organization_id`, `frontend_url`). None of these segregate
  *identity* — they gate who may enter (`user_apps` membership) and
  which permissions/org the token carries.
- **Organizations** are the closest existing grouping, but they're
  RBAC membership groupings layered on the one global user — not
  identity pools. A user is one global identity that belongs to N orgs.

### Answers to the specific questions

> **How is it namespacing users?**
It isn't. Every user lives in one implicit global pool keyed by a
globally-unique email.

> **Does it put all users in the default pool unless given a different app namespace?**
Effectively there is only the (implicit) global pool. Apps cannot
direct a user into a different identity pool today — `app_code` changes
*access* and *token scope*, never *which user record* an email maps to.

> **When users log in, is it checking the auth user pools by namespace correctly?**
There are no pools to check. Login looks the user up by global email,
then verifies `user_apps` *access* membership for the resolved
`app_code`. So it checks app **access**, not pool **identity**.

**Conclusion:** the requested workflow (apps choosing read pools + a
write pool, with existing-user reuse across pools) is **not currently
supported** and requires a new namespace dimension on `users` plus
read/write namespace config on `apps`.

---

## 2. Desired workflow (restated)

- Every user belongs to one **namespace/pool** (default: `default`).
- An app may declare:
  - **`registration_namespace`** (the *write* pool) — which pool new
    users created through this app are written into. Default `default`.
  - **`read_namespaces`** (the *read* pools) — the set of pools this
    app authenticates / validates users against at login. Default:
    just its write pool (which, unconfigured, is `default`).
- **Login**: resolve the app → find the user by email **within the
  app's read namespaces** → authenticate.
- **Register**: resolve the app → if a user with that email already
  exists in **any read namespace**, reuse it (no duplicate identity);
  otherwise create a **new** user in the **write** namespace.
- All of this is **opt-in**. An app with no namespace config reads and
  writes `default` → behaves exactly as today.

This lets an app capture *new* users into its own pool while still
honoring *existing* users from the shared `default` pool (or any other
listed pool), so people don't re-create themselves per app.

---

## 3. Design

### 3.1 Schema (new migration `017_user_namespaces`)

```sql
-- users gain a home namespace.
ALTER TABLE users
    ADD COLUMN namespace VARCHAR(100) NOT NULL DEFAULT 'default';

-- Email uniqueness becomes per-namespace (see §4 for the decision).
DROP INDEX users_email_unique;
CREATE UNIQUE INDEX users_namespace_email_unique
    ON users(namespace, email) WHERE deleted_at IS NULL;
DROP INDEX idx_users_email;
CREATE INDEX idx_users_namespace_email
    ON users(namespace, LOWER(email)) WHERE deleted_at IS NULL;

-- apps gain read/write pool config (both optional → default behavior).
ALTER TABLE apps
    ADD COLUMN registration_namespace VARCHAR(100),          -- NULL/'' ⇒ 'default'
    ADD COLUMN read_namespaces        TEXT[] NOT NULL DEFAULT '{}';  -- empty ⇒ [write ns]
```

All existing rows get `namespace='default'`; all existing apps get
`registration_namespace=NULL` + `read_namespaces='{}'` → unchanged
behavior.

### 3.2 Domain helpers (on `App`)

```go
// WriteNamespace — pool new users register into. Defaults to "default".
func (a *App) WriteNamespace() string {
    if a == nil || a.RegistrationNamespace == nil || *a.RegistrationNamespace == "" {
        return "default"
    }
    return *a.RegistrationNamespace
}

// ReadNamespaces — pools this app authenticates against. Always
// includes the write namespace; falls back to ["default"] when nothing
// is configured. De-duplicated.
func (a *App) ReadNamespaces() []string { ... } // union(read_namespaces, WriteNamespace())
```

`User` gains `Namespace string` (`db:"namespace"`, default `"default"`
in `domain.NewUser`).

### 3.3 Repository

- Add `GetByEmailInNamespaces(ctx, email, namespaces []string) (*User, error)`
  → `WHERE email=$1 AND namespace = ANY($2) AND deleted_at IS NULL`,
  ordered so `default` (or the first listed) wins deterministically when
  an email exists in more than one readable pool.
- Keep `GetByEmail(email)` for legacy/global flows; it resolves the
  `default` namespace (every pre-feature user is `default`, so no
  behavior change). SSO / password-reset / check-email / admin lookup
  stay on this path in v1 (see §6 limitations).

### 3.4 Register flow change

At the existing collision check, replace the global `GetByEmail` with a
read-namespace lookup driven by the resolved `registrationApp`:

```go
readNs := registrationApp.ReadNamespaces()           // ["default"] when unconfigured
existing, err := s.userRepo.GetByEmailInNamespaces(ctx, email, readNs)
// ...same mode dispatch (register / register_or_login / register_or_return)...
// On create:
user := domain.NewUser(email, first, last)
user.Namespace = registrationApp.WriteNamespace()    // "default" when unconfigured
```

So a brand-new email gets written to the app's write pool; an email
already present in a readable pool is reused (login / link), never
duplicated.

### 3.5 Login flow change

```go
readNs := resolvedApp.ReadNamespaces()
user, err := s.userRepo.GetByEmailInNamespaces(ctx, email, readNs)
```

Base-user mode (no app) and the legacy/Cognito fallback keep using the
`default` namespace.

### 3.6 Token claims

Add an optional `namespace` claim to the access token (and surface it
on `/auth/me`) so downstream services + the client can see which pool
the authenticated identity belongs to. Empty/`default` omitted for
wire economy if desired.

### 3.7 Admin API + DTO

`POST /admin/apps` + `PUT /admin/apps/{id}` accept
`registration_namespace` (string) + `read_namespaces` (string[]),
echoed on read. Validation: kebab/lower-case, ≤100 chars, no spaces.

### 3.8 auth-client

The namespace is **app-level server config**, not a per-login client
input — so the browser client doesn't pass it on `login`. Client work
is: surface `namespace` on the decoded user/claims type, and (in
`auth-server-ts` / `auth-server-nest` admin helpers, if present) accept
the two new fields when creating/updating an app. Docs updated to
explain pools.

### 3.9 Backwards compatibility

Every change defaults to `default`. Unconfigured apps + all existing
users behave identically. The feature only activates when an app sets
`registration_namespace` and/or `read_namespaces`.

---

## 4. The decision that needs sign-off

**Email uniqueness scope.** The feature as described implies the same
email can be a *separate identity* in two pools (you can "register new
users to a unique pool" that already exist elsewhere only via the
read-list; truly new ones get their own record). Two ways to model it:

- **(A) Per-namespace uniqueness** — `UNIQUE(namespace, email)`.
  `alice@x.com` in `default` and `alice@x.com` in `wristleo` are *distinct
  users*. Full pool segregation (Cognito-style). **Matches your
  description.** Cost: drops the global "one email = one human"
  invariant; every email-only flow (SSO upsert, password-reset-request,
  check-email, admin lookup-by-email) must either take a namespace or
  default to `default`. **Recommended** — it's the only model that
  actually delivers separable pools.
- **(B) Global uniqueness + namespace tag** — keep `UNIQUE(email)`;
  `namespace` is just a "home pool" label on the single global record.
  Lighter + preserves the global invariant, but an email is always the
  same person everywhere, so apps can't truly own a private pool of the
  same address. Simpler, but doesn't fully satisfy the ask.

This doc specifies **(A)**. It's the consequential, mostly-one-way
schema-semantics change, which is why it's flagged before the migration
runs.

---

## 5. Implementation plan (layers, in order)

1. `migrations/017_user_namespaces.{up,down}.sql` — §3.1.
2. `internal/domain/user.go` (+ `NewUser` default), `internal/domain/app.go`
   (fields + `WriteNamespace`/`ReadNamespaces`).
3. `internal/repository/interfaces.go` + `postgres/user_repository.go` —
   `GetByEmailInNamespaces`; `Create`/scans include `namespace`.
4. `internal/service/auth_registration.go` / `auth_login.go` — Register + Login resolution
   (§3.4, §3.5).
5. `internal/auth/jwt/*` — optional `namespace` claim (§3.6).
6. `internal/api/dto/*` + `handlers/app.go` + `service/app_service.go` —
   accept/echo the two app fields (§3.7).
7. `internal/config` — no new env required (defaults live in schema).
8. auth-client + auth-server-ts/nest types + docs (§3.8).
9. Docs: this file, `APP_REGISTRATION.md` (§ pools), `How_It_Works.md`
   (multi-tenant model), `README.md`, auth-client `README.md`.

## 6. Known limitations for v1 (documented, deferrable)

- ~~SSO upsert, password-reset-request, `/auth/check-email`, and
  admin-lookup-by-email resolve in `default` only.~~ **Resolved
  (GlobalSKU integration §1).** These flows now resolve the app context
  and use the app's read pools:
  - **App-context resolution** uses the existing `app_code` channel (no
    new middleware): the **`X-App-Code` header** for unauthenticated
    flows (SSO start, password-reset-request), with the request-body
    `app_code` as a fallback; for the authenticated `/auth/check-email`
    the **JWT `app_code` claim** is authoritative (header → body
    fallback). No app context ⇒ `default` (unchanged behavior).
  - **SSO upsert** carries `app_code` through the SSO `state` (captured at
    `/auth/sso/url`), resolves the user by `GetByEmailInNamespaces` across
    the app's read pools, writes new users into the app's write pool, and
    tags + grants the app namespace (auto-grant honored).
  - **password-reset-request / resend-verification / check-email** all use
    `resolveReadNamespaces(appCode)` instead of the bare `default` lookup.
  - **admin lookup-by-email** (`POST /admin/users/lookup`) is a bulk,
    cross-pool resolver and returns each user's `namespace`, so a
    namespaced caller disambiguates by that field; the `ven_user_id`
    backfill path now also gets uids directly from bulk-import (§4).
- A user belongs to exactly one home namespace. "Same human, two pools"
  is *by design* two records under model (A); linking them is out of
  scope.

## 7. Local test plan (after implementation)

1. `make docker-up`; seed `system_admin`.
2. Create two apps: `app-default` (no namespace config) and
   `wristleo` (`registration_namespace=wristleo`,
   `read_namespaces=["default","wristleo"]`).
3. Register `new@x.com` via `wristleo` → lands in `wristleo`.
4. Register/login an existing `default` user via `wristleo` → reused
   from `default`, not duplicated.
5. Login `new@x.com` via `app-default` → **not found** (isolation: it's
   in `wristleo`, which `app-default` doesn't read).
6. Verify `app_id`/`namespace`/roles claims + `user_apps` segregation.
