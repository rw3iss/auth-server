# App Registration — rw3iss Auth

How a new app gets wired into the rw3iss auth system. Every consumer — backend service, frontend SPA, mobile client, or internal tool — goes through this same flow, once.

For the broader picture (token lifecycle, multi-tenant model) see [`How_It_Works.md`](./How_It_Works.md). This doc covers *only* the onboarding contract.

---

## TL;DR

```
1. system_admin POSTs to /admin/apps with the new code + allowed redirect URLs
2. New app sets two env vars: RW3ISS_APP_CODE + JWT_ACCESS_SECRET
3. New app calls /auth/login with app_code; gets back a JWT scoped to that app
```

Three steps total. Step 1 is one-time per app. Steps 2-3 are normal config + runtime.

> **Note**: a dedicated `auth-cli` wrapping the admin REST surface is planned but not yet shipped. Today's flow is the REST API directly — example payloads in §2 below.

---

## 1. Concepts in one paragraph each

**App.** A user-facing consumer of rw3iss auth — anything that initiates logins or holds access tokens. Identified by a stable `code` (e.g. `marketplace-v2`, `release-manager`). One row in the `apps` table. Owns its redirect-URL allowlist, opt-in/out of auto-grant, and the set of permission *services* it consumes. Required before tokens can be minted for it.

**Service.** A backend that owns and declares a slice of the permission catalog. Identified by a stable string (e.g. `auction-api`, `billing`). A service self-registers its permissions at boot via `POST /admin/permissions/register`; auth-server reconciles (upserts new, prunes removed). Most apps are 1:1 with a service of the same code. Pure-frontend apps may have no service at all and still work fine — they just don't carry custom permissions.

**`user_apps` membership.** A row per (user, app) pair indicating the user is allowed into that app. Created either automatically on first login (`auto_grant_on_signup: true`) or explicitly by an admin (`POST /admin/users/{userId}/apps/{appId}`).

---

## 2. The registration step (one-time per app)

A system_admin creates the app row via the admin REST API.

### Step-by-step

1. **Get a system_admin access token.** Log in via the demo at [demo.auth.ryanweiss.net](https://demo.auth.ryanweiss.net) as a user with the `system_admin` role (today: `demotest@ryanweiss.net`). Copy the access token from the browser devtools (any authed request → `Authorization` header), or log in over the REST API and capture the token from the response.

2. **POST to `/admin/apps`** with the new app's config:

```http
POST /admin/apps
Authorization: Bearer <system-admin-token>
Content-Type: application/json

{
  "code": "marketplace-v2",
  "name": "Marketplace v2",
  "description": "Public marketplace, browser SPA",
  "allowed_redirect_urls": ["https://marketplace-v2.ryanweiss.net/auth/callback"],
  "service_codes": ["marketplace-v2"],       // optional; defaults to [code]
  "auto_grant_on_signup": true,              // optional; default false
  "registration_namespace": "default",       // optional WRITE pool; default "default"
  "read_namespaces": ["default"],            // optional READ pools; default [write ns]
  "default_organization_id": "<org id>",     // optional; org new users are auto-added to
  "default_role_code": "org_manager",        // optional (§7); org role for that membership; default org_member
  "linked_app_codes": ["rw3iss-marketplace"], // optional (§7); extra apps to also grant
  "status": "active"
}
```

Quick `curl` form:

```bash
curl -X POST https://auth.ryanweiss.net/api/v1/admin/apps \
  -H "Authorization: Bearer $RW3ISS_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "code": "marketplace-v2",
    "name": "Marketplace v2",
    "allowed_redirect_urls": ["https://marketplace-v2.ryanweiss.net/auth/callback"],
    "auto_grant_on_signup": true
  }'
```

### Future: `auth-cli`

A dedicated `@rw3iss/auth-cli` wrapping this (`auth login`, `auth apps:create`, `auth users:roles`, `auth m2m:create`, …) is on the roadmap. It will use the developer's system_admin token (cached at `~/.rw3iss/auth` or `RW3ISS_ADMIN_TOKEN` env) and POST to the same REST surface. Until it ships, the curl/Postman form above is canonical.

Response:

```json
{
  "id": "9c1f...",
  "code": "marketplace-v2",
  "status": "active",
  "created_at": "..."
}
```

That's the whole platform-side setup.

### Editing after creation (PATCH)

`PATCH /admin/apps/{appId}` accepts every field except `code` (immutable):
name, description, redirect URLs, service codes, auto-grant, status, the
pool fields, **and** (since 2026-06-10) the registration-policy fields —
`frontend_url`, `allowed_email_domains`, `allowed_auth_methods`,
`default_organization_id`, **and** (since 2026-06-22, §7)
`default_role_code` + `linked_app_codes`. Pass `""` for `frontend_url` /
`default_organization_id` / `default_role_code` to clear back to NULL. Mind the
blast radius of `frontend_url`: verification / reset / magic-link / invitation
emails link to that origin, so a wrong value strands those flows for live users.

### Auto-provisioning: default role + linked apps (§7, migration 020)

When `auto_grant_on_signup: true`, the **first** time a user touches the app
(register, first login, or JIT migration) the server provisions a full
entitlement set, idempotently:

- a `user_apps` membership for this app **and** each of `linked_app_codes`
  (code→id; unknown codes are skipped with a warning, never fatal);
- if `default_organization_id` is set, an org membership with
  `default_role_code` (falling back to `org_member`).

`default_role_code` **must be an org-scoped role** — platform roles
(`system_admin` / `super_admin` / `base_user`) are refused and fall back to
`org_member`.

**Validated at config time.** `POST`/`PATCH /admin/apps` rejects (400) a
`default_role_code` that (a) is set without a `default_organization_id` (the
role has no org to attach to), or (b) names a role that doesn't exist or isn't
org-scoped. So a typo surfaces immediately rather than silently degrading to
`org_member` at login. `linked_app_codes` are NOT existence-checked at config
time (an app may be linked before its target exists); unknown codes are skipped
with a warning during provisioning.

**Per-request override.** A client may pass `role_code` and/or
`linked_app_codes` in the **login or register body** to override the app's
defaults for that request (e.g. registering an org_member vs. an org_manager through the
same app). The app config is the fallback. `role_code` is re-validated
server-side as an org-scoped role, so a client can never escalate to a platform
role. Example:

```jsonc
POST /auth/login
{ "email": "...", "password": "...", "app_code": "globalsku",
  "role_code": "org_manager", "linked_app_codes": ["rw3iss-marketplace"] }
```

### Webhooks (migration 019)

Apps can declare outbound webhooks fired on app events — currently
`user.registered` (new-user creation through the app; never plain
logins):

```jsonc
{
  "webhooks": [
    { "name": "Slack #signups",
      "url": "https://hooks.slack.com/services/T…/B…/x…",
      "events": ["user.registered"],
      "enabled": true }
  ]
}
```

Settable at create and PATCH (non-nil replaces the list; `[]` removes
all). Delivery is async + best-effort: 3 attempts, 5s timeout, linear
backoff; permanent 4xx drops without retry; registration never blocks
or fails on a webhook. The JSON envelope carries the app, the new user
(with pools), any org landed in, the **complete registration body**
(password redacted — extra client fields like referral codes pass
through verbatim), and request context (ip / user-agent / issuer),
plus an `X-rw3iss-Event` header. URLs under `hooks.slack.com`
receive a Slack-formatted `{"text": …}` summary instead of the raw
envelope.

### What gets validated at registration

- `code` is unique, kebab-case, ≤100 chars.
- `allowed_redirect_urls` is non-empty in production mode (refused by config validation).
- `service_codes` defaults to `[code]` if omitted; entries are stable strings, not required to point at a service that exists yet (a service can register later).
- `registration_namespace` / `read_namespaces` default to the `default` user pool. Namespaces are lower-case `[a-z0-9_-]`, ≤100 chars. See "User pools" below.

### User pools (optional, migration 017)

By default every user lives in one global pool (`default`) and an app
reads + writes that pool — identical to pre-017 behavior. Apps that want
**segregated identity** set two fields:

- **`registration_namespace`** — the **default pool (registration)**,
  a single value. New users registered through this app get it as
  their home namespace (`users.namespace`). Omit ⇒ `default`.
- **`read_namespaces`** — the **other pools (login)**. Login +
  register match existing users across `[default pool, ...other
  pools]` (home **or** tag), so an account already in one of the
  app's pools is **reused, not duplicated** — and new registrants are
  **tagged** into every other pool. The default pool is always
  implicitly included. Omit ⇒ just the default pool.
- *(legacy)* `registration_namespaces` (plural) — original 018 shape;
  when non-empty its first entry acts as the default pool. Prefer the
  singular field.

Email is unique **per namespace**, so the same address can be a distinct
identity in two pools. Worked examples + the full semantics live in
[`USER_POOLS.md`](./USER_POOLS.md).

Example — the Wristleo app owns its own pool but still lets existing
rw3iss users in:

```json
{
  "code": "wristleo",
  "name": "Wristleo",
  "allowed_redirect_urls": ["https://wristleo.example.com/cb"],
  "registration_namespace": "wristleo",
  "read_namespaces": ["default", "wristleo"]
}
```

New emails → the `wristleo` pool; existing `default` users authenticate
without re-registering. An app that omits both fields stays on
`default` and behaves exactly as before.

---

## 3. The consumer's side (per environment)

The new app sets two env vars and calls the API. The shape of "calling the API" depends on the app type.

### Required env

```
RW3ISS_AUTH_URL=https://auth.ryanweiss.net
RW3ISS_APP_CODE=marketplace-v2
JWT_ACCESS_SECRET=<shared with auth-server, ≥32 chars>
```

The JWT secret is the same one the auth-server signs with; sharing it lets the consumer validate access tokens locally (HMAC signature) without a network hop per request.

### Backend-only API (Node)

```ts
import { AuthClientModule } from '@rw3iss/auth-server-nest';

AuthClientModule.forRoot({
  authUrl: process.env.RW3ISS_AUTH_URL,
  appCode: process.env.RW3ISS_APP_CODE,
  jwtSecret: process.env.JWT_ACCESS_SECRET,
});

// In a controller:
@UseGuards(AuthGuard)
@Get('/me/orders')
listOrders(@CurrentUser() user) { ... }
```

The SDK validates the bearer token locally and asserts `claims.app_id` matches this app's code. Any mismatch → 401.

### Frontend SPA (Preact / React)

The browser SDK ([`@rw3iss/auth-client`](https://github.com/rw3iss/auth-client)) is the canonical way to integrate. It handles `app_code` on every login, refresh-token rotation, BroadcastChannel cross-tab sync, and PKCE for SSO. See [auth-docs.rw3iss.com/auth-client/](https://auth-docs.rw3iss.com/auth-client/overview/) for the full surface.

Minimal example:

```ts
import { createAuthClient } from '@rw3iss/auth-client';

const auth = createAuthClient({
  apiBaseUrl: 'https://auth.ryanweiss.net/api/v1',
  appCode: 'marketplace-v2',
});

await auth.login({ email, password });
```

### Mobile / server-to-server

Same HTTP contract as the SPA. Until language-specific SDKs exist, consumers do direct REST calls. The wire protocol is stable.

---

## 4. What's in the issued JWT

When a user logs in with `app_code: "marketplace-v2"`, the access token carries:

| Claim | Value |
|---|---|
| `app_id` | the marketplace-v2 UUID |
| `app_code` | `"marketplace-v2"` |
| `uid` | user UUID |
| `email`, `first_name`, `last_name` | user identity |
| `org_id`, `org_slug` | optional org context |
| `roles` | role codes (e.g. `["base_user"]`) |
| `permissions` | union of permissions across services in `apps.service_codes`, **plus** all `core` permissions |
| `tv` | per-user token version (for logout-everywhere — see AUDIT §1.10) |
| `iss`, `aud`, `exp`, `nbf`, `iat`, `jti` | standard JWT claims |

`core` permissions (auth-server's own slice — `users:read_self`, `users:update_self`, etc.) are always included regardless of which app the token is scoped to. They're the bedrock catalog every user gets.

If the app's `service_codes` list services that haven't registered any permissions yet, the `permissions` array is just `core` + whatever role-based perms the user has. That's fine — the app simply doesn't carry custom permissions yet.

---

## 5. Adding custom permissions (optional, later)

When the new app wants to introduce its own permissions (e.g. `listings:create`, `bids:place`):

1. The app's **backend** calls on boot:
   ```http
   POST /admin/permissions/register
   Authorization: Bearer <service-account-or-system-admin>

   {
     "service": "marketplace-v2",
     "permissions": [
       { "code": "listings:create", "name": "Create listing", "resource": "listings", "action": "create" },
       { "code": "bids:place",      "name": "Place bid",      "resource": "bids",     "action": "place" }
     ]
   }
   ```
2. Auth reconciles: upserts these, prunes any previously-declared marketplace-v2 permissions not in the list. Idempotent — safe to call every boot.
3. A system_admin assigns the new permissions to roles via the existing role-permission API.
4. Users with those roles, logging into marketplace-v2, see the permissions in their JWT.

This step is **purely opt-in**. Apps that don't need custom permissions never call this.

---

## 6. Granting users access

Two modes, set on the `apps` row:

- **`auto_grant_on_signup: true`** — every user who logs into the app gets a `user_apps` row on first attempt. Use for public consumer apps where any rw3iss user can enter.
- **`auto_grant_on_signup: false`** (default) — users must be explicitly granted:
  ```http
  POST /admin/users/{userId}/apps/{appId}
  Authorization: Bearer <system-admin>
  ```
  Use for internal tools and paid-tier apps.

A user can be revoked from one app without affecting their session in others:

```http
DELETE /admin/users/{userId}/apps/{appId}
```

This sets the `user_apps.status` to `revoked` and bumps the user's token version, so their currently-valid access token for that app stops validating on the next request.

---

## 7. What's required vs. optional, at a glance

| Step | Required? | Who | When |
|---|---|---|---|
| Create the app row | **Yes** | system_admin (POST /admin/apps) | Once per app |
| Set `RW3ISS_APP_CODE` + `JWT_ACCESS_SECRET` env | **Yes** | the new app | Per environment |
| Pass `app_code` on `/auth/login` | **Yes** | the new app | Every login |
| Register a service catalog (`permissions/register`) | No | the new app's backend | Boot, only if the app owns custom permissions |
| Grant users via `user_apps` | No (if `auto_grant_on_signup`) | system_admin or auto | First login or explicit grant |
| Configure SSO providers | No | system_admin | Only if the app accepts third-party login |

---

## 8. Common pitfalls

- **Forgetting `app_code` on login.** Returns either a 400 (when `app_code` is required globally) or a token without an `app_id` claim, depending on config. Downstream services that enforce `claims.app_id == self.app_id` will reject the token.
- **Redirect URL mismatch.** `https://marketplace-v2.ryanweiss.net/auth/callback` registered, request goes to `https://marketplace-v2.ryanweiss.net/auth/callback/` (trailing slash) — strict match, fails. Use the trailing `*` wildcard if you need a path prefix.
- **JWT secret drift.** Auth-server rotates `JWT_ACCESS_SECRET`, the consumer doesn't pick up the change. Validation fails for every request. Rotations need to be coordinated; the dual-secret rotation feature on the Phase C roadmap will fix this.
- **Stale `service_codes` after splitting a backend.** If marketplace-v2's billing logic gets pulled into a separate `billing` service, update `apps.service_codes` to `["marketplace-v2", "billing"]`. Otherwise marketplace-v2 users lose access to billing permissions in their JWT.

---

## 9. References

- [`How_It_Works.md`](./How_It_Works.md) — token lifecycle, multi-tenant model, validation flow
- [`Development.md`](./Development.md) — local setup, migrations, integration tests
- [`AUDIT-2026-05-11.md`](../.claude/audits/AUDIT-2026-05-11.md) §1.13 (redirect allowlist), §8.3-8.7 (app scoping rationale)
