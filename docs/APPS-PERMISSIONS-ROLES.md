# Registering an app, defining permissions, assigning them to users

How a new application joins the CivicGate auth server, declares its own permission vocabulary, and gets
those permissions onto real users' tokens.

**Audience:** whoever operates the auth server, or is standing up a new civic portal against it.

---

## 1. The three axes (read this first)

People usually expect one hierarchy. There are three, and they are independent:

| Axis | Column | Answers |
|---|---|---|
| **App** | `apps.code`, `user_apps` | Who may *log in*, and what the token is scoped to |
| **Service** | `permissions.service` | Who *owns* a permission definition |
| **Organization** | `roles.organization_id` | Who a role *belongs to* |

An **app** is a thing people log into (`philly-civics`). A **service** is a thing that owns permission
definitions. Usually one app = one service with the same name, but they are separate because a shared
service (say `billing`) can be consumed by several apps — which is what `apps.service_codes` records.

**Permission codes are unique per SERVICE, not globally** (migration 026). Two apps can both define
`reports.publish` and they are different rows that cannot interfere with each other.

---

## 2. Register the app

```http
POST /api/v1/admin/apps          (system_admin)
Content-Type: application/json

{
  "code": "philly-civics",
  "name": "Philadelphia Civics",
  "description": "City civic portal",
  "allowed_redirect_urls": ["https://philly.example.org/auth/callback"],
  "service_codes": ["philly-civics"],
  "auto_grant_on_signup": true,

  "allowed_email_domains": [],
  "allowed_auth_methods": ["password", "google"],
  "default_organization_id": null
}
```

| Field | Why it matters |
|---|---|
| `code` | Permanent. Every token issued for this app carries it as `app_code`. |
| `service_codes` | Which services' permissions this app consumes. **Set this** — it is the app→permission link. |
| `auto_grant_on_signup` | `true` = anyone registering with this `app_code` is granted access. `false` = an admin grants each user explicitly. |
| `allowed_email_domains` | Restricts who may register (e.g. `["phila.gov"]` for a staff-only portal). Empty = anyone. |
| `default_organization_id` | New users are placed in this org, so org roles can apply immediately. |

Your signup form should **read** the policy rather than duplicating it:

```http
GET /api/v1/apps/philly-civics/registration-policy        (public)
```

Other app routes: `GET /admin/apps`, `GET /admin/apps/{appId}`, `PATCH /admin/apps/{appId}`,
`DELETE /admin/apps/{appId}`.

---

## 3. Declare your permissions

```http
POST /api/v1/admin/permissions/register        (system_admin)
Content-Type: application/json

{
  "service": "philly-civics",
  "permissions": [
    { "code": "reports.publish", "name": "Publish reports",
      "resource": "reports", "action": "publish",
      "category": "content", "org_assignable": true },

    { "code": "budget.approve", "name": "Approve budget items",
      "resource": "budget", "action": "approve",
      "category": "finance", "org_assignable": false }
  ]
}
```

Response: `{ "service": "philly-civics", "upserted_count": 2 }`

### This is a DECLARATIVE SYNC, not an append

`SyncForService` upserts everything you send, then **deletes any permission previously owned by this
service that you did not declare**, in one transaction. Your payload *is* the desired state.

- Sending `"permissions": []` deletes every permission for that service.
- You can only prune your own — the delete is `WHERE service = $1`, so one service can never remove
  another's.

Treat the list as code: keep it in your repo and POST the whole thing on deploy.

### `org_assignable` is the safety gate

Defaults to **false**. Only flagged permissions can be attached to an *organization* role by an org admin.
Unflagged ones stay reserved to platform admins.

Set it deliberately. `reports.publish` is reasonable for an org admin to grant; `budget.approve` probably
is not — and if it were flagged, any org admin could grant it to themselves.

### Rules

- `service` is required and **`"core"` is reserved** — that is the auth server's own permissions.
- `code`, `resource` and `action` are required on every entry.
- Codes are unique per `(service, code)`. Prefixing (`philly.reports.publish`) is no longer *necessary*,
  but it still makes tokens self-describing, and tokens carry bare codes (see §7).

---

## 4. Create a role that carries them

> ⚠️ **There is currently no HTTP endpoint to create a role.** The server exposes
> `GET /admin/roles` and the two *assignment* endpoints below, but role creation lives only in
> `RoleService.CreateCustomRole` with no route in front of it. Until one is added, create roles in SQL
> — via a migration, so it is reproducible.

```sql
-- A system role: platform-wide, not tied to an organization.
INSERT INTO roles (code, name, description, type, level, is_org_role)
VALUES ('philly_editor', 'Philadelphia Editor', 'Publishes city reports', 'custom', 50, false);

-- Attach permissions. role_permissions links by ID, so the (service, code) pair
-- resolves to exactly one row and cannot pick up another service's same-named permission.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
  FROM roles r, permissions p
 WHERE r.code = 'philly_editor'
   AND p.service = 'philly-civics'
   AND p.code IN ('reports.publish');
```

**Always qualify by `p.service`.** Without it you may attach another service's identically-named
permission — which is precisely what the per-service uniqueness makes possible.

### System role vs organization role

| | System role | Organization role |
|---|---|---|
| `organization_id` | `NULL` | the org's id |
| `is_org_role` | `false` | `true` |
| Scope | Platform-wide | That one organization |
| Uniqueness | `code` unique where org is null | unique per `(code, organization_id)` |

Two orgs can each have an `editor` role with different permissions and never collide.

`system_admin` is special: a platform superuser that **bypasses permission checks entirely**. Do not use
it as a convenient "admin" role for an app — it grants everything, everywhere.

---

## 5. Grant a user into the app

An account exists once. Access to each app is granted separately.

```http
POST   /api/v1/admin/users/{userId}/apps/{appId}      # grant
DELETE /api/v1/admin/users/{userId}/apps/{appId}      # revoke
GET    /api/v1/admin/users/{userId}/apps              # list
```

With `auto_grant_on_signup: true` this happens automatically at registration.

Revoking is per-app: sessions and refresh tokens are keyed on `(user, app, org)`, so removing someone from
app A leaves their app B session untouched.

---

## 6. Assign roles to the user

**System roles** — platform-wide:

```http
PUT /api/v1/admin/users/{userId}/roles
{ "role_codes": ["philly_editor"] }
```

**Organization roles** — scoped to one org:

```http
POST /api/v1/admin/organizations/{orgId}/members         { "user_id": "…" }
PUT  /api/v1/admin/organizations/{orgId}/members/{userId}/roles
{ "role_codes": ["editor"] }
```

Read back with `GET /admin/users/{userId}/roles` and `GET /admin/users/{userId}/organizations`.

Both are `PUT` — they **replace** the set, they do not add to it. Send the full list you want.

---

## 7. What the user ends up with

On login the token carries:

```json
{
  "uid": "…", "email": "…",
  "app_code": "philly-civics",
  "roles": ["philly_editor"],
  "permissions": ["reports.publish"],
  "org_id": "…", "org_slug": "…"
}
```

Your service then checks `permissions` (or calls `POST /auth/validate` for the claims plus revocation
state, which a local signature check cannot see).

### Two things to know

**Permissions are bare code strings, not qualified by service.** Since two services may now define
`reports.publish`, a user who belongs to both apps carries an ambiguous claim. Not exploitable today — a
role grant links to one specific permission row — but it is why **prefixing codes with your service name
remains good practice**.

**The token is not filtered by app.** `collectRolePermissions` flattens every role the user holds,
regardless of which app the token was issued for. A user in several apps carries the union in all of them.
The intended fix is to filter at issue time against the app's `service_codes`; until then, a resource
server should check only for the codes it owns and ignore the rest.

---

## 8. End-to-end example

```bash
API=https://auth.civicgate.org/api/v1
TOKEN=…   # a system_admin access token

# 1. app
curl -X POST $API/admin/apps -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{
  "code":"philly-civics","name":"Philadelphia Civics",
  "allowed_redirect_urls":["https://philly.example.org/auth/callback"],
  "service_codes":["philly-civics"],"auto_grant_on_signup":true }'

# 2. permissions (declarative — the full list, every deploy)
curl -X POST $API/admin/permissions/register -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{
  "service":"philly-civics",
  "permissions":[
    {"code":"reports.publish","name":"Publish reports","resource":"reports","action":"publish","org_assignable":true}
  ]}'

# 3. role — SQL for now (see §4)

# 4. grant the user into the app
curl -X POST $API/admin/users/$USER_ID/apps/$APP_ID -H "Authorization: Bearer $TOKEN"

# 5. assign the role
curl -X PUT $API/admin/users/$USER_ID/roles -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' -d '{"role_codes":["philly_editor"]}'

# 6. verify — log in as that user and read the claims
curl -X POST $API/auth/login -H 'Content-Type: application/json' \
     -d '{"email":"…","password":"…","app_code":"philly-civics"}'
```

---

## 9. Known gaps

| Gap | Impact | Workaround |
|---|---|---|
| No role-creation endpoint | Custom roles need SQL | `RoleService.CreateCustomRole` exists; it needs a route |
| Token permissions not app-filtered | A multi-app user carries the union | Check only your own codes |
| Permission claims are unqualified | Two services' same-named codes are indistinguishable in a token | Prefix codes with your service |

The first is the one that matters for onboarding a portal — everything else in this document works over
HTTP, and role creation is the single step that drops to SQL.

---

## 10. History

- **005** — `permissions.service`; each service owns its slice of the catalog.
- **007** — `apps`, `user_apps`; sessions keyed per `(user, app, org)`.
- **009** — `org_assignable`; the gate on what an org admin may grant.
- **013 / 015** — per-app registration policy.
- **017** — namespaced read pools.
- **026** — permission codes unique per `(service, code)`. Previously a second service declaring an
  existing code silently took ownership of the row, and the original owner's next sync deleted it. Fixed
  alongside a prune bug (`[]string` passed where `pq.StringArray` was required) that had made *every*
  registration with a non-empty list fail.
