# Audit — auth.civicgate.org as a third-party identity provider

**Date:** 2026-08-19
**Question asked:** can this serve as an enterprise-grade IdP for other sites, so CivicGate becomes a
central "civics identity" other applications authenticate against?

**Short answer:** the *account system* is genuinely strong. The *federation surface* is not there yet, and
one specific thing blocks all of it: **tokens are signed with HS256**.

---

## 1. What already exists, and is good

| Capability | Status |
|---|---|
| Register / login / refresh / logout, logout-all | ✅ |
| Password reset, magic link, email verification | ✅ |
| SSO **inbound** (Google, X, Apple) | ✅ |
| 2FA (TOTP setup/enable/disable) | ✅ |
| Sessions: list, terminate one, terminate all | ✅ |
| Multi-app (`app_code`), per-app registration policy, namespaced read pools | ✅ |
| Orgs, members, system + org roles, permission registration | ✅ |
| Audit log, background jobs, admin user management, impersonation | ✅ |
| Rate limiting, body limits, idempotency, trusted-proxy client IP, security headers | ✅ |
| `POST /auth/validate` (token introspection) | ✅ |
| `POST /oauth/token` | ⚠️ partial — see §2.4 |
| **`POST /auth/availability`** (public signup check) | ✅ **added in this pass** |

The multi-app model (`app_code` + per-app registration policy + namespaced pools) is the right foundation
for serving several sites — that part of the design already anticipates this use.

---

## 2. What blocks third-party integration

### 2.1 HS256 signing — THE blocker

`internal/auth/jwt/service.go` signs with `jwt.SigningMethodHS256`, a **symmetric** algorithm. Verification
requires the same secret used to sign.

This makes federation impossible without breaking security: to let another site verify a CivicGate token,
you must hand them the signing secret — which also lets them **mint** tokens for any user of any app. There
is no configuration of HS256 that avoids this.

**Required:** asymmetric signing (RS256 or ES256), private key server-side only, public key published.
Everything else in this section depends on it.

**Migration must be non-breaking**, since every live session holds an HS256 token:
1. Add a keypair and sign NEW tokens with RS256, carrying a `kid` header.
2. Keep VERIFYING HS256 for a full refresh-token lifetime, so existing sessions survive.
3. Publish JWKS (§2.2) from day one so relying parties can start verifying.
4. Drop HS256 verification only after the longest-lived legacy token has expired.

### 2.2 No JWKS endpoint

No `/.well-known/jwks.json`. Relying parties need the public keys, with `kid` selection, to verify without
contacting the server per request. This is the mechanism that makes an IdP scale.

### 2.3 No OIDC discovery

No `/.well-known/openid-configuration`. Every mainstream OIDC client library (NextAuth, Spring Security,
Passport, oidc-client-ts, Keycloak adapters …) bootstraps from this document. Without it, each integrator
hand-configures endpoints — which is exactly the friction that stops adoption.

### 2.4 OAuth2 is incomplete

`POST /oauth/token` exists, but there is no `/oauth/authorize`. Without an authorization-code + PKCE flow
there is no standard way for a third-party web app to send a user here, have them log in, and receive a
code. Today an integrator would have to proxy credentials, which is precisely what OAuth exists to avoid.

### 2.5 No `/userinfo`

OIDC's standard profile endpoint. `GET /auth/me` returns the same shape of data but under a non-standard
path with non-standard claim names, so no OIDC client can consume it automatically.

### 2.6 No client registry

Third-party apps need `client_id` / `client_secret`, registered **redirect URIs** (an allow-list is what
prevents token theft via redirect), and per-client scopes. `app_code` is close, but it identifies a
first-party app rather than an external relying party, and carries no redirect allow-list.

---

## 3. Recommended order of work

| Phase | Work | Why this order |
|---|---|---|
| **P1** | RS256 + `kid`, dual-verify HS256, `/.well-known/jwks.json` | Nothing else is safe until signing is asymmetric. Non-breaking. |
| **P2** | `/.well-known/openid-configuration`, `/userinfo` | Makes standard OIDC clients work; both are read-only additions. |
| **P3** | Client registry (client_id/secret, redirect allow-list, scopes) + `/oauth/authorize` with PKCE | The actual federation flow. Needs P1 + P2 to be meaningful. |
| **P4** | Consent screen, scope-based claim filtering, per-client audit | What makes it defensible for members: they see and control what each site receives. |

**Scope design matters for CivicGate specifically.** The civic profile is more sensitive than a typical
IdP payload — declared political positions and contact history are political-belief data about a private
individual. Recommended scopes: `openid`, `profile`, `email`, `civic:location`, `civic:interests`,
`civic:positions`, `civic:activity`. Positions and activity should require **explicit per-app consent**,
never a default grant.

---

## 4. Changes made in this pass

- **`POST /auth/availability`** (public, rate-limited). `POST /auth/check-email` requires `system_admin`,
  so a signup form — which has no session — could never use it. Enumeration is mitigated in the handler:
  per-IP sliding window, a bare boolean, and "available" on throttle or error so a throttled caller learns
  nothing while registration remains the real gate.

**On the CivicGate side** (`apps/gateway`), the relying-party data surface now exists:

- **`civicProfile(handle)`** — the extended civic profile: identity, location (city/state/country only —
  never the street address or postal code held in the same JSONB), interests, declared positions,
  connection count, activity counts, and a `visibility` map so an integrator can distinguish "the member
  hid this" from "the member has none".
- It reuses **`canSeeFacet`**, the same check the profile page uses. A relying party sees what an anonymous
  visitor sees plus whatever the member opened wider. A third-party integration must never be a route
  around a member's own privacy settings, and a second permission model would eventually disagree with the
  first. Per-app scope consent belongs **on top of** this check, never instead of it.

---

## 5. Honest assessment

For **first-party use** (CivicGate itself, and any app you also operate), this server is already suitable:
the account, session, org and permission model is more complete than most projects ever build.

For **third-party federation**, it is not yet an IdP in the sense integrators expect — not because it lacks
features, but because it lacks the four standard endpoints and the asymmetric signing that make those
features consumable from outside. P1 and P2 are modest, additive, and non-breaking; P3 is the real work.
