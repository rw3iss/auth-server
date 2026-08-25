# FedCM — browser-mediated sign-in with this auth server

**Federated Credential Management** lets a site offer "Sign in with CivicGate" where the **browser** runs the
account chooser, instead of a popup window and third-party cookies. The person taps one row in a dialog the
browser draws; the relying party receives a signed ID token.

This server implements the identity-provider (IdP) side. It **reuses the existing OIDC provider** — same
signing keys, same JWKS, same `oauth_clients` registry, same `oauth_consents` table. FedCM is a new way for a
browser to *ask* for identity, not a second identity system.

---

## 1. Why it exists here

Third-party cookies are being removed. Every previous way for a widget on `example.org` to detect an existing
CivicGate session — a hidden iframe reading storage, a third-party cookie, a silent probe — is either already
partitioned or on its way out. FedCM is the replacement the platform actually offers: one tap, no popup, no
tracking surface, because the browser mediates and the IdP is never told which site is asking until the person
has chosen.

---

## 2. The endpoints

All at the **root** of the issuer origin, never under `API_PREFIX`. The config URL is what a relying party
names, and every other endpoint resolves relative to it, so a prefixed path is somewhere no browser looks —
the same reason `/.well-known/openid-configuration` and `/.well-known/jwks.json` live at the root.

| Method | Endpoint | Credential | CORS | Purpose |
|---|---|---|---|---|
| GET | `/.well-known/web-identity` | none | – | Names the config URL. **See §3 — this must be served from the eTLD+1.** |
| GET | `/fedcm/config.json` | none | – | The provider manifest: endpoints, `login_url`, branding. |
| GET | `/fedcm/accounts` | **session cookie** | – | The signed-in accounts. `401` when signed out. |
| POST | `/fedcm/assertion` | **session cookie** | **required** | Mints the ID token for one relying party. |
| GET | `/fedcm/client-metadata` | none | – | The RP's privacy / terms links, shown in the browser's own dialog. |
| POST | `/fedcm/disconnect` | **session cookie** | **required** | Forgets that this person connected to that RP. |
| GET | `/fedcm/login` | optional | – | The `login_url` page. Sets the browser's login-status bit. |

Every endpoint except `/fedcm/login` requires **`Sec-Fetch-Dest: webidentity`**.

> **`Sec-Fetch-Dest` is the access control, and it is not decoration.** It is a *forbidden header name*: page
> script cannot set it and `fetch()` drops any attempt, so its presence is the browser asserting that *it*
> made the request as part of a FedCM flow. Without the check, `GET /fedcm/accounts` is a credentialed read
> of a signed-in person's name and email available to any cross-site page that can get the cookie attached.
>
> Practical consequence: **`curl` needs the header**, or every FedCM endpoint answers `403`.
> ```bash
> curl -s -H 'Sec-Fetch-Dest: webidentity' https://auth.civicgate.org/fedcm/config.json
> ```
>
> `/fedcm/login` is exempt because the browser opens it as a top-level navigation, where `Sec-Fetch-Dest` is
> `document`.

### The flow

```
  relying party                    browser                    auth.civicgate.org
  navigator.credentials.get() ───────►│                                 │
                                      │ GET civicgate.org/.well-known/web-identity
                                      │ GET /fedcm/config.json ────────►│
                                      │ GET /fedcm/accounts (cookie) ──►│
                                      │ ◄──── the signed-in accounts    │
                              [browser draws the account chooser]       │
                                      │ POST /fedcm/assertion ─────────►│
  ◄──── IdentityCredential.token ─────│ ◄──── {"token": "<id_token>"}   │
```

The token is an ordinary OIDC ID token: `RS256`, `kid` in the header, verifiable against
`/.well-known/jwks.json` with `iss` = the issuer and `aud` = the relying party's `client_id`.

---

## 3. ⚠ The well-known file must be served from the registrable domain

**This is the single easiest thing to get wrong, and it fails with no useful diagnostic.**

The browser does not fetch `/.well-known/web-identity` from the config URL's origin. It fetches it from the
**registrable domain (eTLD+1)** of that origin. With a config at

```
https://auth.civicgate.org/fedcm/config.json
```

the browser requests

```
https://civicgate.org/.well-known/web-identity     ← the APEX, not auth.
```

which **this server does not serve** — that host is the web app's vhost. A redirect does not help: the browser
fetches the well-known with redirect mode `error`.

**Deployment action:** the CivicGate web app (or the nginx vhost for the apex) must serve, at
`https://civicgate.org/.well-known/web-identity`, with `Content-Type: application/json`:

```json
{ "provider_urls": ["https://auth.civicgate.org/fedcm/config.json"] }
```

The route is still registered on this server, because it is *correct* for any deployment where the IdP is
itself the registrable domain — `localhost` in development, a single-host install in production — and because
a wrong-but-present file is easier to diagnose than a missing one.

**The check is skipped entirely when the relying party is same-site with the IdP.** `www.civicgate.org` and
`auth.civicgate.org` share an eTLD+1, so CivicGate's own pages federate against this server without the apex
file existing at all. It matters only for genuinely third-party relying parties — which is the point of
building this.

---

## 4. The session cookie must be `SameSite=None`

FedCM's accounts call happens while the person is on the **relying party's** page. That makes it a cross-site
request, and a `SameSite=Lax` cookie is simply not attached — so the endpoint sees an anonymous request and
honestly answers "no accounts", with a perfectly valid session sitting right there and nothing in any log to
explain it.

The same applies one step earlier: a login `POST` issued cross-origin (`www.civicgate.org` →
`auth.civicgate.org`) cannot even **store** a `Lax` cookie. The browser rejects the `Set-Cookie` outright.

So:

- **`POST /auth/login` accepts `cookie_mode: true`.** The token pair is still returned in the body — the two
  are not exclusive — and the session is additionally written as `HttpOnly` cookies via
  `internal/api/middleware/cookie.go` (the audited AUDIT 9.2 path, which until now had no caller).
- **`AUTH_COOKIE_CROSS_SITE`** writes the access + CSRF cookies `SameSite=None; Secure`. It **defaults on**
  when the OIDC/FedCM provider is enabled. `SameSite=None` without `Secure` is rejected by every current
  browser, so `CrossSite` forces `Secure` on regardless of `ENVIRONMENT`.
- **The refresh cookie stays `SameSite=Strict`.** Nothing cross-site needs it — FedCM reads the session, never
  the refresh chain — and it is the credential that outlives the access token.
- `CORS_ORIGINS` must list the login UI's origin exactly (`https://www.civicgate.org`). A wildcard `*` cannot
  carry credentials, so the cookie never arrives.

### `cookie_mode` is honoured only for a FIRST-PARTY login

`SameSite=Lax` was doing security work that `None` gives up, and it has to be replaced explicitly.

`POST /auth/login` is unauthenticated and carries no CSRF token, and a cross-site `fetch` with a
CORS-safelisted content type triggers **no preflight**. So an attacker's page can POST **its own** credentials
with `cookie_mode: true` and `credentials: "include"`. It cannot read the reply — CORS stops that — but it
does not need to: the `Set-Cookie` lands anyway, and the victim's browser is now holding a live session for
the **attacker's** account. The next FedCM sign-in anywhere then offers, or silently re-authenticates, the
wrong person. That is login CSRF, and `SameSite=Lax` used to block it for free.

So cookies are written only when `middleware.IsFirstPartyRequest` passes:

- **`Sec-Fetch-Site` is the check.** Like `Sec-Fetch-Dest`, it is a forbidden header name, so page script
  cannot set it — and it separates the two cases cleanly: `www.civicgate.org → auth.civicgate.org` is
  **`same-site`**, any attacker page is **`cross-site`**.
- **Absent header** (older browser, non-browser client) falls back to an exact `Origin` match against
  `CORS_ORIGINS`. A literal `*` is **not** honoured there — it would turn the fallback into no check at all.
- **No `Origin` at all** is a non-browser caller (`curl`, a server). It carries no ambient cookies to fixate,
  so it is allowed.

A refused request still **logs in** and still returns its tokens; only the cookies are withheld, and the
refusal is logged at WARN with the offending `Sec-Fetch-Site` / `Origin`. Failing the whole login would break
a bearer client that merely set the flag hopefully.

**This is why the IdP must be `auth.civicgate.org` and never `www.civicgate.org`.** The www origin
deliberately has no session cookie: that is the assumption CivicGate's shared page-cache policy depends on.
Adding one there would silently make cached HTML visitor-dependent. `auth.` is excluded from caching by its
own Cloudflare rule, so a session cookie there is safe.

---

## 5. Login status — the bit that makes it work at all

The browser keeps a tri-state per IdP origin: `unknown` → `logged-in` → `logged-out`. **While it reads
`logged-out` the browser does not call the accounts endpoint at all**; the FedCM request fails immediately.
An IdP that never reports its status looks permanently signed-out no matter how valid the cookie is.

Two mechanisms, both wired:

- **`Set-Login: logged-in`** on the `cookie_mode` login response and **`Set-Login: logged-out`** on
  `POST /auth/logout` (`middleware.SetLoginStatus`).
- **`GET /fedcm/login`** — the `login_url` from the config document. Signed in, it emits `Set-Login: logged-in`
  *and* calls `navigator.login.setStatus("logged-in")` then `IdentityProvider.close()`. Signed out, it `302`s
  to `OIDC_LOGIN_URL` with a `next=` that returns here.

**Why that page has to exist on this origin.** `Set-Login` is honoured on top-level navigations and
*same-origin* subresource requests. A login `POST` from `www` to `auth` is **cross-origin**, so the header may
be ignored there — and `navigator.login.setStatus()` only counts when executed on a page of the IdP origin.
`/fedcm/login` is that page. It is why the header on the login response is belt-and-braces rather than the
mechanism.

It is served with its own CSP carrying a per-response **script nonce**: the server-wide policy is
`default-src 'none'`, which would block the inline script, and a nonce grants exactly that one script rather
than opening `'unsafe-inline'` for the whole page.

---

## 6. Registering a relying party

FedCM reuses the **existing OIDC client registry** — `oauth_clients`, administered through
`POST /api/v1/admin/oauth/clients` (platform-admin only). There is no separate FedCM registry, and
deliberately so: two client lists would eventually disagree about who is allowed to ask for identity.

A relying party is identified by its **`Origin` header**, which the browser sets and page script cannot forge.
That origin is matched against the origins of the client's registered **`redirect_uris`** and
`post_logout_uris`:

```jsonc
{
  "client_id": "rp-demo",
  "name": "Demo RP",
  // FedCM never redirects — but registering the origin here is what authorises it,
  // and it is a field every OIDC client fills in anyway.
  "redirect_uris": ["https://rp.example/auth/callback"],
  "allowed_scopes": ["openid", "profile", "email"]
}
```

Matching is **exact** on scheme + host + port, with the default port normalised away (a browser's `Origin` never
carries `:443`; a registered redirect URI reasonably might). No wildcards and no prefix matching — a
prefix-tolerant comparison would also accept `https://rp.example.attacker.net`.

Relying-party call:

```js
const cred = await navigator.credentials.get({
  identity: {
    providers: [{
      configURL: "https://auth.civicgate.org/fedcm/config.json",
      clientId:  "rp-demo",
      nonce:     crypto.randomUUID(),
    }],
  },
});
// cred.token is an RS256 ID token. Verify it against
// https://auth.civicgate.org/.well-known/jwks.json (iss = the issuer, aud = your clientId).
```

---

## 7. Consent and disclosure

`approved_clients` in the accounts response is what tells the browser whether to show the "you are about to
share your name and email with X" disclosure. It is read from **`oauth_consents`** — the same rows the OIDC
consent screen writes — so a grant made through either flow is honoured by both, and revoking it once revokes
it for both.

- The assertion endpoint records a grant only when the browser reports `disclosure_text_shown=true`, i.e. the
  person was actually asked and went ahead.
- When the consent lookup fails, the accounts endpoint reports **nothing approved**. The cost is one extra
  prompt; claiming an approval we could not verify would silently skip a disclosure.
- `POST /fedcm/disconnect` deletes the consent row. It does **not** end the person's session — disconnecting
  from one site must not sign them out of everything.

### What a token carries

The browser's `fields` parameter is mapped onto this server's OIDC scopes, so `NewIDToken`'s existing
scope-based claim filtering remains the **single** place that decides what a token contains — FedCM does not
get a parallel notion of "what may be shared". An absent `fields` means the browser used its default
disclosure (name, email, picture) and maps to `openid profile email`; mapping it to everything would hand out
more than the person was shown. The result is then intersected with the client's `allowed_scopes`, so a client
cannot widen its own reach by asking the browser for more.

---

## 8. Configuration

| Variable | Default | Meaning |
|---|---|---|
| `OIDC_ISSUER` | `https://auth.civicgate.org` | Issuer origin. FedCM endpoint URLs are built from it. |
| `OIDC_LOGIN_URL` | `https://www.civicgate.org/login` | Where `/fedcm/login` sends an anonymous visitor. |
| `AUTH_COOKIE_CROSS_SITE` | on when OIDC is enabled | Write the session cookie `SameSite=None; Secure`. **FedCM requires this.** |
| `AUTH_COOKIE_DOMAIN` | *(unset — host-only)* | Widen the cookie to a parent domain. Leave unset for FedCM. |
| `FEDCM_BRAND_NAME` | `CivicGate` | Name in the browser's account chooser. |
| `FEDCM_BRAND_ICON_URL` | `https://www.civicgate.org/icon-192.png` | Chooser icon. Chrome requires ≥25px (passive) / ≥40px (button mode). |
| `FEDCM_BRAND_BACKGROUND` | `#0f1115` | Chooser background colour. |
| `FEDCM_BRAND_COLOR` | `#e6e6ea` | Chooser text colour. |

FedCM is enabled by exactly the same condition as OIDC: a usable signing key plus a client store. There is no
separate on/off switch, because there is nothing separate to switch on.

---

## 9. Where the spec and this server's OIDC conventions differ

Three places, each resolved deliberately.

1. **Error shape.** The repo's `writeError` emits `{"error":{"code","message","details"}}` with codes like
   `UNAUTHORIZED`. FedCM defines `{"error":{"code","url"}}` with **OAuth2** codes (`access_denied`,
   `invalid_request`, `unauthorized_client`, `server_error`). The FedCM endpoints emit the spec's `code` **and**
   the repo's `message` in one object; the browser reads `code` and ignores the rest, so both conventions hold.
2. **No preflight, but CORS is still mandatory.** `application/x-www-form-urlencoded` is a CORS-safelisted
   content type, so no `OPTIONS` fires for the assertion or disconnect endpoints — but the response still needs
   `Access-Control-Allow-Origin: <exact RP origin>` and `Access-Control-Allow-Credentials: true`, because the
   body crosses into the RP's JavaScript. `*` is invalid with credentials. **The headers are attached before
   any session check can fail**, or a `401` is blocked by the browser and reaches the relying party as an opaque
   network error instead of a readable one.
3. **`nonce` moved.** Chrome ≤142 sent it as its own form field; Chrome 143 moved it inside `params`, a
   percent-encoded JSON blob; Chrome 145 drops the flat form. Both are read, `params` first. Handling only one
   would silently drop the nonce during the transition — no error anywhere, just a token with no replay binding.

---

## 10. Verifying a deployment

```bash
# 1. The config document (needs the header, or 403).
curl -s -H 'Sec-Fetch-Dest: webidentity' https://auth.civicgate.org/fedcm/config.json | jq

# 2. The well-known — on the APEX, not on auth.
curl -s -H 'Sec-Fetch-Dest: webidentity' https://civicgate.org/.well-known/web-identity | jq

# 3. Signed out, the accounts endpoint answers 401. That is correct, not a fault:
#    it is how the browser tells "signed out" from "signed in with no accounts".
curl -si -H 'Sec-Fetch-Dest: webidentity' https://auth.civicgate.org/fedcm/accounts | head -1

# 4. The cookie is actually cross-site capable. Look for SameSite=None; Secure.
curl -si -X POST https://auth.civicgate.org/api/v1/auth/login \
  -H 'Content-Type: application/json' -H 'Origin: https://www.civicgate.org' \
  -d '{"email":"…","password":"…","app_code":"civicgate","cookie_mode":true}' \
  | grep -i 'set-cookie\|set-login'
```

**If FedCM reports no accounts with a valid session, check in this order:** the cookie's `SameSite`
(§4) → the login-status bit (§5) → the well-known's location (§3). Each of the three fails silently on its
own, and each produces exactly the same symptom.

**If the login returned 200 but set no cookies**, the request was not first-party (§4). The server logs
`cookie_mode refused for a cross-site login` with the `Sec-Fetch-Site` and `Origin` it saw.

### What was verified against a running server

Every endpoint, at build time, against a local instance with a real session — not only unit tests:
the `Sec-Fetch-Dest` gate (`403` without it on all six), `401` from `/fedcm/accounts` when signed out,
`cookie_mode` writing `SameSite=None; Secure` for the access cookie and `SameSite=Strict` for the refresh one
plus `Set-Login: logged-in`, a minted token whose `kid` matches the published JWKS and whose
`iss`/`sub`/`aud`/`azp`/`nonce` are correct, an unregistered `Origin` refused with **no**
`Access-Control-Allow-Credentials` on the response, an `account_id` that is not the session's refused,
consent appearing in `approved_clients` and disappearing again after `disconnect`, and logout clearing all
three cookies with `Set-Login: logged-out`.

The login-CSRF gate (§4) was verified as a live attack: a cross-site login with valid credentials returns
`200` and **zero** `Set-Cookie` headers, while the same-site login, the `Origin`-fallback login and a
credential-free `curl` all get their three cookies. Both refusals appear in the log.

---

## 11. Code map

| Path | What lives there |
|---|---|
| `internal/api/handlers/fedcm_handler.go` | All seven endpoints. |
| `internal/api/middleware/fedcm.go` | `RequireWebIdentity`, `SetLoginStatus`. |
| `internal/api/middleware/cookie.go` | `CookieOptions` (incl. `CrossSite`), `SetAuthCookiesWith`, `AuthenticateCookie`, `OptionalAuthCookie`. |
| `internal/auth/oidc/store.go` | `Client.AllowsOrigin`, `Client.PrimaryOrigin`, `ListConsentedClients`, `DeleteConsent`. |
| `internal/auth/oidc/keys.go`, `token.go` | The signing key and ID-token minting — shared with OIDC, unchanged. |
| `internal/api/routes/routes.go` | Route registration + the cookie policy. |

**No migration was needed.** Every table FedCM touches — `oauth_clients`, `oauth_consents` — already exists
from migration `025`.
