# Email templates

The auth-server renders all transactional email (verify-email, password-reset,
magic-link, invitation, welcome, password-changed, security-alert) through one
shared, themed HTML system so every message looks like the same product
regardless of transport (SMTP / SendGrid) and regardless of light/dark mode.

The default theme is **CivicGate** — a serif "Civic" + amber "Gate" wordmark, a
bulletproof table-based card, mobile-responsive width, and a "Neutral civic
intelligence" footer. Dark is the default; a light variant exists for recipients
who prefer it.

## Anatomy

```
internal/email/
├── renderer.go        Renderer: two-layer template lookup + palette + shell selection
├── smtp.go            SMTPService (multipart/alternative) — uses Renderer
├── sendgrid.go        SendGridService (v3 API) — uses Renderer
└── templates/         Embedded defaults (go:embed all:templates)
    ├── _base.html         Shell — DARK variant (the default; loaded as "_base")
    ├── _base_light.html   Shell — LIGHT variant
    ├── verification.html  Per-message content templates. Each renders INSIDE a
    ├── password_reset.html   shell via {{.BodyHTML}}. They emit only the body
    ├── magic_link.html       (heading, copy, button, fallback link, expiry note).
    ├── invitation.html
    ├── welcome.html
    ├── password_changed.html
    └── security_alert.html
```

### The shell (layout)

`_base.html` (dark) and `_base_light.html` (light) are the layout/shell. Each
wraps the pre-rendered inner body (`{{.BodyHTML}}`) in the CivicGate brand
chrome: header wordmark, card, footer. The two shells are literal siblings with
**inline hex** transcribed from CivicGate's `DESIGN.md` (email clients don't
support CSS variables or external stylesheets, so every color is a hex literal).

`_base` is the canonical default — the renderer loads it for dark mode and for
any send that doesn't specify a color mode. Keeping the dark shell at the
plain `_base` name preserves the pre-existing operator-override contract.

### The content templates

Each per-message template emits only its body and reads **palette tokens**
injected by the renderer, so a single content template renders correctly in
both modes:

| Token | Meaning (dark / light) |
|---|---|
| `{{.TextColor}}` | primary text (`#e8ecf2` / `#16202e`) |
| `{{.MutedColor}}` | secondary text (`#8896a8` / `#5a6a7d`) |
| `{{.DimColor}}` | tertiary/expiry text (`#4a5568` / `#94a2b3`) |
| `{{.ButtonBg}}` / `{{.ButtonFg}}` | primary button bg / fg (`#3f7fff` / `#2f6bff`, on white) |
| `{{.LinkColor}}` | inline link (`#6f9dff` / `#2f6bff`) |
| `{{.AccentColor}}` | "Gate" amber (`#e8b44a` / `#c8901f`) |
| `{{.SurfaceColor}}` / `{{.Surface2Color}}` / `{{.BorderColor}}` | surfaces + hairline |
| `{{.ColorMode}}` | `"dark"` or `"light"` (the resolved mode) |

Shell-level fields are also always available: `{{.BrandName}}`,
`{{.SupportEmail}}`, `{{.Year}}`, `{{.Subject}}`, `{{.PreviewText}}`, plus
whatever the caller passes in `RenderInput.Data` (e.g. `{{.VerificationURL}}`).

The palette lives in one place — `paletteFor()` / `darkPalette` / `lightPalette`
in `renderer.go`. The shells carry the same hex inline (they can't read the
palette map at parse time), so if you change a brand color, update **both**
`renderer.go` and the two shell files.

## Color-mode selection (the rule)

`RenderInput.ColorMode` selects the shell + palette: `"light"` → `_base_light`
+ light palette; anything else (including `""`) → `_base` + dark palette.
**Unknown/empty always falls back to dark** — the CivicGate default. That rule
is centralized in `domain.NormalizeColorMode` (Go) and `paletteFor` (renderer).

When sending to a **known user**, the caller passes that user's preference:

```go
// auth_registration.go / auth_password.go
s.emailService.SendVerificationEmail(ctx, appBase, email, firstName, token, user.ColorMode())
```

`domain.User.ColorMode()` reads `users.default_color_mode` (migration 021) and
resolves empty/legacy rows to `"dark"`. Anonymous sends (e.g. invitations to a
not-yet-registered address) pass `""` and get dark.

### `default_color_mode` — storage & API

- **Column:** `users.default_color_mode VARCHAR(10) NOT NULL DEFAULT 'dark'
  CHECK (default_color_mode IN ('dark','light'))` — migration
  `022_user_default_color_mode`.
- **Domain:** `domain.User.DefaultColorMode` (+ `ColorMode()` accessor;
  `NormalizeColorMode` for the fallback).
- **Repository:** written by `Create`/`Update`, read by the full-column
  selects (`GetByID`, `GetByEmail`, `GetByEmailInNamespaces`, `List`, `Lookup`).
- **Read (profile GET):** exposed as `default_color_mode` on `dto.UserResponse`
  (so `/admin/users/{id}` etc. carry it) and injected into the `/auth/me`
  response.
- **Write (profile PATCH/update):** `default_color_mode` on
  `dto.UpdateUserRequest` → `service.UpdateUserInput` → `UserService.UpdateUser`
  (invalid values coerce to `dark` server-side).

## Overrides — `EMAIL_TEMPLATES_PATH`

The `Renderer` does a two-layer lookup per template name: an operator file at
`${EMAIL_TEMPLATES_PATH}/<name>.html` wins; otherwise the embedded default is
used. Operators can override any content template **or** either shell
(`_base.html`, `_base_light.html`) without rebuilding the binary. Overrides are
lazy-compiled on first use, so a typo fails at first send, not at boot.

## Adding a new email type

1. **Content template** — add `internal/email/templates/<name>.html`. Emit only
   the body; use the palette tokens for all colors (never a raw hex, so it works
   in both modes) and the shared button pattern (copy an existing one, e.g.
   `verification.html`). It's embedded automatically via `go:embed all:templates`.
2. **Interface method** — add `Send<Name>Email(...)` to
   `service.EmailService`. If it targets a **known user**, take a trailing
   `colorMode string` param (mirror `SendVerificationEmail`); anonymous sends can
   omit it and render dark.
3. **Providers** — implement the method on `SMTPService` and `SendGridService`
   (both just assemble a `sendArgs`/`smtpSendArgs` and call `renderAndSend`; set
   `ColorMode`), and on `NoOpEmailService` (log-only). All three must satisfy the
   interface or the build breaks.
4. **Caller** — from the service layer, pass the recipient's preference:
   `user.ColorMode()` for a known user, `""` otherwise.
5. **Test** — add a render assertion in `internal/email/renderer_test.go`
   (both variants; check the wordmark, the button label, and the action URL).

## Rendering pipeline

```
caller ─► EmailService.Send…Email(…, colorMode)
        ─► provider builds sendArgs{Template, Data, ColorMode, …}
        ─► Renderer.Render:
             • paletteFor(ColorMode) → palette + shell name (_base | _base_light)
             • render <name>.html with palette+data → BodyHTML
             • render shell with BodyHTML → final HTML
        ─► provider ships HTML (+ text/plain fallback) via SMTP / SendGrid API
```

Both providers also attach a minimal `text/plain` alternative
(`PlainTextFallback`) carrying the CTA URL, for non-HTML clients and spam-filter
friendliness. SMTP sends these as `multipart/alternative`.
