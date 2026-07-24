package sso

// Per-org SSO provider stub (AUDIT C9). The organizations table is already
// schema-prepared with sso_provider + sso_config columns (migration 001)
// so a future build-out can:
//
//  1. Lookup per email-domain or org_id which provider an incoming login
//     should route to.
//  2. Materialize an OAuthProviderConfig at request time from the org's
//     sso_config JSONB (client_id, client_secret, scopes, endpoints).
//  3. Mint state with the org's redirect URL.
//  4. On callback, validate the user's email domain matches the org's
//     configured domain so a user can't be silently joined to the wrong
//     tenant.
//
// # Intended design
//
//   - White-label clients (portal customers running on their own
//     domains) can configure their own IdP at the
//     org level — typically Okta, Azure AD, or a Google Workspace
//     domain restriction.
//   - org.sso_config holds the provider-specific JSON. Schema:
//       {
//         "type": "oidc" | "saml" | "google_workspace",
//         "client_id": "...",
//         "client_secret_kms_key": "arn:...",   // never plaintext in JSONB
//         "issuer": "https://...",
//         "scopes": ["openid", "email", "profile"],
//         "email_domains": ["acmecorp.com"]      // gate enrollment
//       }
//   - The Manager grows a `PerOrgProvider(ctx, orgID) (Provider, error)`
//     method that constructs the right adapter on demand. Cached for
//     the lifetime of the request to avoid re-resolving on each call.
//   - For mTLS / SAML — that's a separate provider impl. Both fit
//     behind the existing Provider interface in provider.go.
//
// # Why not wired now
//
// The current marketplace doesn't have a real consumer asking for it.
// Building the JSONB schema, the per-request resolver, and the SAML
// adapter without a concrete consumer would mean shipping speculative
// code. When a real white-label client lands, this file becomes the
// starting point — the schema is already in place, the Provider
// interface is already shaped right, the redirect-URL allowlist already
// accommodates per-tenant origins.
//
// In the meantime: callers that need to know whether an org has SSO
// configured can read organizations.sso_provider directly via the org
// repo; this file just marks where the dispatcher would live.

// OrgSSOResolver — placeholder interface (AUDIT C9). When the build-out
// happens, this becomes the type the Manager wires in so that
// /auth/sso/url can look up per-org providers without conflating with
// the platform-wide SSO_GOOGLE_* / SSO_APPLE_* config.
//
// type OrgSSOResolver interface {
//     ResolveByOrgID(ctx context.Context, orgID types.ID) (Provider, error)
//     ResolveByEmailDomain(ctx context.Context, domain string) (Provider, *types.ID, error)
// }
//
// Left commented out to signal "not yet" rather than "API contract."
