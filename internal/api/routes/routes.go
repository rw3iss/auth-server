// Package routes provides HTTP route configuration
package routes

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/redis/go-redis/v9"

	"github.com/rw3iss/auth/internal/api/handlers"
	"github.com/rw3iss/auth/internal/api/middleware"
	"github.com/rw3iss/auth/internal/auth/jwt"
	oidcauth "github.com/rw3iss/auth/internal/auth/oidc"
	"github.com/rw3iss/auth/internal/background"
	"github.com/rw3iss/auth/internal/cache"
	"github.com/rw3iss/auth/internal/config"
	"github.com/rw3iss/auth/internal/repository"
	"github.com/rw3iss/auth/internal/service"
	auth "github.com/rw3iss/auth/internal/service/auth"
)

// Router wraps http.ServeMux with additional functionality
type Router struct {
	mux *http.ServeMux
}

// NewRouter creates a new router
func NewRouter() *Router {
	return &Router{
		mux: http.NewServeMux(),
	}
}

// Handle registers a handler for a pattern
func (r *Router) Handle(pattern string, handler http.Handler) {
	r.mux.Handle(pattern, handler)
}

// HandleFunc registers a handler function for a pattern
func (r *Router) HandleFunc(pattern string, handler http.HandlerFunc) {
	r.mux.HandleFunc(pattern, handler)
}

// ServeHTTP implements http.Handler
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mux.ServeHTTP(w, req)
}

// SetupRoutes configures all API routes. `ctx` is the application's
// shutdown context — the rate-limiter (and any other long-running
// goroutines started here in the future) tie their lifetimes to it so
// they exit cleanly on server.Shutdown rather than leaking past the
// process's nominal end. AUDIT 5.6.
func SetupRoutes(
	ctx context.Context,
	cfg *config.Config,
	authService *auth.AuthService,
	userService *service.UserService,
	orgService *service.OrganizationService,
	roleService *service.RoleService,
	appService *service.AppService,
	m2mService *service.M2MService,
	magicLinkService *auth.MagicLinkService,
	auditQueryService *service.AuditQueryService,
	permRepo repository.PermissionRepository,
	jwtService *jwt.Service,
	scheduler *background.Scheduler,
	redisClient *cache.RedisClient,
	oidcStore *oidcauth.Store,
	tokenCache ...cache.TokenCache,
) http.Handler {
	router := NewRouter()

	// Create middleware
	authMw := middleware.NewAuthMiddleware(jwtService)
	var tc cache.TokenCache
	if len(tokenCache) > 0 {
		tc = tokenCache[0]
	}
	rateLimiter := middleware.NewRateLimiter(ctx, cfg.Security, tc)

	availabilityHandler := handlers.NewAvailabilityHandler(authService)

	// ── OIDC provider (migration 025) ────────────────────────────────────────────────────────────────
	// The issuer MUST equal the base URL relying parties use, character for character: every OIDC client
	// compares the `iss` claim against the URL it discovered from, and a mismatch is a hard failure.
	issuer := os.Getenv("OIDC_ISSUER")
	if issuer == "" {
		issuer = "https://auth.civicgate.org"
	}
	loginURL := os.Getenv("OIDC_LOGIN_URL")
	if loginURL == "" {
		loginURL = "https://www.civicgate.org/login"
	}
	keyDir := os.Getenv("OIDC_KEY_DIR")
	if keyDir == "" {
		keyDir = os.Getenv("HOME") + "/.config/civicgate"
	}
	oidcKeys, oidcErr := oidcauth.NewKeyManager(keyDir)
	var oidcHandler *handlers.OIDCHandler
	var fedcmHandler *handlers.FedCMHandler
	fedcmOK := false
	oidcOK := oidcErr == nil && oidcStore != nil
	if oidcErr != nil || oidcStore == nil {
		// Fail LOUD in the log but keep the rest of the server serving: a signing-key problem must not
		// take password login down with it.
		slog.Error("oidc: signing key unavailable — OIDC endpoints disabled", "error", oidcErr)
	} else {
		oidcHandler = handlers.NewOIDCHandler(oidcKeys, oidcStore, authService, issuer, loginURL)
		// FedCM reuses the SAME keys, the SAME client registry and the SAME consent
		// table as OIDC. It is a different way for a browser to ask for identity, not a
		// second identity system — so it is enabled by exactly the same condition.
		fedcmHandler = handlers.NewFedCMHandler(oidcKeys, oidcStore, authService, issuer, loginURL, fedcmBranding())
		fedcmOK = true
	}

	// Cookie policy for the opt-in `cookie_mode` login path (middleware/cookie.go).
	//
	// AUTH_COOKIE_CROSS_SITE writes the session cookie SameSite=None; Secure, which
	// FedCM REQUIRES: the browser calls the accounts endpoint from a page on the
	// relying party's origin, and a Lax cookie is simply not attached there. It
	// defaults ON when FedCM is available, because a FedCM deployment with Lax
	// cookies fails in the one way that leaves no trace — the endpoint sees an
	// anonymous request and honestly answers "no accounts".
	cookieOpts := middleware.CookieOptions{
		Production: cfg.IsProduction(),
		CrossSite:  getEnvBool("AUTH_COOKIE_CROSS_SITE", fedcmHandler != nil),
		Domain:     os.Getenv("AUTH_COOKIE_DOMAIN"),
	}
	authHandler := handlers.NewAuthHandler(authService,
		handlers.WithCookies(cookieOpts, int(cfg.JWT.RefreshTokenExpiry.Seconds()), cfg.Server.CORSOrigins))
	userHandler := handlers.NewUserHandler(userService, roleService, authService)
	orgHandler := handlers.NewOrganizationHandler(orgService, userService)
	permHandler := handlers.NewPermissionHandler(permRepo)
	jobHandler := handlers.NewJobHandler(scheduler)
	appHandler := handlers.NewAppHandler(appService)
	oauthHandler := handlers.NewOAuthHandler(m2mService)
	m2mHandler := handlers.NewM2MHandler(m2mService)
	magicLinkHandler := handlers.NewMagicLinkHandler(magicLinkService)
	auditHandler := handlers.NewAuditHandler(auditQueryService)
	invitationHandler := handlers.NewInvitationHandler(orgService, userService)

	// Route prefix from config (e.g. "/api/v1" or "")
	p := cfg.Server.APIPrefix

	// Health check
	router.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"healthy"}`))
	})

	// Public auth routes (no authentication required)
	router.HandleFunc("POST "+p+"/auth/register", authHandler.Register)
	router.HandleFunc("POST "+p+"/auth/login", authHandler.Login)
	router.HandleFunc("POST "+p+"/auth/refresh", authHandler.RefreshToken)
	// AUDIT 1.23: /auth/logout now requires Authorization: Bearer so a
	// stolen refresh token alone isn't enough to trigger logouts.
	router.Handle("POST "+p+"/auth/logout", authMw.Authenticate(http.HandlerFunc(authHandler.Logout)))
	router.HandleFunc("POST "+p+"/auth/password/reset-request", authHandler.RequestPasswordReset)
	router.HandleFunc("POST "+p+"/auth/password/reset", authHandler.ResetPassword)

	// Magic-link sign-in (migration 014). Anonymous on both endpoints —
	// request mints + emails a one-tap link; verify exchanges it for
	// the same token-pair shape /auth/login returns.
	router.HandleFunc("POST "+p+"/auth/magic-link/request", magicLinkHandler.Request)
	router.HandleFunc("POST "+p+"/auth/magic-link/verify", magicLinkHandler.Verify)
	router.HandleFunc("POST "+p+"/auth/verify-email", authHandler.VerifyEmail)
	router.HandleFunc("GET "+p+"/auth/verify-email", authHandler.VerifyEmail)
	// AUDIT 5.4: re-issue a verification token when the initial send
	// failed or the link expired. Always 200; service silently no-ops
	// to avoid email enumeration.
	router.HandleFunc("POST "+p+"/auth/verify-email/resend", authHandler.ResendVerificationEmail)

	// PUBLIC signup availability (M16). Separate from /auth/check-email, which is a system_admin route:
	// a registration form has no session, so it could not use that one and had no way to tell someone
	// their address was taken until submit. Enumeration is mitigated in the handler (per-IP limit, bare
	// boolean, "available" on throttle) — see availability_handler.go.
	router.HandleFunc("POST "+p+"/auth/availability", availabilityHandler.CheckAvailability)

	// SSO routes
	router.HandleFunc("POST "+p+"/auth/sso/url", authHandler.GetSSOAuthURL)
	router.HandleFunc("GET "+p+"/auth/sso/callback", authHandler.SSOCallback)
	router.HandleFunc("POST "+p+"/auth/sso/callback", authHandler.SSOCallback)
	// AUDIT C2: PKCE redemption endpoint. Public; one-shot auth_code +
	// verifier proves possession of the original challenge.
	router.HandleFunc("POST "+p+"/auth/sso/exchange", authHandler.SSOExchange)
	router.HandleFunc("GET "+p+"/auth/sso/providers", authHandler.GetEnabledProviders)

	// Token validation (for internal services)
	router.HandleFunc("POST "+p+"/auth/validate", authHandler.ValidateToken)

	// Public per-app registration policy — UX hints (allowed email
	// domains, allowed auth methods, default org name) so a client can
	// render an accurate form. Server still enforces on register.
	// Migration 013.
	router.HandleFunc("GET "+p+"/apps/{code}/registration-policy", appHandler.RegistrationPolicy)

	// OAuth2 client_credentials grant (RFC 6749 §4.4). Public — auth is
	// via client_id + client_secret in the body. Mints service-principal
	// access tokens for M2M consumers (cron, batch, CI runners, downstream
	// services that need to call this server's admin surface).
	// One token URL for every grant, as discovery advertises: the OIDC handler takes authorization_code
	// and hands anything else (client_credentials) to the original handler.
	router.HandleFunc("POST "+p+"/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		if oidcHandler != nil {
			oidcHandler.Token(w, r, oauthHandler.Token)
			return
		}
		oauthHandler.Token(w, r)
	})

	if oidcHandler != nil {
		// Discovery + JWKS live at the ROOT, not under the /api/v1 prefix — the spec fixes these paths
		// relative to the issuer, and a client will not find them anywhere else.
		router.HandleFunc("GET /.well-known/openid-configuration", oidcHandler.Discovery)
		router.HandleFunc("GET /.well-known/jwks.json", oidcHandler.JWKS)
		// Optional auth: an authenticated browser proceeds, an anonymous one is bounced to login.
		router.Handle("GET "+p+"/oauth/authorize", authMw.OptionalAuth(http.HandlerFunc(oidcHandler.Authorize)))
		router.Handle("GET "+p+"/oauth/userinfo", authMw.Authenticate(http.HandlerFunc(oidcHandler.UserInfo)))
		router.Handle("POST "+p+"/oauth/userinfo", authMw.Authenticate(http.HandlerFunc(oidcHandler.UserInfo)))
		router.HandleFunc("GET "+p+"/oauth/logout", oidcHandler.EndSession)
	}

	// The deployment's own identity, for every surface that renders "Sign in with <provider>".
	providerIdentity := handlers.ProviderIdentityFromEnv(issuer, fedcmOK, oidcOK)
	providerHandler := handlers.NewProviderHandler(providerIdentity)
	router.Handle("GET /api/v1/provider", http.HandlerFunc(providerHandler.Get))
	router.Handle("GET /.well-known/auth-provider", http.HandlerFunc(providerHandler.Get))

	if fedcmHandler != nil {
		// FedCM (Federated Credential Management) — "Sign in with CivicGate", brokered
		// by the browser. Like OIDC discovery, these paths live at the ROOT: the config
		// URL is what a relying party names, and every other endpoint resolves relative
		// to it, so mounting them under /api/v1 would put them somewhere no browser
		// looks. See docs/FEDCM.md.
		//
		// EVERY endpoint is behind RequireWebIdentity. `Sec-Fetch-Dest: webidentity` is
		// a forbidden header name — page script cannot set it — so its presence is the
		// browser asserting it made the call itself. Without that check /fedcm/accounts
		// is a credentialed read of a signed-in person's name and email, available to
		// any cross-site page. (It also means curl needs the header; see the doc.)
		wi := middleware.RequireWebIdentity
		router.Handle("GET /.well-known/web-identity", wi(http.HandlerFunc(fedcmHandler.WellKnown)))
		router.Handle("GET /fedcm/config.json", wi(http.HandlerFunc(fedcmHandler.Config)))
		// Cookie auth, not bearer: the browser makes these calls and has no way to
		// attach an Authorization header. AuthenticateCookie answers 401 when signed
		// out, which is exactly what FedCM reads as "offer the login page".
		router.Handle("GET /fedcm/accounts", wi(authMw.AuthenticateCookie(http.HandlerFunc(fedcmHandler.Accounts))))
		// Optional auth on assertion + disconnect so the handler runs far enough to
		// validate the relying party and attach CORS headers before it reports a
		// missing session — a 401 without them reaches the RP as an opaque network
		// error instead of a readable one.
		router.Handle("POST /fedcm/assertion", wi(authMw.OptionalAuthCookie(http.HandlerFunc(fedcmHandler.Assertion))))
		router.Handle("POST /fedcm/disconnect", wi(authMw.OptionalAuthCookie(http.HandlerFunc(fedcmHandler.Disconnect))))
		// Uncredentialed by design — it answers a question about the CLIENT, and the
		// browser deliberately sends no cookies.
		router.Handle("GET /fedcm/client-metadata", wi(http.HandlerFunc(fedcmHandler.ClientMetadata)))
		// The login_url from the config document. NOT behind RequireWebIdentity: the
		// browser opens it as a top-level navigation, where Sec-Fetch-Dest is "document".
		router.Handle("GET /fedcm/login", authMw.OptionalAuthCookie(http.HandlerFunc(fedcmHandler.LoginPage)))
	}

	// Protected auth routes
	router.Handle("GET "+p+"/auth/me", authMw.Authenticate(http.HandlerFunc(authHandler.GetMe)))
	router.Handle("PATCH "+p+"/auth/me", authMw.Authenticate(http.HandlerFunc(authHandler.UpdateMe)))
	router.Handle("POST "+p+"/auth/password/change", authMw.Authenticate(http.HandlerFunc(authHandler.ChangePassword)))
	router.Handle("POST "+p+"/auth/admin/set-password", authMw.Authenticate(http.HandlerFunc(authHandler.AdminSetPassword)))
	router.Handle("POST "+p+"/auth/check-email", authMw.Authenticate(http.HandlerFunc(authHandler.CheckEmail)))
	router.Handle("POST "+p+"/auth/logout/all", authMw.Authenticate(http.HandlerFunc(authHandler.LogoutAll)))
	router.Handle("GET "+p+"/auth/sessions", authMw.Authenticate(http.HandlerFunc(authHandler.GetSessions)))
	router.Handle("DELETE "+p+"/auth/sessions/{sessionId}", authMw.Authenticate(http.HandlerFunc(authHandler.TerminateSession)))

	// AUDIT C4 — TOTP 2FA. All three endpoints require an authenticated
	// caller. Setup → returns provisioning URI; Enable → verifies first
	// code + flips ConfirmedAt; Disable → requires password + code, bumps
	// the user's token-version so other sessions immediately see 2FA off.
	router.Handle("POST "+p+"/auth/2fa/setup", authMw.Authenticate(http.HandlerFunc(authHandler.SetupTwoFactor)))
	router.Handle("POST "+p+"/auth/2fa/enable", authMw.Authenticate(http.HandlerFunc(authHandler.EnableTwoFactor)))
	router.Handle("POST "+p+"/auth/2fa/disable", authMw.Authenticate(http.HandlerFunc(authHandler.DisableTwoFactor)))

	// AUDIT 2.5 + super_admin role (migration 008): centralise admin gates
	// at the route layer.
	//
	// Two chains:
	//   - adminChain        — Authenticate + RequirePlatformAdmin
	//                         (system_admin OR super_admin). For data + ops
	//                         admin: users, orgs, members, background jobs.
	//   - systemAdminChain  — Authenticate + RequireSystemAdmin. For
	//                         platform-internal routes that can affect the
	//                         platform's own behaviour: app registration,
	//                         service-permission self-registration. Only
	//                         system_admin is allowed.
	//
	// Handlers still keep their belt-and-suspenders check for now; we'll
	// remove those in a follow-up once integration coverage proves the
	// middleware gate is fully effective.
	adminChain := func(h http.Handler) http.Handler {
		return authMw.Authenticate(authMw.RequirePlatformAdmin(h))
	}

	if oidcHandler != nil {

		// Relying-party administration. Behind the admin chain: registering a redirect_uri is functionally
		// granting an application the ability to receive other people's sessions, so it is an
		// administrative capability, never self-service.
		oidcAdmin := handlers.NewOIDCAdminHandler(oidcStore)
		router.Handle("GET "+p+"/admin/oauth/clients", adminChain(http.HandlerFunc(oidcAdmin.List)))
		router.Handle("POST "+p+"/admin/oauth/clients", adminChain(http.HandlerFunc(oidcAdmin.Create)))
		router.Handle("PATCH "+p+"/admin/oauth/clients/{clientId}", adminChain(http.HandlerFunc(oidcAdmin.Update)))
		router.Handle("POST "+p+"/admin/oauth/clients/{clientId}/rotate-secret", adminChain(http.HandlerFunc(oidcAdmin.RotateSecret)))
		router.Handle("DELETE "+p+"/admin/oauth/clients/{clientId}", adminChain(http.HandlerFunc(oidcAdmin.Delete)))

		// SELF-SERVICE relying-party registration — "add Login with CivicGate to my site".
		//
		// Authenticated, NOT administrative: any member may register an application, the way Google and
		// GitHub let any account register an OAuth app. What makes that safe is that this surface can do
		// strictly LESS than the admin one above, and enforces ownership inside every query — see
		// handlers/oidc_selfservice_handler.go and oidc/store_selfservice.go. Clients created here carry
		// an owner_user_id (migration 028); the admin-created ones do not, which is exactly what keeps
		// them — including the trusted first-party `civicgate-web` client — invisible here.
		//
		// The admin routes above are untouched and remain the only way to grant a client anything
		// privileged: the civic:* scopes, `trusted`, an app_code, or PKCE-off.
		oidcSelf := handlers.NewOIDCSelfServiceHandler(oidcStore)
		selfChain := authMw.Authenticate
		router.Handle("GET "+p+"/oidc/clients", selfChain(http.HandlerFunc(oidcSelf.List)))
		router.Handle("POST "+p+"/oidc/clients", selfChain(http.HandlerFunc(oidcSelf.Create)))
		router.Handle("GET "+p+"/oidc/clients/{clientId}", selfChain(http.HandlerFunc(oidcSelf.Get)))
		router.Handle("PATCH "+p+"/oidc/clients/{clientId}", selfChain(http.HandlerFunc(oidcSelf.Update)))
		router.Handle("DELETE "+p+"/oidc/clients/{clientId}", selfChain(http.HandlerFunc(oidcSelf.Delete)))
		router.Handle("POST "+p+"/oidc/clients/{clientId}/rotate-secret", selfChain(http.HandlerFunc(oidcSelf.RotateSecret)))
	}
	systemAdminChain := func(h http.Handler) http.Handler {
		return authMw.Authenticate(authMw.RequireSystemAdmin(h))
	}

	// Admin user management
	router.Handle("GET "+p+"/admin/users", adminChain(http.HandlerFunc(userHandler.ListUsers)))
	router.Handle("GET "+p+"/admin/users/{userId}", adminChain(http.HandlerFunc(userHandler.GetUser)))
	// AUTH-PHP-LARAVEL-DESIGN §5: bulk lookup by email and/or id, one
	// round-trip. Powers back-office tools, the PHP package's
	// AdminFlow.lookupUsers, and any caller that needs to resolve >1
	// user without iterating /auth/check-email per row.
	router.Handle("POST "+p+"/admin/users/lookup", adminChain(http.HandlerFunc(userHandler.LookupUsers)))
	// §4 bulk pre-hashed import. systemAdminChain — writes credentials
	// verbatim; the cutover path for onboarding an app's existing users.
	router.Handle("POST "+p+"/admin/users/bulk-import", systemAdminChain(http.HandlerFunc(authHandler.BulkImportUsers)))
	router.Handle("GET "+p+"/admin/roles", adminChain(http.HandlerFunc(userHandler.ListSystemRoles)))
	// Role CREATION — previously the one onboarding step with no HTTP route, forcing operators into SQL.
	// system_admin only: a role is a bundle of permissions, so being able to mint one is equivalent to
	// being able to grant them.
	roleAdmin := handlers.NewRoleAdminHandler(roleService)
	router.Handle("POST "+p+"/admin/roles", systemAdminChain(http.HandlerFunc(roleAdmin.Create)))
	router.Handle("PUT "+p+"/admin/roles/{roleId}", systemAdminChain(http.HandlerFunc(roleAdmin.Update)))
	router.Handle("DELETE "+p+"/admin/roles/{roleId}", systemAdminChain(http.HandlerFunc(roleAdmin.Delete)))
	router.Handle("GET "+p+"/admin/users/{userId}/roles", adminChain(http.HandlerFunc(userHandler.GetUserRoles)))
	router.Handle("PUT "+p+"/admin/users/{userId}/roles", adminChain(http.HandlerFunc(userHandler.SetUserRoles)))
	router.Handle("GET "+p+"/admin/users/{userId}/organizations", adminChain(http.HandlerFunc(userHandler.GetUserOrganizations)))
	router.Handle("POST "+p+"/admin/users/{userId}/revoke-sessions", adminChain(http.HandlerFunc(userHandler.RevokeUserSessions)))
	router.Handle("POST "+p+"/admin/users/{userId}/reset-lockout", adminChain(http.HandlerFunc(userHandler.ResetLockout)))
	// Per-session admin control. ListUserSessions mirrors
	// /auth/sessions's response shape so UIs can reuse the row
	// renderer; TerminateUserSession is the granular counterpart to
	// revoke-sessions (which kills every session at once). Both
	// gated by adminChain (system_admin OR super_admin).
	router.Handle("GET "+p+"/admin/users/{userId}/sessions", adminChain(http.HandlerFunc(userHandler.ListUserSessions)))
	router.Handle("DELETE "+p+"/admin/users/{userId}/sessions/{sessionId}", adminChain(http.HandlerFunc(userHandler.TerminateUserSession)))
	// AUDIT C7: impersonation. Authenticate only — service layer enforces
	// system_admin/super_admin (any user) vs org_admin (within their org)
	// per actor's roles + org context. Putting it under adminChain would
	// hide the org_admin pathway behind a 401.
	router.Handle("POST "+p+"/admin/users/{userId}/impersonate", authMw.Authenticate(http.HandlerFunc(authHandler.Impersonate)))
	// AUDIT C8: hard-delete users. systemAdminChain — destructive enough
	// to reserve to platform owners; super_admin can soft-delete via the
	// existing routes.
	router.Handle("DELETE "+p+"/admin/users/{userId}/hard", systemAdminChain(http.HandlerFunc(authHandler.HardDeleteUser)))

	// Admin organization routes
	router.Handle("GET "+p+"/admin/organizations", adminChain(http.HandlerFunc(orgHandler.ListOrganizations)))
	router.Handle("POST "+p+"/admin/organizations", adminChain(http.HandlerFunc(orgHandler.CreateOrganization)))
	router.Handle("GET "+p+"/admin/organizations/{orgId}", adminChain(http.HandlerFunc(orgHandler.GetOrganization)))
	router.Handle("PUT "+p+"/admin/organizations/{orgId}", adminChain(http.HandlerFunc(orgHandler.UpdateOrganization)))
	router.Handle("DELETE "+p+"/admin/organizations/{orgId}", adminChain(http.HandlerFunc(orgHandler.DeleteOrganization)))
	router.Handle("GET "+p+"/admin/organizations/{orgId}/members", adminChain(http.HandlerFunc(orgHandler.ListMembers)))
	router.Handle("POST "+p+"/admin/organizations/{orgId}/members", adminChain(http.HandlerFunc(orgHandler.AddMember)))
	router.Handle("DELETE "+p+"/admin/organizations/{orgId}/members/{userId}", adminChain(http.HandlerFunc(orgHandler.RemoveMember)))
	router.Handle("PUT "+p+"/admin/organizations/{orgId}/members/{userId}/status", adminChain(http.HandlerFunc(orgHandler.UpdateMemberStatus)))
	router.Handle("PUT "+p+"/admin/organizations/{orgId}/members/{userId}/roles", adminChain(http.HandlerFunc(orgHandler.SetMemberRoles)))

	// Admin permission management (service self-registration). Platform-
	// internal — only system_admin. super_admin should not be able to
	// alter the platform's permission catalog.
	router.Handle("POST "+p+"/admin/permissions/register", systemAdminChain(http.HandlerFunc(permHandler.RegisterPermissions)))

	// Audit-log viewer — read access for system_admin or super_admin.
	router.Handle("GET "+p+"/admin/audit-log", adminChain(http.HandlerFunc(auditHandler.List)))

	// Background-job management
	router.Handle("GET "+p+"/admin/jobs", adminChain(http.HandlerFunc(jobHandler.List)))
	router.Handle("GET "+p+"/admin/jobs/{name}", adminChain(http.HandlerFunc(jobHandler.Get)))
	router.Handle("POST "+p+"/admin/jobs/{name}/trigger", adminChain(http.HandlerFunc(jobHandler.Trigger)))
	router.Handle("POST "+p+"/admin/jobs/{name}/pause", adminChain(http.HandlerFunc(jobHandler.Pause)))
	router.Handle("POST "+p+"/admin/jobs/{name}/resume", adminChain(http.HandlerFunc(jobHandler.Resume)))

	// App registration + per-user grants (AUDIT 8.3 / docs/APP_REGISTRATION.md).
	router.Handle("POST "+p+"/admin/apps", systemAdminChain(http.HandlerFunc(appHandler.Create)))
	router.Handle("GET "+p+"/admin/apps", adminChain(http.HandlerFunc(appHandler.List)))
	router.Handle("GET "+p+"/admin/apps/{appId}", adminChain(http.HandlerFunc(appHandler.Get)))
	router.Handle("PATCH "+p+"/admin/apps/{appId}", systemAdminChain(http.HandlerFunc(appHandler.Update)))
	router.Handle("DELETE "+p+"/admin/apps/{appId}", systemAdminChain(http.HandlerFunc(appHandler.Delete)))
	router.Handle("GET "+p+"/admin/users/{userId}/apps", adminChain(http.HandlerFunc(appHandler.ListUserApps)))
	router.Handle("POST "+p+"/admin/users/{userId}/apps/{appId}", adminChain(http.HandlerFunc(appHandler.GrantUser)))
	router.Handle("DELETE "+p+"/admin/users/{userId}/apps/{appId}", adminChain(http.HandlerFunc(appHandler.RevokeUser)))

	// User pools (namespaces) administration — system_admin only.
	// Moving identities between pools is an identity-tier operation
	// (it changes who an email resolves to per app), so it sits with
	// apps + m2m below the super_admin data tier. docs/USER_POOLS.md.
	router.Handle("GET "+p+"/admin/namespaces", systemAdminChain(http.HandlerFunc(userHandler.ListNamespaces)))
	router.Handle("GET "+p+"/admin/users/{userId}/namespaces", systemAdminChain(http.HandlerFunc(userHandler.GetUserNamespaces)))
	router.Handle("PUT "+p+"/admin/users/{userId}/namespace", systemAdminChain(http.HandlerFunc(userHandler.SetUserHomeNamespace)))
	router.Handle("POST "+p+"/admin/users/{userId}/namespaces", systemAdminChain(http.HandlerFunc(userHandler.AddUserNamespace)))
	router.Handle("DELETE "+p+"/admin/users/{userId}/namespaces/{namespace}", systemAdminChain(http.HandlerFunc(userHandler.RemoveUserNamespace)))

	// M2M client_credentials registry. system_admin only — these are
	// platform-internal credentials that authorize service-to-service
	// calls into this server's admin surface. Mistakenly delegating
	// create/revoke to super_admin would let a data-tier role mint
	// credentials that can in turn execute system_admin-level actions.
	router.Handle("POST "+p+"/admin/m2m-clients", systemAdminChain(http.HandlerFunc(m2mHandler.Create)))
	router.Handle("GET "+p+"/admin/m2m-clients", systemAdminChain(http.HandlerFunc(m2mHandler.List)))
	router.Handle("GET "+p+"/admin/m2m-clients/{clientId}", systemAdminChain(http.HandlerFunc(m2mHandler.Get)))
	router.Handle("DELETE "+p+"/admin/m2m-clients/{clientId}", systemAdminChain(http.HandlerFunc(m2mHandler.Revoke)))
	// Self-service: authenticated users list their own app memberships.
	router.Handle("GET "+p+"/me/apps", authMw.Authenticate(http.HandlerFunc(appHandler.MyApps)))
	// AUTH-PHP-LARAVEL-DESIGN §5: self-service org memberships. Mirrors
	// /me/apps. Lets UIs render an org-switcher without admin scope —
	// the access token claim only carries the *current* org, which is
	// insufficient when the user belongs to several.
	router.Handle("GET "+p+"/me/orgs", authMw.Authenticate(http.HandlerFunc(userHandler.GetMyOrganizations)))

	// Self-service account deletion. Requires the caller's current
	// password + a typed "DELETE" confirmation in the body.
	router.Handle("DELETE "+p+"/me/account", authMw.Authenticate(http.HandlerFunc(authHandler.DeleteMyAccount)))

	// /me/invitations — invitee-side invitation surface. List pending,
	// accept, decline. Authenticated (the email match is verified at
	// service layer for constant-time NotFound on mismatch).
	router.Handle("GET "+p+"/me/invitations", authMw.Authenticate(http.HandlerFunc(invitationHandler.ListMyInvitations)))
	router.Handle("POST "+p+"/me/invitations/{invitationId}/accept", authMw.Authenticate(http.HandlerFunc(invitationHandler.AcceptMyInvitation)))
	router.Handle("POST "+p+"/me/invitations/{invitationId}/decline", authMw.Authenticate(http.HandlerFunc(invitationHandler.DeclineMyInvitation)))

	// AUDIT 2.4: org-scoped self-service endpoints. Routed to the same
	// OrganizationHandler methods but gated by RequireOrgContext (caller's
	// JWT must be scoped to {orgId}) plus a permission check. system_admin
	// bypasses the path-match. Handler-level role-level guard (AUDIT 3.2)
	// catches privilege-escalation on AddMember.
	orgSelfChain := func(perm string, h http.Handler) http.Handler {
		return authMw.Authenticate(authMw.RequireOrgContext(authMw.RequirePermission(perm)(h)))
	}
	router.Handle("GET "+p+"/orgs/{orgId}/members", orgSelfChain("org:members:read", http.HandlerFunc(orgHandler.ListMembers)))
	router.Handle("POST "+p+"/orgs/{orgId}/members", orgSelfChain("org:members:invite", http.HandlerFunc(orgHandler.AddMember)))
	router.Handle("DELETE "+p+"/orgs/{orgId}/members/{userId}", orgSelfChain("org:members:remove", http.HandlerFunc(orgHandler.RemoveMember)))
	router.Handle("PUT "+p+"/orgs/{orgId}/members/{userId}/status", orgSelfChain("org:members:update", http.HandlerFunc(orgHandler.UpdateMemberStatus)))
	router.Handle("GET "+p+"/orgs/{orgId}", orgSelfChain("org:read", http.HandlerFunc(orgHandler.GetOrganization)))
	router.Handle("PUT "+p+"/orgs/{orgId}", orgSelfChain("org:update", http.HandlerFunc(orgHandler.UpdateOrganization)))

	// AUDIT C3: org self-service custom role CRUD. Same chain as members
	// endpoints; service layer enforces the org_assignable gate so platform
	// permissions can't be delegated through a custom role.
	orgRoleHandler := handlers.NewOrgRoleHandler(roleService)
	router.Handle("GET "+p+"/orgs/{orgId}/roles", orgSelfChain("org:roles:read", http.HandlerFunc(orgRoleHandler.List)))
	router.Handle("GET "+p+"/orgs/{orgId}/roles/{roleId}", orgSelfChain("org:roles:read", http.HandlerFunc(orgRoleHandler.Get)))
	router.Handle("POST "+p+"/orgs/{orgId}/roles", orgSelfChain("org:roles:create", http.HandlerFunc(orgRoleHandler.Create)))
	router.Handle("PUT "+p+"/orgs/{orgId}/roles/{roleId}", orgSelfChain("org:roles:update", http.HandlerFunc(orgRoleHandler.Update)))
	router.Handle("DELETE "+p+"/orgs/{orgId}/roles/{roleId}", orgSelfChain("org:roles:delete", http.HandlerFunc(orgRoleHandler.Delete)))
	router.Handle("GET "+p+"/orgs/{orgId}/permissions/assignable", orgSelfChain("org:roles:read", http.HandlerFunc(orgRoleHandler.ListAssignablePermissions)))

	// Org-side invitations: invite by email + list + revoke. Replaces
	// the "add member by user_id" UX with a more natural workflow.
	router.Handle("POST "+p+"/orgs/{orgId}/invitations", orgSelfChain("org:members:invite", http.HandlerFunc(invitationHandler.CreateOrgInvitation)))
	router.Handle("GET "+p+"/orgs/{orgId}/invitations", orgSelfChain("org:members:read", http.HandlerFunc(invitationHandler.ListOrgInvitations)))
	router.Handle("DELETE "+p+"/orgs/{orgId}/invitations/{invitationId}", orgSelfChain("org:members:invite", http.HandlerFunc(invitationHandler.RevokeOrgInvitation)))

	// Apply global middleware. AUDIT 7.10: BodyLimit applied to the full
	// chain so every endpoint inherits the 5MB default. Routes that
	// legitimately accept larger bodies (bulk-CSV etc., when we add them)
	// can apply BodyLimit(15*MB) per-route inside their own subrouter.
	// AUDIT 9.4: idempotency middleware before the rate limiter so a
	// cached-replay doesn't count toward the rate-limit budget.
	var redisCli *redis.Client
	if redisClient != nil && redisClient.IsConnected() {
		redisCli = redisClient.Client()
	}
	handler := middleware.Chain(
		middleware.Recovery,
		middleware.Logger,
		middleware.RequestID,
		middleware.SecurityHeaders(middleware.SecurityHeadersOptions{
			Production: cfg.IsProduction(),
		}),
		middleware.CORS(cfg.Server.CORSOrigins),
		middleware.BodyLimit(middleware.DefaultBodyLimit),
		middleware.Idempotency(redisCli),
		rateLimiter.Limit,
	)(router)

	return handler
}

// fedcmBranding builds the account-chooser styling the BROWSER paints. It is the
// only visual control an IdP has in a FedCM flow, so it is worth getting right —
// a chooser that does not look like the product reads as a phishing dialog.
//
// Env-overridable so a non-CivicGate deployment is not stuck advertising
// CivicGate's name and icon.
func fedcmBranding() handlers.FedCMBranding {
	b := handlers.DefaultFedCMBranding()
	if v := os.Getenv("FEDCM_BRAND_NAME"); v != "" {
		b.Name = v
	}
	if v := os.Getenv("FEDCM_BRAND_ICON_URL"); v != "" {
		b.IconURL = v
	}
	if v := os.Getenv("FEDCM_BRAND_BACKGROUND"); v != "" {
		b.BackgroundColor = v
	}
	if v := os.Getenv("FEDCM_BRAND_COLOR"); v != "" {
		b.Color = v
	}
	return b
}

// getEnvBool reads a boolean env var, falling back to def when unset or
// unparseable. Unparseable falls back rather than erroring: a typo in a cookie
// flag must not stop the server from booting.
func getEnvBool(key string, def bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	parsed, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return parsed
}

// methodRouter routes requests based on HTTP method
type methodRouter struct {
	handlers map[string]http.Handler
}

func newMethodRouter() *methodRouter {
	return &methodRouter{
		handlers: make(map[string]http.Handler),
	}
}

func (m *methodRouter) Handle(method string, handler http.Handler) {
	m.handlers[method] = handler
}

func (m *methodRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if handler, ok := m.handlers[r.Method]; ok {
		handler.ServeHTTP(w, r)
		return
	}
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}
