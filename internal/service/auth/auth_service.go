// AuthService — core service state, construction and shared helpers.
//
// The auth domain logic is split by purpose across sibling files (all
// methods on the same *AuthService):
//
//	auth_registration.go  — Register (+ webhooks dispatch), register-or-login,
//	                        email verification (send/verify/resend)
//	auth_login.go         — Login, RefreshTokens, Logout/LogoutAll, sessions
//	auth_sso.go           — SSO URL minting, callback login, PKCE exchange,
//	                        enabled-provider listing
//	auth_password.go      — password reset request/complete, ChangePassword
//	auth_2fa.go           — TOTP setup / enable / disable (AUDIT C4)
//	auth_admin.go         — CheckEmail (service-only), AdminSetPassword,
//	                        Impersonate, HardDeleteUser, DeleteMyAccount
//	auth_migration.go     — legacy-auth (Cognito) login fallback
//
// This file keeps the struct, constructor, option builders and the
// cross-cutting helpers those files share.
// Package service provides business logic services for the auth application
package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/rw3iss/auth/internal/auth/jwt"
	"github.com/rw3iss/auth/internal/auth/password"
	"github.com/rw3iss/auth/internal/auth/sso"
	"github.com/rw3iss/auth/internal/cache"
	"github.com/rw3iss/auth/internal/config"
	"github.com/rw3iss/auth/internal/domain"
	"github.com/rw3iss/auth/internal/repository"
	"github.com/rw3iss/auth/internal/service"
	"github.com/rw3iss/auth/pkg/migration"
	"github.com/rw3iss/auth/pkg/shared/types"
	"github.com/rw3iss/auth/pkg/shared/utils"
)

// AuthService handles authentication business logic

type AuthService struct {
	cfg          *config.Config
	userRepo     repository.UserRepository
	orgRepo      repository.OrganizationRepository
	roleRepo     repository.RoleRepository
	permRepo     repository.PermissionRepository
	inviteRepo   repository.InvitationRepository
	tokenRepo    repository.TokenRepository
	txManager    repository.TransactionManager
	jwtService   *jwt.Service
	ssoManager   *sso.Manager
	emailService service.EmailService
	tokenCache   cache.TokenCache // AUDIT 1.17: per-account rate-limit primitive

	// Optional legacy-auth fallback for migrating users off a previous
	// identity system (Cognito in rw3iss's case). Wired in main.go when
	// COGNITO_AUTO_MIGRATE_ENABLED=true and a working Cognito adapter
	// initialised cleanly. Nil otherwise — AuthService.Login skips the
	// migration branch entirely.
	legacyAuth migration.LegacyAuthProvider
	roleMapper migration.RoleMapper

	// §5 — per-app legacy providers, keyed by app_code. Lets each consuming
	// app supply its own legacy backend (GlobalSKU, ClaimLeo, …) for JIT
	// migration, independent of the global Cognito fallback above. An app
	// with no entry here (and no global provider) gets zero JIT cost.
	legacyProviders map[string]migration.LegacyAuthProvider
	legacyMappers   map[string]migration.RoleMapper

	// AUDIT 8.3 — app-scoping. Nil when no AppRepository is wired (legacy
	// deployments + tests that don't care). Login resolves the supplied
	// app_code via this service before issuing tokens.
	appService AppDirectory

	// hashers is the legacy-hash strategy registry for bulk pre-hashed
	// import (§4). Nil ⇒ lazily defaulted to bcrypt-only in BulkImport.
	// Inject a richer registry via WithHasherRegistry to support argon2id,
	// pbkdf2, etc. without touching core.
	hashers *password.Registry
}

// WithHasherRegistry injects a legacy-hash strategy registry for bulk import.
// Optional — defaults to a bcrypt-only registry.
func (s *AuthService) WithHasherRegistry(r *password.Registry) *AuthService {
	s.hashers = r
	return s
}

// WithAppService injects the AppService so Login can resolve app_code →
// app row and gate issuance accordingly. Optional — when nil, Login
// behaves as if AUTH_ALLOW_BASE_USER_LOGIN were on (every login produces
// a base-user token). main.go always wires this in production.
// AppDirectory is the slice of the app registry the auth domain needs.
// Implemented by *service.AppService; defined here as an interface so
// this package doesn't import its parent (no cycle, easy test fakes).
type AppDirectory interface {
	// GetByCode resolves an app_code to its registry row (hot path on
	// every login/register).
	GetByCode(ctx context.Context, code string) (*domain.App, error)
	// IsUserAuthorized reports whether the user holds an active
	// user_apps membership in the app.
	IsUserAuthorized(ctx context.Context, userID, appID types.ID) (bool, error)
	// GrantUser creates/reactivates a user_apps membership
	// (auto_grant_on_signup path). grantedBy nil = self/auto grant.
	GrantUser(ctx context.Context, userID, appID types.ID, grantedBy *types.ID) error
}

func (s *AuthService) WithAppService(a AppDirectory) *AuthService {
	s.appService = a
	return s
}

// WithLegacyAuth wires in a legacy-system auto-migration provider. Called
// from main.go when COGNITO_AUTO_MIGRATE_ENABLED is set. Idempotent — call
// again with nil to disable. The default role mapper is installed if none
// is supplied.
//
// Kept as a separate setter (rather than a NewAuthService argument) so
// deployments that don't need migration aren't forced to construct or
// import the migration package.
func (s *AuthService) WithLegacyAuth(provider migration.LegacyAuthProvider, mapper migration.RoleMapper) *AuthService {
	s.legacyAuth = provider
	if mapper == nil {
		mapper = migration.DefaultRoleMapper{}
	}
	s.roleMapper = mapper
	return s
}

// WithLegacyAuthFor registers a legacy-auth provider for a specific app_code
// (§5). Each app can bring its own legacy backend; the global WithLegacyAuth
// provider (if any) is the fallback for app codes without a specific entry.
// The default role mapper is installed when none is supplied.
func (s *AuthService) WithLegacyAuthFor(appCode string, provider migration.LegacyAuthProvider, mapper migration.RoleMapper) *AuthService {
	if appCode == "" || provider == nil {
		return s
	}
	if s.legacyProviders == nil {
		s.legacyProviders = map[string]migration.LegacyAuthProvider{}
		s.legacyMappers = map[string]migration.RoleMapper{}
	}
	if mapper == nil {
		mapper = migration.DefaultRoleMapper{}
	}
	s.legacyProviders[appCode] = provider
	s.legacyMappers[appCode] = mapper
	return s
}

// legacyProviderFor resolves the legacy provider + role mapper for an app
// code: the app-specific registration wins, falling back to the global
// provider (Cognito). Returns (nil, nil) when no provider applies — the
// caller then skips the JIT path entirely (zero cost).
func (s *AuthService) legacyProviderFor(appCode string) (migration.LegacyAuthProvider, migration.RoleMapper) {
	if appCode != "" && s.legacyProviders != nil {
		if p, ok := s.legacyProviders[appCode]; ok {
			m := s.legacyMappers[appCode]
			if m == nil {
				m = migration.DefaultRoleMapper{}
			}
			return p, m
		}
	}
	if s.legacyAuth != nil {
		m := s.roleMapper
		if m == nil {
			m = migration.DefaultRoleMapper{}
		}
		return s.legacyAuth, m
	}
	return nil, nil
}

// sha256Hex hashes a string for use as a Redis key when we don't want the
// raw value (PII like email) in cache storage. Defense in depth — the
// Redis backend is internal, but operationally we don't need plaintext
// emails in cache keys.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// passwordPolicy builds the password policy from runtime config so every
// validation site applies the same configurable rules. Centralising this
// here keeps register/change/reset/admin-set in lockstep — and means relaxing
// (say) "require digit" is a single env var, not a code change (AUDIT 1.5).
func (s *AuthService) passwordPolicy() utils.PasswordPolicy {
	return utils.PasswordPolicy{
		MinLength:      s.cfg.Auth.PasswordMinLength,
		MaxLength:      s.cfg.Auth.PasswordMaxLength,
		RequireUpper:   s.cfg.Auth.PasswordRequireUpper,
		RequireLower:   s.cfg.Auth.PasswordRequireLower,
		RequireDigit:   s.cfg.Auth.PasswordRequireDigit,
		RequireSpecial: s.cfg.Auth.PasswordRequireSpecial,
	}
}

// hashPassword wraps utils.HashPassword at the service layer so every site
// uses the configured cost. Prior to AUDIT 1.3 this was a free function that
// silently fell back to bcrypt.DefaultCost (10) — operators who raised
// BCRYPT_COST got no behavior change.
func (s *AuthService) hashPassword(password string) (string, error) {
	return utils.HashPassword(password, s.cfg.Security.BcryptCost)
}

// collectPermissions returns the unique permission codes across the given
// roles in a single repo round-trip. Replaces the per-role GetPermissions
// loop that ran 3-5 queries per login (AUDIT 4.1).
func (s *AuthService) collectPermissions(ctx context.Context, roles []*domain.Role) []string {
	if len(roles) == 0 {
		return nil
	}
	roleIDs := make([]types.ID, len(roles))
	for i, r := range roles {
		roleIDs[i] = r.ID
	}
	perms, err := s.roleRepo.GetPermissionsForRoles(ctx, roleIDs)
	if err != nil {
		// Match the original loop's tolerant behavior: log silently and
		// return whatever we have (nothing here). A login that proceeds
		// without permissions is bad but a 500 is worse — downstream
		// services will refuse the token on first protected call.
		return nil
	}
	out := make([]string, 0, len(perms))
	for _, p := range perms {
		out = append(out, p.Code)
	}
	return out
}

// NewAuthService creates a new auth service
func NewAuthService(
	cfg *config.Config,
	userRepo repository.UserRepository,
	orgRepo repository.OrganizationRepository,
	roleRepo repository.RoleRepository,
	permRepo repository.PermissionRepository,
	inviteRepo repository.InvitationRepository,
	tokenRepo repository.TokenRepository,
	txManager repository.TransactionManager,
	jwtService *jwt.Service,
	ssoManager *sso.Manager,
	emailService service.EmailService,
	tokenCache cache.TokenCache,
) *AuthService {
	if tokenCache == nil {
		tokenCache = cache.NewNoOpTokenCache()
	}
	return &AuthService{
		cfg:          cfg,
		userRepo:     userRepo,
		orgRepo:      orgRepo,
		roleRepo:     roleRepo,
		permRepo:     permRepo,
		inviteRepo:   inviteRepo,
		tokenRepo:    tokenRepo,
		txManager:    txManager,
		jwtService:   jwtService,
		ssoManager:   ssoManager,
		emailService: emailService,
		tokenCache:   tokenCache,
	}
}

// RegistrationMode controls how Register handles an email-already-exists
// collision. AUDIT 8.1.

const dummyBcryptHash = "$2a$10$DLnLF6cMSPi04Sy2skMtkesgw0Lvf9hMa0LzdJ8DwiR99y6wnXEHa"

// RegisterInput contains input for user registration

// resolveReadNamespaces returns the user pools an app authenticates against
// (migration 017 / docs/USER_POOLS.md). Falls back to [DefaultNamespace] when
// no app context is supplied, the app registry isn't wired, or the code is
// unknown — preserving pre-017 behavior for un-namespaced callers. This is the
// shared resolver for the auxiliary flows (password-reset, check-email,
// resend-verification) that historically used a bare default lookup.
func (s *AuthService) resolveReadNamespaces(ctx context.Context, appCode string) []string {
	if appCode == "" {
		appCode = s.cfg.Auth.DefaultAppCode
	}
	if appCode == "" || s.appService == nil {
		return []string{domain.DefaultNamespace}
	}
	app, err := s.appService.GetByCode(ctx, appCode)
	if err != nil || app == nil || !app.IsActive() {
		return []string{domain.DefaultNamespace}
	}
	return app.EffectiveReadNamespaces()
}

func (s *AuthService) resolveAppBaseURL(ctx context.Context, appCode string) string {
	if appCode == "" || s.appService == nil {
		return ""
	}
	app, err := s.appService.GetByCode(ctx, appCode)
	if err != nil || app == nil || !app.IsActive() {
		return ""
	}
	return app.FrontendBaseURL()
}

// ResetPassword resets a user's password.
//
// AUDIT 1.1: single-use enforcement. The JWT carries the stored row's UUID
// as its `jti` (claims.ID). We look the row up by that id, reject if it's
// already marked used, then update password + mark row used inside the same
// transaction so reuse is impossible even with a leaked link. The transaction
// also revokes the user's outstanding tokens to log them out everywhere.

func (s *AuthService) ValidateToken(tokenString string) (*jwt.TokenClaims, error) {
	return s.jwtService.ValidateAccessToken(tokenString)
}

// GetEnabledSSOProviders returns enabled SSO providers
