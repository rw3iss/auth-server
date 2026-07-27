// Login, logout, token refresh & session management — the password
// credential path (with 2FA gate + legacy migration fallback), refresh
// rotation, and per-session control. Split from auth_service.go
// (2026-06-11); shared state/helpers live there.
// Package service provides business logic services for the auth application
package auth

import (
	"context"

	"github.com/rw3iss/auth/internal/audit"
	"github.com/rw3iss/auth/internal/auth/jwt"
	"github.com/rw3iss/auth/internal/auth/totp"
	"github.com/rw3iss/auth/internal/domain"
	"github.com/rw3iss/auth/pkg/shared/errors"
	"github.com/rw3iss/auth/pkg/shared/types"
	"github.com/rw3iss/auth/pkg/shared/utils"
)

// AuthService handles authentication business logic

type LoginInput struct {
	Email          string `json:"email" validate:"required,email"`
	Password       string `json:"password" validate:"required"`
	OrganizationID string `json:"organization_id,omitempty"` // Optional org context
	// AppCode scopes the issued token to a registered consuming app.
	// AUDIT 8.3, docs/APP_REGISTRATION.md. Behavior:
	//   - present + recognised → token is scoped to that app
	//   - present + unrecognised → 400/404
	//   - empty + cfg.AUTH_DEFAULT_APP_CODE set → fall back to default
	//   - empty + cfg.AUTH_ALLOW_BASE_USER_LOGIN=true → base-user mode
	//     (no app context — for tracking/form-submission flows)
	//   - empty + neither → 400 InvalidInput
	AppCode    string `json:"app_code,omitempty"`
	RememberMe bool   `json:"remember_me,omitempty"`
	// TwoFactorCode is the 6-digit TOTP for accounts with 2FA active
	// (AUDIT C4). Omit on the first login attempt; the server responds
	// `requires_2fa: true` and the client retries with the code populated.
	// We deliberately don't introduce a separate "mfa_token" endpoint —
	// keeping it as a re-submit of the same form keeps the surface small
	// and the security delta is marginal (password is in the client either
	// way until the second attempt succeeds).
	TwoFactorCode string `json:"two_factor_code,omitempty"`
	DeviceInfo    string `json:"device_info,omitempty"`
	IPAddress     string `json:"ip_address,omitempty"`
	UserAgent     string `json:"user_agent,omitempty"`

	// §7 per-request provisioning overrides (used when the app auto-grants
	// on first contact / auto-registers a migrated user). RoleCode overrides
	// the app's default_role_code for the default-org membership; it is still
	// validated server-side as an org-scoped role (no privilege escalation).
	// LinkedAppCodes overrides the app's linked_app_codes (nil = use the app
	// default). Both fall back to the app config when empty.
	RoleCode       string   `json:"role_code,omitempty"`
	LinkedAppCodes []string `json:"linked_app_codes,omitempty"`
}

// LoginResult contains the result of login. AUDIT C2 introduced a second
// terminal shape for SSO with PKCE: when AuthCode is non-empty, TokenPair is
// nil and the caller is expected to render an SSOAuthCodeResponse instead.
// The public client redeems {auth_code, code_verifier} at /auth/sso/exchange.
type LoginResult struct {
	User         *domain.User         `json:"user"`
	Organization *domain.Organization `json:"organization,omitempty"`
	TokenPair    *jwt.TokenPair       `json:"tokens"`
	Roles        []string             `json:"roles"`
	Permissions  []string             `json:"permissions"`

	// AuthCode + AuthCodeExpiresIn are set only when SSO completed under PKCE.
	// Mutually exclusive with TokenPair: presence of AuthCode means tokens
	// have NOT been minted; absence means they have.
	AuthCode          string `json:"auth_code,omitempty"`
	AuthCodeExpiresIn int64  `json:"auth_code_expires_in,omitempty"`

	// RequiresTwoFactor is true when password authentication succeeded but
	// the user has 2FA enabled and the request omitted `two_factor_code`
	// (or supplied a wrong one). Client should re-POST /auth/login with
	// the code populated. AUDIT C4.
	RequiresTwoFactor bool `json:"requires_2fa,omitempty"`
}

// Login authenticates a user
func (s *AuthService) Login(ctx context.Context, input LoginInput) (*LoginResult, error) {
	email := types.Email(utils.NormalizeEmail(input.Email))

	// AUDIT 1.17: per-account rate limit, independent of per-IP. A
	// botnet-distributed attack that gets one request through per IP can
	// still saturate this counter, capping wall-clock guesses per email.
	// Hash the email so the Redis key doesn't carry PII.
	emailKey := sha256Hex(string(email))
	if s.cfg.Auth.AccountAttemptsLimit > 0 {
		count, _ := s.tokenCache.IncrementAccountAttempts(ctx, emailKey, s.cfg.Auth.AccountAttemptsWindow)
		if count > int64(s.cfg.Auth.AccountAttemptsLimit) {
			audit.Record(ctx, audit.Event{
				Action: "login.rate_limited_account",
				Details: map[string]any{
					"email_sha256": emailKey,
					"attempts":     count,
				},
			})
			return nil, errors.RateLimited()
		}
	}

	// Migration 017 — resolve the target app BEFORE looking up the user,
	// so the lookup is scoped to the app's READ namespaces (user pools).
	// User-specific authorization (user_apps membership / auto-grant) is
	// still checked further down, once we have the user. App identity
	// resolution (which pools, is it active) is independent of the user,
	// so hoisting it here is safe and lets login honor pool segregation.
	var resolvedApp *domain.App
	readNamespaces := []string{domain.DefaultNamespace}
	if s.appService != nil {
		appCode := input.AppCode
		if appCode == "" {
			appCode = s.cfg.Auth.DefaultAppCode
		}
		if appCode != "" {
			app, appErr := s.appService.GetByCode(ctx, appCode)
			if appErr != nil {
				return nil, errors.NotFound("app")
			}
			if !app.IsActive() {
				return nil, errors.New(errors.ErrCodeValidation, "app is not active", 403)
			}
			resolvedApp = app
			readNamespaces = app.EffectiveReadNamespaces()
		} else if !s.cfg.Auth.AllowBaseUserLogin {
			return nil, errors.InvalidInput("app_code", "app_code is required")
		}
	}

	// Resolve the legacy provider + write pool for this app once (§5). The
	// provider is nil unless COGNITO_AUTO_MIGRATE_ENABLED or an app-specific
	// provider is registered, so deployments without migration pay zero cost.
	legacyAppCode := ""
	writeNamespace := domain.DefaultNamespace
	if resolvedApp != nil {
		legacyAppCode = resolvedApp.Code
		writeNamespace = resolvedApp.WriteNamespace()
	}
	legacyProvider, legacyMapper := s.legacyProviderFor(legacyAppCode)

	// Get user, scoped to the app's read namespaces (migration 017).
	// AUDIT B7b / §5: when the internal store doesn't know the email AND a
	// legacy-auth provider applies to this app, try it — provisioning the
	// migrated user into the app's write pool + tags.
	user, err := s.userRepo.GetByEmailInNamespaces(ctx, email, readNamespaces)
	if err != nil {
		if legacyProvider != nil {
			migrated, migErr := s.tryMigrateFromLegacy(ctx, email, input.Password,
				legacyProvider, legacyMapper, writeNamespace, domain.ExcludeHomeNamespace(readNamespaces, writeNamespace))
			if migErr == nil && migrated != nil {
				user = migrated
				// Fall through to the success path with this freshly
				// migrated user as if they'd always existed.
			} else {
				// Either user truly absent everywhere (ErrLegacyUserNotFound)
				// or the legacy login failed. Same response shape either way
				// — never reveal which branch broke.
				return nil, errors.InvalidCredentials()
			}
		} else {
			return nil, errors.InvalidCredentials()
		}
	}

	// Check if user can login
	if user.IsLocked() {
		return nil, errors.New(errors.ErrCodeUserSuspended, "Account is temporarily locked due to too many failed login attempts", 403)
	}

	if user.Status == types.UserStatusSuspended {
		return nil, errors.UserSuspended()
	}

	if user.Status == types.UserStatusDeleted || user.IsDeleted() {
		return nil, errors.UserNotFound()
	}

	// Verify password
	if !utils.CheckPassword(input.Password, user.PasswordHash) {
		// §5 conflict detection: the user already exists in the auth-server,
		// but the supplied password doesn't match the internal credential.
		// If a legacy provider applies and the SAME password authenticates
		// against the legacy store, the two systems hold different creds for
		// this email — halt with an explicit conflict rather than silently
		// overwriting or failing. (We never migrate/overwrite in this case.)
		if legacyProvider != nil {
			if _, lerr := legacyProvider.TryLogin(ctx, string(email), input.Password); lerr == nil {
				audit.Record(ctx, audit.Event{
					Action:      "login.legacy_migration_conflict",
					ActorUserID: &user.ID,
					Details:     map[string]any{"app_code": legacyAppCode, "source": legacyProvider.Name()},
				})
				return nil, errors.LegacyMigrationConflict(string(email), legacyAppCode)
			}
		}
		// Increment failed login attempts
		user.IncrementFailedLogin(s.cfg.Auth.MaxLoginAttempts, s.cfg.Auth.LockoutDuration)
		_ = s.userRepo.Update(ctx, user)
		audit.Record(ctx, audit.Event{
			Action:      "login.failed",
			ActorUserID: &user.ID,
			Details:     map[string]any{"reason": "invalid_password"},
		})
		return nil, errors.InvalidCredentials()
	}

	// AUDIT C4 — TOTP gate. Runs after the password check so we never reveal
	// the existence of 2FA to an attacker who can't authenticate. Branches:
	//
	//   - 2FA inactive → fall through.
	//   - 2FA active + code empty → return RequiresTwoFactor=true. Handler
	//     renders 401 with `{requires_2fa: true}`; client re-POSTs with code.
	//   - 2FA active + code present but wrong → audit `2fa.failed`, treat
	//     identically to wrong-password (same lockout counter). Same
	//     RequiresTwoFactor flag set so the client can retry.
	//   - 2FA active + code present and valid → fall through.
	if user.IsTwoFactorActive() {
		if input.TwoFactorCode == "" {
			return &LoginResult{RequiresTwoFactor: true}, nil
		}
		if !totp.Validate(input.TwoFactorCode, user.TwoFactorSecret) {
			user.IncrementFailedLogin(s.cfg.Auth.MaxLoginAttempts, s.cfg.Auth.LockoutDuration)
			_ = s.userRepo.Update(ctx, user)
			audit.Record(ctx, audit.Event{
				Action:      "2fa.failed",
				ActorUserID: &user.ID,
				Details:     map[string]any{"reason": "invalid_code"},
			})
			return &LoginResult{RequiresTwoFactor: true}, nil
		}
		audit.Record(ctx, audit.Event{
			Action:      "2fa.verified",
			ActorUserID: &user.ID,
		})
	}

	// Reset failed login attempts on successful login
	if user.FailedLoginAttempts > 0 {
		user.ResetFailedLogin()
	}

	// Update last login
	now := types.Now()
	user.LastLoginAt = &now
	_ = s.userRepo.Update(ctx, user)

	// Get roles and permissions
	var roles []*domain.Role
	var permissions []string
	var org *domain.Organization

	if input.OrganizationID != "" {
		// Login with organization context
		orgID, err := types.ParseID(input.OrganizationID)
		if err != nil {
			return nil, errors.InvalidInput("organization_id", "Invalid organization ID")
		}

		org, err = s.orgRepo.GetByID(ctx, orgID)
		if err != nil {
			return nil, errors.OrgNotFound()
		}

		if !org.IsActive() {
			return nil, errors.New(errors.ErrCodeOrgSuspended, "Organization is suspended", 403)
		}

		// Get membership
		membership, err := s.orgRepo.GetMembership(ctx, user.ID, orgID)
		if err != nil {
			return nil, errors.NotOrgMember()
		}

		if !membership.IsActive() {
			return nil, errors.NotOrgMember()
		}

		// Get organization roles
		roles, err = s.orgRepo.GetMemberRoles(ctx, membership.ID)
		if err != nil {
			return nil, err
		}
	} else {
		// Login without organization context - get base roles
		roles, err = s.userRepo.GetBaseRoles(ctx, user.ID)
		if err != nil {
			return nil, err
		}
	}

	// AUDIT 4.1: one batched query for permissions across every role,
	// instead of N+1 (was 3-5 queries per login depending on role count).
	roleCodes := make([]string, len(roles))
	for i, role := range roles {
		roleCodes[i] = role.Code
	}
	permissions = s.collectPermissions(ctx, roles)

	// AUDIT 8.3: app authorization. App *identity* was resolved above —
	// before the user lookup — so the lookup could be scoped to the app's
	// read namespaces (user pools, migration 017). The order/fallback
	// rules (input.AppCode → AUTH_DEFAULT_APP_CODE → base-user mode →
	// reject) are enforced there. Here we enforce user-specific access:
	// an active user_apps membership, or auto-grant on first login when
	// the app opts in.
	if resolvedApp != nil {
		// §2 — ensure the user carries the app's namespace tag(s). Idempotent;
		// this is the "reconnect / link" step for a returning shared identity.
		if tags := domain.ExcludeHomeNamespace(readNamespaces, user.Namespace); len(tags) > 0 {
			_ = s.userRepo.AddUserToNamespaces(ctx, user.ID, tags)
		}
		authorized, _ := s.appService.IsUserAuthorized(ctx, user.ID, resolvedApp.ID)
		if !authorized {
			if !resolvedApp.AutoGrantOnSignup {
				return nil, errors.Forbidden("user is not authorized for this app")
			}
			// First contact (new / JIT-migrated / un-granted user) → full
			// provisioning: app + linked-app memberships + default-org role,
			// honoring per-request overrides. Idempotent + best-effort. §7.
			s.ensureAppEntitlements(ctx, user, resolvedApp, EntitlementOverrides{
				RoleCode:          input.RoleCode,
				LinkedAppCodes:    input.LinkedAppCodes,
				LinkedAppCodesSet: input.LinkedAppCodes != nil,
			})
		}
	}

	// Generate tokens
	tokenInput := jwt.GenerateTokenInput{
		User:         user,
		Organization: org,
		App:          resolvedApp,
		Roles:        roles,
		Permissions:  permissions,
		RememberMe:   input.RememberMe,
		DeviceInfo:   input.DeviceInfo,
		IPAddress:    input.IPAddress,
		UserAgent:    input.UserAgent,
	}

	tokenPair, err := s.jwtService.GenerateTokenPair(ctx, tokenInput)
	if err != nil {
		return nil, errors.Internal("Failed to generate tokens")
	}

	// Successful login: clear the per-account-attempts counter so a
	// legitimate user who finally remembers their password isn't penalized
	// by leftover failed attempts trailing in the window.
	_ = s.tokenCache.ResetAccountAttempts(ctx, emailKey)

	auditEvt := audit.Event{
		Action:      "login.success",
		ActorUserID: &user.ID,
	}
	if org != nil {
		auditEvt.OrganizationID = &org.ID
	}
	audit.Record(ctx, auditEvt)

	return &LoginResult{
		User:         user,
		Organization: org,
		TokenPair:    tokenPair,
		Roles:        roleCodes,
		Permissions:  permissions,
	}, nil
}

// SSOLoginInput contains input for SSO login

func (s *AuthService) RefreshTokens(ctx context.Context, refreshToken string, orgID *types.ID) (*jwt.TokenPair, error) {
	claims, err := s.jwtService.ValidateRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, err
	}

	user, err := s.userRepo.GetByID(ctx, claims.UserID)
	if err != nil {
		return nil, err
	}

	// Use same checks as Login: allow pending users, reject suspended/deleted
	if user.Status == types.UserStatusSuspended {
		return nil, errors.UserSuspended()
	}
	if user.Status == types.UserStatusDeleted || user.IsDeleted() {
		return nil, errors.UserNotFound()
	}

	// Determine organization context. AUDIT 2.2 + 2.7: when an org is
	// requested (either via this call or carried in the refresh token's
	// claim), every failure mode along the way must surface an explicit
	// error — not silently drop the user back to base roles. Silent
	// downgrade lets a user who was just kicked out of org X get a
	// "personal" session they didn't ask for, and worse, a suspended-org
	// user get a working session. Login already has this shape (auth_service
	// :353-376); refresh needs to match.
	useOrgID := claims.OrganizationID
	if orgID != nil {
		useOrgID = orgID
	}

	var roles []*domain.Role
	var permissions []string
	var org *domain.Organization

	if useOrgID != nil {
		org, err = s.orgRepo.GetByID(ctx, *useOrgID)
		if err != nil {
			return nil, errors.OrgNotFound()
		}
		if !org.IsActive() {
			return nil, errors.New(errors.ErrCodeOrgSuspended, "Organization is suspended", 403)
		}
		membership, err := s.orgRepo.GetMembership(ctx, user.ID, *useOrgID)
		if err != nil {
			return nil, errors.NotOrgMember()
		}
		if !membership.IsActive() {
			return nil, errors.NotOrgMember()
		}
		roles, err = s.orgRepo.GetMemberRoles(ctx, membership.ID)
		if err != nil {
			return nil, err
		}
	} else {
		// No org context requested — base roles only.
		roles, err = s.userRepo.GetBaseRoles(ctx, user.ID)
		if err != nil {
			return nil, err
		}
	}

	// AUDIT 4.1: batched permission fetch on the refresh path too.
	permissions = s.collectPermissions(ctx, roles)

	// Preserve app scope across refresh — the refresh token carries the
	// app_code it was minted under, so the new access token keeps its
	// app_id/app_code claims (and the permission union for the app's services).
	var app *domain.App
	if claims.AppCode != "" && s.appService != nil {
		if a, aerr := s.appService.GetByCode(ctx, claims.AppCode); aerr == nil && a != nil && a.IsActive() {
			app = a
		}
	}

	tokenInput := jwt.GenerateTokenInput{
		User:         user,
		Organization: org,
		App:          app,
		Roles:        roles,
		Permissions:  permissions,
		RememberMe:   claims.RememberMe,
	}

	return s.jwtService.RefreshTokens(ctx, refreshToken, tokenInput)
}

// Logout logs out a user (revokes their refresh token)
func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	claims, err := s.jwtService.ValidateRefreshToken(ctx, refreshToken)
	if err != nil {
		return err
	}

	return s.jwtService.RevokeRefreshToken(ctx, claims.TokenID, "user_logout")
}

// LogoutWithCaller revokes a refresh token but requires the caller's
// access-token user_id to match the refresh token's user_id (AUDIT 1.23).
// Without this gate, an attacker who exfiltrated a refresh token through
// a CSRF / XSS vector could trigger logouts for any user whose token
// they obtained, even without being authenticated themselves. The
// authenticated /auth/logout requires Authorization: Bearer; we then
// double-check the bearer identity against the refresh-token identity.
func (s *AuthService) LogoutWithCaller(ctx context.Context, refreshToken string, callerID types.ID) error {
	claims, err := s.jwtService.ValidateRefreshToken(ctx, refreshToken)
	if err != nil {
		return err
	}
	if claims.UserID != callerID {
		// Don't reveal which side mismatched — just an Unauthorized.
		return errors.Unauthorized("refresh token does not match the authenticated user")
	}
	return s.jwtService.RevokeRefreshToken(ctx, claims.TokenID, "user_logout")
}

// LogoutAll logs out a user from all sessions
func (s *AuthService) LogoutAll(ctx context.Context, userID types.ID) error {
	return s.jwtService.RevokeAllUserTokens(ctx, userID, "user_logout_all")
}

// ResendVerificationEmail re-sends the email-verification link for an
// unverified account (AUDIT 5.4). Modeled on RequestPasswordReset:
//
//   - Always returns nil from the caller's POV so a probing client can't
//     enumerate which emails exist or which accounts are already verified.
//   - Silently no-ops when the email isn't registered, when the user is
//     already email-verified, when the user is suspended/deleted, or
//     when the email service is unconfigured.
//   - Generates a fresh token via the standard jwtService.GenerateEmailVerificationToken
//     path, which atomically invalidates any prior unverified token for
//     this user — see token_repository's InvalidateUserEmailVerificationTokens.
//
// Rate limiting is the route-layer's responsibility (the global per-IP
// limit applies; operators can tune AUTH_ACCOUNT_ATTEMPTS_LIMIT for
// per-email if they want a tighter bound).

func (s *AuthService) GetUserSessions(ctx context.Context, userID types.ID) ([]*domain.Session, error) {
	return s.jwtService.GetUserSessions(ctx, userID)
}

// GetUserProfile loads the full user row for a given id. Used by the
// /auth/me handler to surface profile fields (e.g. default_color_mode)
// that aren't carried in the JWT claims.
func (s *AuthService) GetUserProfile(ctx context.Context, userID types.ID) (*domain.User, error) {
	return s.userRepo.GetByID(ctx, userID)
}

// TerminateSession terminates a specific session
func (s *AuthService) TerminateSession(ctx context.Context, userID, sessionID types.ID) error {
	session, err := s.tokenRepo.GetSession(ctx, sessionID)
	if err != nil {
		return err
	}

	// Verify ownership
	if session.UserID != userID {
		return errors.Forbidden("Cannot terminate session of another user")
	}

	return s.jwtService.TerminateSession(ctx, sessionID)
}

// ValidateToken validates an access token and returns the claims
