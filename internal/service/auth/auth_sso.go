// SSO / OAuth flows — provider URL minting, callback login, PKCE
// exchange, provider listing. Split from auth_service.go (2026-06-11);
// shared state/helpers live there.
// Package service provides business logic services for the auth application
package auth

import (
	"context"
	"time"

	"github.com/rw3iss/auth/internal/auth/jwt"
	"github.com/rw3iss/auth/internal/auth/sso"
	"github.com/rw3iss/auth/internal/domain"
	"github.com/rw3iss/auth/pkg/shared/errors"
	"github.com/rw3iss/auth/pkg/shared/models"
	"github.com/rw3iss/auth/pkg/shared/types"
	"github.com/rw3iss/auth/pkg/shared/utils"
)

// AuthService handles authentication business logic

type SSOLoginInput struct {
	Provider       types.AuthProvider `json:"provider"`
	CustomProvider string             `json:"custom_provider,omitempty"`
	Code           string             `json:"code"`
	State          string             `json:"state"`
	OrganizationID string             `json:"organization_id,omitempty"`
	InviteCode     string             `json:"invite_code,omitempty"`
	// AppCode is a fallback app context for the callback (the authoritative
	// value rides in the SSO state from /auth/sso/url). Used to scope the
	// user-pool lookup + tag membership (migration 017).
	AppCode string `json:"app_code,omitempty"`
	// AppleUser is the raw JSON Apple posts in the `user` form field on the
	// FIRST authorization only (name + email). Empty on every later login.
	AppleUser  string `json:"apple_user,omitempty"`
	DeviceInfo string `json:"device_info,omitempty"`
	IPAddress  string `json:"ip_address,omitempty"`
	UserAgent  string `json:"user_agent,omitempty"`
}

// SSOLogin handles SSO authentication
func (s *AuthService) SSOLogin(ctx context.Context, input SSOLoginInput) (*LoginResult, error) {
	// Handle SSO callback
	userInfo, stateData, err := s.ssoManager.HandleCallback(ctx, input.State, input.Code)
	if err != nil {
		return nil, err
	}

	// Apple delivers the user's name only on the FIRST authorization, in the
	// `user` form-post field (never in the id_token). Backfill it here so a
	// freshly-created Apple user gets a name; later logins omit it.
	if userInfo.Provider == types.AuthProviderApple && userInfo.FirstName == "" && input.AppleUser != "" {
		fn, ln := sso.ParseAppleUserName(input.AppleUser)
		userInfo.FirstName, userInfo.LastName = fn, ln
	}

	// Resolve the app context that rode through the SSO state (migration 017
	// / docs/USER_POOLS.md). The authoritative app_code is captured at
	// /auth/sso/url; input.AppCode is a callback-time fallback. This scopes
	// the by-email lookup to the app's read pools and decides the write pool
	// + namespace tags for a brand-new user.
	appCode := stateData.AppCode
	if appCode == "" {
		appCode = input.AppCode
	}
	var resolvedApp *domain.App
	readNamespaces := []string{domain.DefaultNamespace}
	writeNamespace := domain.DefaultNamespace
	if s.appService != nil && appCode != "" {
		app, appErr := s.appService.GetByCode(ctx, appCode)
		if appErr != nil {
			return nil, errors.NotFound("app")
		}
		if !app.IsActive() {
			return nil, errors.New(errors.ErrCodeValidation, "app is not active", 403)
		}
		resolvedApp = app
		readNamespaces = app.EffectiveReadNamespaces()
		writeNamespace = app.WriteNamespace()
	}

	// Check if user exists with this SSO provider (provider link is global
	// identity — independent of pool).
	user, err := s.userRepo.GetByProviderID(ctx, userInfo.Provider, userInfo.ProviderUserID)

	if err != nil {
		// Not linked yet — resolve the core user by email within the app's
		// read pools so we adopt an existing shared identity rather than
		// minting a duplicate (the "find the core user" behavior the
		// GlobalSKU integration calls for).
		email := types.Email(utils.NormalizeEmail(userInfo.Email))
		user, err = s.userRepo.GetByEmailInNamespaces(ctx, email, readNamespaces)

		if err != nil {
			// Create new user in the app's WRITE pool (home namespace).
			user = domain.NewUser(email, userInfo.FirstName, userInfo.LastName)
			user.Namespace = writeNamespace
			user.DisplayName = userInfo.DisplayName
			user.AvatarURL = userInfo.AvatarURL
			user.AuthProvider = userInfo.Provider
			user.ProviderUserID = userInfo.ProviderUserID
			user.EmailVerified = userInfo.EmailVerified
			if userInfo.EmailVerified {
				user.Status = types.UserStatusActive
			}

			if err := s.userRepo.Create(ctx, user); err != nil {
				return nil, err
			}

			// Assign base user role
			baseRole, err := s.roleRepo.GetByCode(ctx, string(models.RoleBaseUser))
			if err == nil {
				roleAssignment := domain.NewUserBaseRole(user.ID, baseRole.ID, nil)
				_ = s.userRepo.AssignBaseRole(ctx, roleAssignment)
			}
		} else {
			// Link SSO provider to existing user
			link := domain.NewUserAuthProvider(user.ID, userInfo.Provider, userInfo.ProviderUserID)
			if err := s.userRepo.LinkProvider(ctx, link); err != nil {
				return nil, err
			}
		}
	}

	// Ensure the resolved/created user carries the app's namespace tag(s) and
	// an active user_apps membership (auto-grant when the app opts in). This
	// is §2 of the integration spec — "ensure app-namespace membership" — for
	// the SSO path. Mirrors the password-login authorization gate.
	if resolvedApp != nil {
		if tags := domain.ExcludeHomeNamespace(readNamespaces, user.Namespace); len(tags) > 0 {
			_ = s.userRepo.AddUserToNamespaces(ctx, user.ID, tags)
		}
		authorized, _ := s.appService.IsUserAuthorized(ctx, user.ID, resolvedApp.ID)
		if !authorized {
			if !resolvedApp.AutoGrantOnSignup {
				return nil, errors.Forbidden("user is not authorized for this app")
			}
			// First contact via SSO → full §7 provisioning (app + linked-app
			// memberships + default-org role), same as password login + JIT
			// migration. SSO carries no per-request overrides, so app defaults
			// apply. Idempotent + best-effort.
			s.ensureAppEntitlements(ctx, user, resolvedApp, EntitlementOverrides{})
		}
	}

	// Handle organization from state
	orgID := stateData.OrganizationID
	if orgID == "" {
		orgID = input.OrganizationID
	}

	// Handle invitation from state
	inviteCode := stateData.InviteCode
	if inviteCode == "" {
		inviteCode = input.InviteCode
	}

	// If there's an invite code, process it
	if inviteCode != "" {
		invitation, err := s.inviteRepo.GetByCode(ctx, inviteCode)
		if err == nil && invitation.IsValid() {
			// Create membership
			membership := domain.NewOrganizationMembership(user.ID, invitation.OrganizationID)
			membership.InvitedBy = &invitation.InvitedBy
			if err := s.orgRepo.AddMember(ctx, membership); err == nil {
				// Assign roles from invitation
				for _, roleID := range invitation.RoleIDs {
					roleAssign := domain.NewOrganizationMemberRole(membership.ID, roleID, invitation.InvitedBy)
					_ = s.orgRepo.AssignMemberRole(ctx, roleAssign)
				}
				invitation.Accept(user.ID)
				_ = s.inviteRepo.Update(ctx, invitation)

				orgID = invitation.OrganizationID.String()
			}
		}
	}

	// Update last login
	now := types.Now()
	user.LastLoginAt = &now
	_ = s.userRepo.Update(ctx, user)

	// Get roles and permissions
	var roles []*domain.Role
	var permissions []string
	var org *domain.Organization

	if orgID != "" {
		parsedOrgID, err := types.ParseID(orgID)
		if err == nil {
			org, err = s.orgRepo.GetByID(ctx, parsedOrgID)
			if err == nil && org.IsActive() {
				membership, err := s.orgRepo.GetMembership(ctx, user.ID, parsedOrgID)
				if err == nil && membership.IsActive() {
					roles, _ = s.orgRepo.GetMemberRoles(ctx, membership.ID)
				}
			}
		}
	}

	if len(roles) == 0 {
		roles, _ = s.userRepo.GetBaseRoles(ctx, user.ID)
	}

	// AUDIT 4.1: batched permission fetch.
	roleCodes := make([]string, len(roles))
	for i, role := range roles {
		roleCodes[i] = role.Code
	}
	permissions = s.collectPermissions(ctx, roles)

	// AUDIT C2: if the original /auth/sso/url request initiated PKCE, defer
	// token minting. The public client redeems {auth_code, code_verifier} at
	// /auth/sso/exchange. User-side effects (account create/link, invitation
	// acceptance, last_login update) have already happened above — the
	// auth_code is purely the token-issuance handoff. 60s is plenty for an
	// immediate redirect; over-long codes are an attack surface.
	if stateData.CodeChallenge != "" {
		authCode, ierr := s.ssoManager.IssueAuthCode(ctx, &sso.AuthCodeData{
			UserID:              user.ID.String(),
			Email:               string(user.Email),
			OrganizationID:      orgID,
			Provider:            userInfo.Provider,
			CodeChallenge:       stateData.CodeChallenge,
			CodeChallengeMethod: stateData.CodeChallengeMethod,
		}, 60*time.Second)
		if ierr != nil {
			return nil, errors.Internal("Failed to issue auth_code")
		}
		return &LoginResult{
			User:              user,
			Organization:      org,
			Roles:             roleCodes,
			Permissions:       permissions,
			AuthCode:          authCode,
			AuthCodeExpiresIn: 60,
		}, nil
	}

	// Generate tokens
	tokenInput := jwt.GenerateTokenInput{
		User:         user,
		Organization: org,
		Roles:        roles,
		Permissions:  permissions,
		DeviceInfo:   input.DeviceInfo,
		IPAddress:    input.IPAddress,
		UserAgent:    input.UserAgent,
	}

	tokenPair, err := s.jwtService.GenerateTokenPair(ctx, tokenInput)
	if err != nil {
		return nil, errors.Internal("Failed to generate tokens")
	}

	return &LoginResult{
		User:         user,
		Organization: org,
		TokenPair:    tokenPair,
		Roles:        roleCodes,
		Permissions:  permissions,
	}, nil
}

// SSOExchangeInput parameterizes /auth/sso/exchange. The verifier is the
// public client's PKCE secret; the auth_code is the one-shot issued by the
// PKCE branch of SSOLogin. Device/IP/UA mirror Login — they get stamped on
// the resulting refresh-token row for session listing.
type SSOExchangeInput struct {
	AuthCode     string
	CodeVerifier string
	DeviceInfo   string
	IPAddress    string
	UserAgent    string
}

// SSOExchange redeems a PKCE auth_code for an access/refresh token pair
// (AUDIT C2). Atomically consumes the auth_code, verifies the supplied
// verifier matches the stored challenge, and mints tokens against the
// current user/org/role state. Re-fetching state (rather than serializing
// it into the auth_code) keeps the auth_code small and means a permission
// or membership change between callback and exchange is reflected in the
// issued token.
func (s *AuthService) SSOExchange(ctx context.Context, input SSOExchangeInput) (*LoginResult, error) {
	data, err := s.ssoManager.ConsumeAuthCode(ctx, input.AuthCode)
	if err != nil {
		// Map NotFound (already consumed / expired / never issued) to the
		// generic invalid-grant error. Don't differentiate — the public
		// client can't usefully distinguish them.
		return nil, errors.New(errors.ErrCodeTokenInvalid, "invalid or expired auth_code", 400)
	}
	if err := sso.VerifyCodeVerifier(input.CodeVerifier, data.CodeChallenge, data.CodeChallengeMethod); err != nil {
		return nil, err
	}

	userID, err := types.ParseID(data.UserID)
	if err != nil {
		return nil, errors.Internal("invalid user_id in auth_code")
	}
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, errors.UserNotFound()
	}
	if user.Status == types.UserStatusSuspended {
		return nil, errors.UserSuspended()
	}
	if user.Status == types.UserStatusDeleted || user.IsDeleted() {
		return nil, errors.UserNotFound()
	}

	var roles []*domain.Role
	var org *domain.Organization
	if data.OrganizationID != "" {
		parsedOrgID, perr := types.ParseID(data.OrganizationID)
		if perr == nil {
			org, perr = s.orgRepo.GetByID(ctx, parsedOrgID)
			if perr == nil && org.IsActive() {
				membership, merr := s.orgRepo.GetMembership(ctx, user.ID, parsedOrgID)
				if merr == nil && membership.IsActive() {
					roles, _ = s.orgRepo.GetMemberRoles(ctx, membership.ID)
				}
			}
		}
	}
	if len(roles) == 0 {
		roles, _ = s.userRepo.GetBaseRoles(ctx, user.ID)
	}

	roleCodes := make([]string, len(roles))
	for i, role := range roles {
		roleCodes[i] = role.Code
	}
	permissions := s.collectPermissions(ctx, roles)

	tokenPair, err := s.jwtService.GenerateTokenPair(ctx, jwt.GenerateTokenInput{
		User:         user,
		Organization: org,
		Roles:        roles,
		Permissions:  permissions,
		DeviceInfo:   input.DeviceInfo,
		IPAddress:    input.IPAddress,
		UserAgent:    input.UserAgent,
	})
	if err != nil {
		return nil, errors.Internal("Failed to generate tokens")
	}

	return &LoginResult{
		User:         user,
		Organization: org,
		TokenPair:    tokenPair,
		Roles:        roleCodes,
		Permissions:  permissions,
	}, nil
}

// RefreshTokens refreshes the access token using a refresh token

type GetSSOAuthURLInput struct {
	Provider            types.AuthProvider
	RedirectURL         string
	OrganizationID      string
	InviteCode          string
	AppCode             string
	CodeChallenge       string
	CodeChallengeMethod string
}

// GetSSOAuthURL returns the SSO authorization URL. When CodeChallenge is set
// the resulting flow is PKCE-protected: the callback issues an auth_code
// instead of tokens, and the public client redeems via /auth/sso/exchange.
func (s *AuthService) GetSSOAuthURL(ctx context.Context, input GetSSOAuthURLInput) (string, string, error) {
	return s.ssoManager.GetAuthURL(ctx, sso.AuthURLInput{
		Provider:            input.Provider,
		RedirectURL:         input.RedirectURL,
		OrganizationID:      input.OrganizationID,
		InviteCode:          input.InviteCode,
		AppCode:             input.AppCode,
		CodeChallenge:       input.CodeChallenge,
		CodeChallengeMethod: input.CodeChallengeMethod,
	})
}

// GetUserSessions returns active sessions for a user

func (s *AuthService) GetEnabledSSOProviders() []sso.SSOProviderInfo {
	return s.ssoManager.GetProviderInfo()
}

// HardDeleteUserInput parameterizes the destructive user delete (AUDIT C8).
// Reason is recorded in the audit log alongside actor + target so a later
// reviewer has the "why" — soft-deletes can be reasoned about by looking
// at the row, but hard-deletes leave nothing in the user table.
