// Registration & email verification — new-user creation (with per-app
// policy, user pools, org association, webhooks) plus the email
// verification lifecycle. Split from auth_service.go (2026-06-11);
// shared state/helpers live there.
// Package service provides business logic services for the auth application
package auth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rw3iss/auth/internal/auth/jwt"
	"github.com/rw3iss/auth/internal/domain"
	"github.com/rw3iss/auth/internal/webhooks"
	"github.com/rw3iss/auth/pkg/shared/errors"
	"github.com/rw3iss/auth/pkg/shared/models"
	"github.com/rw3iss/auth/pkg/shared/types"
	"github.com/rw3iss/auth/pkg/shared/utils"
)

// AuthService handles authentication business logic

type RegistrationMode string

const (
	// ModeRegister (default) returns an "already exists" error when the
	// email is taken. Current behavior preserved for back-compat.
	ModeRegister RegistrationMode = "register"
	// ModeRegisterOrLogin tries register first; on email collision attempts
	// a login with the submitted password. Idempotent for client UX
	// (mobile apps with double-tap registration buttons). Mitigates the
	// timing side-channel by running a bcrypt comparison against a fixed
	// dummy hash on the register-path, so response time matches whichever
	// branch ran.
	ModeRegisterOrLogin RegistrationMode = "register_or_login"
	// ModeRegisterOrReturn returns the existing user object on collision
	// without attempting login. Gated to service-to-service callers only —
	// it trivially leaks user-existence and must never be exposed to
	// public clients. Use case: idempotent server-side provisioning where
	// the caller already trusts the email.
	ModeRegisterOrReturn RegistrationMode = "register_or_return"
)

// dummyBcryptHash is bcrypt("never-matches", cost=10) — used to spend the
// same CPU on the register-when-exists path as we would on a real login
// password compare, so the response time matches and email-existence can't
// be inferred from latency. AUDIT 8.1 timing-side-channel mitigation.

type RegisterInput struct {
	Email       string           `json:"email" validate:"required,email"`
	Password    string           `json:"password" validate:"required,min=8"`
	FirstName   string           `json:"first_name" validate:"required"`
	LastName    string           `json:"last_name" validate:"required"`
	Phone       string           `json:"phone,omitempty"`
	DisplayName string           `json:"display_name,omitempty"`
	Mode        RegistrationMode `json:"mode,omitempty"` // default: register

	// Optional organization context
	OrganizationName string `json:"organization_name,omitempty"` // Create new org
	InviteCode       string `json:"invite_code,omitempty"`       // Join existing org
	InviteToken      string `json:"invite_token,omitempty"`      // Join via email link

	// AppCode applies the app's registration policy (allowed email
	// domains, allowed auth methods) and triggers auto-assignment to
	// the app's `default_organization_id` when one is configured. The
	// usual app-context fallback (cfg.AUTH_DEFAULT_APP_CODE) applies
	// when this is empty — see migration 013 for the policy model.
	AppCode string `json:"app_code,omitempty"`

	// §7 per-request provisioning overrides (used when the app auto-grants).
	// RoleCode overrides the app's default_role_code for the default-org
	// membership (validated server-side as an org-scoped role).
	// LinkedAppCodes overrides the app's linked_app_codes (nil = app default).
	RoleCode       string   `json:"role_code,omitempty"`
	LinkedAppCodes []string `json:"linked_app_codes,omitempty"`

	// CallerIsService is set by the handler when the request authenticates
	// as a service (system_admin role today). Required for
	// ModeRegisterOrReturn. Not deserialized from the wire — the handler
	// sets it after auth.
	CallerIsService bool `json:"-"`

	// Raw is the registration request body as a generic map (password
	// already redacted by the handler). Carries any EXTRA fields the
	// client sent beyond the typed ones — passed through verbatim to
	// per-app webhooks (migration 019). Never deserialized from the
	// wire directly; the handler builds it.
	Raw map[string]any `json:"-"`
	// ClientIP / UserAgent — request metadata forwarded to webhooks.
	ClientIP  string `json:"-"`
	UserAgent string `json:"-"`
}

// RegisterResult contains the result of registration. When Mode is
// register_or_login and the email existed, LoggedIn is true and TokenPair
// is populated so the caller can treat the response as a login result.
type RegisterResult struct {
	User                  *domain.User         `json:"user"`
	Organization          *domain.Organization `json:"organization,omitempty"`
	VerificationEmailSent bool                 `json:"verification_email_sent"`
	LoggedIn              bool                 `json:"logged_in,omitempty"`
	TokenPair             *jwt.TokenPair       `json:"tokens,omitempty"`
}

// Register registers a new user
func (s *AuthService) Register(ctx context.Context, input RegisterInput) (*RegisterResult, error) {
	// Normalize email
	email := types.Email(utils.NormalizeEmail(input.Email))

	// Validate email format
	if !utils.IsValidEmail(string(email)) {
		return nil, errors.InvalidInput("email", "Invalid email format")
	}

	// AUDIT — migration 013: enforce per-app registration policy. Resolve
	// the target app (explicit input.AppCode, falling back to the server's
	// configured default) and check the allowed-email-domains list AND
	// that "password" is in the allowed-auth-methods list. The same App
	// row is reused below to drive the default-organization auto-assign,
	// so we keep the pointer.
	var registrationApp *domain.App
	if s.appService != nil {
		appCode := input.AppCode
		if appCode == "" {
			appCode = s.cfg.Auth.DefaultAppCode
		}
		if appCode != "" {
			app, err := s.appService.GetByCode(ctx, appCode)
			if err == nil && app != nil && app.IsActive() {
				if !app.IsEmailDomainAllowed(string(email)) {
					return nil, errors.InvalidInput("email",
						"This application restricts registration to specific email domains.")
				}
				if !app.IsAuthMethodAllowed("password") {
					return nil, errors.InvalidInput("password",
						"This application does not accept password registration.")
				}
				registrationApp = app
			}
		}
	}

	// Validate password
	pwResult := utils.ValidatePassword(input.Password, s.passwordPolicy())
	if !pwResult.IsValid {
		return nil, errors.ValidationError("Password does not meet requirements: " + pwResult.Errors[0])
	}

	// Validate required name fields
	if strings.TrimSpace(input.FirstName) == "" {
		return nil, errors.InvalidInput("first_name", "First name is required")
	}
	if strings.TrimSpace(input.LastName) == "" {
		return nil, errors.InvalidInput("last_name", "Last name is required")
	}

	// Migrations 017 + 018 — resolve the app's user pools. The model:
	// an app has ONE "default pool (registration)" plus N "other pools
	// (login)". New users get the default pool as their home namespace
	// (users.namespace) and are tagged (user_namespaces) into every
	// other pool the app uses, so they belong to the app's whole pool
	// set. Existing users are matched across that same set (home OR
	// tag), so an account already living in a usable pool is reused
	// rather than duplicated. Unconfigured apps use `default` only →
	// identical to pre-017.
	//
	// EffectiveReadNamespaces() returns [default pool, ...other pools]
	// in exactly that order — element 0 is the home pool.
	appPools := []string{domain.DefaultNamespace}
	if registrationApp != nil {
		appPools = registrationApp.EffectiveReadNamespaces()
	}
	readNamespaces := appPools

	// AUDIT 8.1: registration mode dispatch on email collision. Default
	// keeps the legacy "register-or-error" behavior; other modes are
	// opt-in.
	existing, err := s.userRepo.GetByEmailInNamespaces(ctx, email, readNamespaces)
	if err == nil {
		switch input.Mode {
		case ModeRegisterOrLogin:
			// Spend the same CPU on the register-path as a real login
			// password compare would, so response time doesn't leak
			// whether the email existed.
			_ = utils.CheckPassword(input.Password, dummyBcryptHash)
			return s.registerOrLogin(ctx, existing, input)
		case ModeRegisterOrReturn:
			if !input.CallerIsService {
				return nil, errors.Forbidden("register_or_return requires service-to-service authentication")
			}
			return &RegisterResult{User: existing}, nil
		default:
			return nil, errors.UserAlreadyExists(string(email))
		}
	}

	// Hash password
	passwordHash, err := s.hashPassword(input.Password)
	if err != nil {
		return nil, errors.Internal("Failed to hash password")
	}

	var result *RegisterResult
	var invitation *domain.Invitation

	// Check invitation if provided
	if input.InviteCode != "" {
		invitation, err = s.inviteRepo.GetByCode(ctx, input.InviteCode)
		if err != nil {
			return nil, errors.InviteNotFound()
		}
		if !invitation.IsValid() {
			if invitation.Status != domain.InvitationStatusPending {
				return nil, errors.InviteAlreadyUsed()
			}
			return nil, errors.InviteExpired()
		}
	} else if input.InviteToken != "" {
		invitation, err = s.inviteRepo.GetByToken(ctx, input.InviteToken)
		if err != nil {
			return nil, errors.InviteNotFound()
		}
		if !invitation.IsValid() {
			return nil, errors.InviteExpired()
		}
	}

	err = s.txManager.WithTransaction(ctx, func(ctx context.Context) error {
		// Create user in the app's DEFAULT pool (their home namespace);
		// tag them into the app's OTHER pools below.
		user := domain.NewUser(email, input.FirstName, input.LastName)
		user.Namespace = appPools[0]
		user.SetPassword(passwordHash)
		user.Phone = types.PhoneNumber(input.Phone)
		user.DisplayName = input.DisplayName
		user.AuthProvider = types.AuthProviderLocal

		if err := s.userRepo.Create(ctx, user); err != nil {
			return err
		}

		// Membership tags for the app's OTHER pools (everything beyond
		// the default pool already on the row). E.g. claimleo with
		// default pool `default` + other pools [wristleo, claimleo]:
		// the user lives in `default` (any default-reading app picks
		// them up) and is tagged into the app's other pools.
		if len(appPools) > 1 {
			if err := s.userRepo.AddUserToNamespaces(ctx, user.ID, appPools[1:]); err != nil {
				return err
			}
		}

		// Assign base user role
		baseRole, err := s.roleRepo.GetByCode(ctx, string(models.RoleBaseUser))
		if err != nil {
			return fmt.Errorf("failed to get base user role: %w", err)
		}

		roleAssignment := domain.NewUserBaseRole(user.ID, baseRole.ID, nil)
		if err := s.userRepo.AssignBaseRole(ctx, roleAssignment); err != nil {
			return err
		}

		result = &RegisterResult{
			User: user,
		}

		// Handle organization association
		var org *domain.Organization

		if invitation != nil {
			// Join organization via invitation
			org, err = s.orgRepo.GetByID(ctx, invitation.OrganizationID)
			if err != nil {
				return err
			}

			// Create membership
			membership := domain.NewOrganizationMembership(user.ID, org.ID)
			membership.InvitedBy = &invitation.InvitedBy
			if err := s.orgRepo.AddMember(ctx, membership); err != nil {
				return err
			}

			// Assign roles from invitation
			for _, roleID := range invitation.RoleIDs {
				roleAssign := domain.NewOrganizationMemberRole(membership.ID, roleID, invitation.InvitedBy)
				if err := s.orgRepo.AssignMemberRole(ctx, roleAssign); err != nil {
					return err
				}
			}

			// Mark invitation as accepted
			invitation.Accept(user.ID)
			if err := s.inviteRepo.Update(ctx, invitation); err != nil {
				return err
			}

			result.Organization = org

		} else if input.OrganizationName != "" {
			// Create new organization
			slug := utils.Slugify(input.OrganizationName)
			org = domain.NewOrganization(input.OrganizationName, slug, user.ID)

			if err := s.orgRepo.Create(ctx, org); err != nil {
				return err
			}

			// Create membership as owner
			membership := domain.NewOrganizationMembership(user.ID, org.ID)
			if err := s.orgRepo.AddMember(ctx, membership); err != nil {
				return err
			}

			// Assign org admin role
			adminRole, err := s.roleRepo.GetByCode(ctx, string(models.RoleOrgAdmin))
			if err != nil {
				return fmt.Errorf("failed to get org admin role: %w", err)
			}

			roleAssign := domain.NewOrganizationMemberRole(membership.ID, adminRole.ID, user.ID)
			if err := s.orgRepo.AssignMemberRole(ctx, roleAssign); err != nil {
				return err
			}

			result.Organization = org

		} else if registrationApp != nil && registrationApp.AutoGrantOnSignup {
			// §7: full app provisioning at registration time — grant the app
			// (and any linked-app) user_apps membership AND the default-org
			// role (default_role_code, override-able per request). Idempotent +
			// best-effort. Replaces the prior hardcoded `org_member`-only path.
			s.ensureAppEntitlements(ctx, user, registrationApp, EntitlementOverrides{
				RoleCode:          input.RoleCode,
				LinkedAppCodes:    input.LinkedAppCodes,
				LinkedAppCodesSet: input.LinkedAppCodes != nil,
			})
			if registrationApp.DefaultOrganizationID != nil {
				if defaultOrg, err := s.orgRepo.GetByID(ctx, *registrationApp.DefaultOrganizationID); err == nil && defaultOrg != nil {
					result.Organization = defaultOrg
				}
			}
		} else if registrationApp != nil && registrationApp.DefaultOrganizationID != nil {
			// Backward-compat (auto_grant_on_signup=false): migration-013
			// default-org auto-add as `org_member` only — no app grant.
			defaultOrg, err := s.orgRepo.GetByID(ctx, *registrationApp.DefaultOrganizationID)
			if err == nil && defaultOrg != nil {
				membership := domain.NewOrganizationMembership(user.ID, defaultOrg.ID)
				if err := s.orgRepo.AddMember(ctx, membership); err != nil {
					return fmt.Errorf("default-org auto-add: create membership: %w", err)
				}
				memberRole, err := s.roleRepo.GetByCode(ctx, string(models.RoleOrgMember))
				if err == nil && memberRole != nil {
					// AssignedBy is the user themselves — auto-assignment via app
					// policy has no acting admin. Keeps audit trails self-consistent.
					roleAssign := domain.NewOrganizationMemberRole(membership.ID, memberRole.ID, user.ID)
					if err := s.orgRepo.AssignMemberRole(ctx, roleAssign); err != nil {
						return fmt.Errorf("default-org auto-add: assign role: %w", err)
					}
				}
				result.Organization = defaultOrg
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	// Per-app webhooks (migration 019) — fan user.registered out to any
	// enabled hooks on the registering app. Async + best-effort; never
	// blocks or fails the registration.
	s.dispatchRegistrationWebhooks(registrationApp, result, input, appPools)

	// Send verification email
	if s.emailService != nil {
		token, err := s.jwtService.GenerateEmailVerificationToken(ctx, result.User, s.cfg.Auth.EmailVerificationExpiry)
		if err == nil {
			// Link target is the registering app's frontend so the
			// verify page lives in the same UI the user just signed
			// up in. Empty when the app row carries no frontend_url
			// — email layer falls back to CLIENT_URL.
			appBase := registrationApp.FrontendBaseURL()
			err = s.emailService.SendVerificationEmail(ctx, appBase, string(result.User.Email), result.User.FirstName, token, result.User.ColorMode())
			if err == nil {
				result.VerificationEmailSent = true
			}
		}
	}

	return result, nil
}

// dispatchRegistrationWebhooks builds the user.registered event envelope
// and fans it out to the app's enabled webhooks. No-ops when the app is
// nil or has no matching hooks. See internal/webhooks/app_webhooks.go.
func (s *AuthService) dispatchRegistrationWebhooks(app *domain.App, result *RegisterResult, input RegisterInput, appPools []string) {
	if app == nil || result == nil || result.User == nil || len(app.WebhooksFor(domain.WebhookEventUserRegistered)) == 0 {
		return
	}
	var event webhooks.RegistrationEvent
	event.Event = domain.WebhookEventUserRegistered
	event.Timestamp = time.Now().UTC().Format(time.RFC3339)
	event.App.ID = app.ID.String()
	event.App.Code = app.Code
	event.App.Name = app.Name
	event.User.ID = result.User.ID.String()
	event.User.Email = string(result.User.Email)
	event.User.FirstName = result.User.FirstName
	event.User.LastName = result.User.LastName
	event.User.DisplayName = result.User.DisplayName
	event.User.Namespace = result.User.Namespace
	event.User.Pools = appPools
	if result.Organization != nil {
		event.Organization = &struct {
			ID   string `json:"id"`
			Slug string `json:"slug"`
			Name string `json:"name"`
		}{
			ID:   result.Organization.ID.String(),
			Slug: result.Organization.Slug,
			Name: result.Organization.Name,
		}
	}
	// The raw request body (password redacted at the handler) — includes
	// any extra fields the client sent. Fallback: reconstruct from the
	// typed input when the handler didn't supply Raw (e.g. SSO paths).
	if input.Raw != nil {
		event.Registration = input.Raw
	} else {
		event.Registration = map[string]any{
			"email":      input.Email,
			"first_name": input.FirstName,
			"last_name":  input.LastName,
		}
		if input.Phone != "" {
			event.Registration["phone"] = input.Phone
		}
		if input.DisplayName != "" {
			event.Registration["display_name"] = input.DisplayName
		}
		if input.AppCode != "" {
			event.Registration["app_code"] = input.AppCode
		}
	}
	event.Context.IP = input.ClientIP
	event.Context.UserAgent = input.UserAgent
	event.Context.Server = s.cfg.JWT.Issuer
	webhooks.DispatchRegistration(app, event)
}

// LoginInput contains input for user login

func (s *AuthService) ResendVerificationEmail(ctx context.Context, email, appCode string) error {
	normalizedEmail := types.Email(utils.NormalizeEmail(email))

	// Resolve within the app's read pools (migration 017).
	user, err := s.userRepo.GetByEmailInNamespaces(ctx, normalizedEmail, s.resolveReadNamespaces(ctx, appCode))
	if err != nil {
		return nil // never reveal email existence
	}
	if user.EmailVerified {
		// Already verified — nothing to do. Don't surface to the caller
		// (information leak: confirms account exists + state).
		return nil
	}
	if user.Status == types.UserStatusSuspended ||
		user.Status == types.UserStatusDeleted ||
		user.IsDeleted() {
		return nil
	}
	if s.emailService == nil {
		// Email is unconfigured. No surface to verify through — the
		// admin path (set-email-verified manually) is the only recourse.
		return nil
	}

	token, err := s.jwtService.GenerateEmailVerificationToken(ctx, user, s.cfg.Auth.EmailVerificationExpiry)
	if err != nil {
		return errors.Internal("Failed to generate verification token")
	}
	return s.emailService.SendVerificationEmail(ctx, s.resolveAppBaseURL(ctx, appCode), string(user.Email), user.FirstName, token, user.ColorMode())
}

// RequestPasswordReset initiates a password reset.
//
// appCode is the calling app's identifier. When present and resolvable,
// the reset link points at that app's frontend_url; otherwise the
// email layer falls back to CLIENT_URL.

func (s *AuthService) VerifyEmail(ctx context.Context, token string) error {
	claims, err := s.jwtService.ValidateEmailVerificationToken(ctx, token)
	if err != nil {
		return err
	}

	tokenID, err := types.ParseID(claims.ID)
	if err != nil {
		return errors.TokenInvalid()
	}

	user, err := s.userRepo.GetByID(ctx, claims.UserID)
	if err != nil {
		return err
	}

	return s.txManager.WithTransaction(ctx, func(ctx context.Context) error {
		stored, err := s.tokenRepo.GetEmailVerificationTokenByID(ctx, tokenID)
		if err != nil {
			return errors.TokenInvalid()
		}
		if stored.Used {
			return errors.TokenInvalid()
		}
		if stored.UserID != claims.UserID {
			return errors.TokenInvalid()
		}

		user.EmailVerified = true
		if user.Status == types.UserStatusPending {
			user.Status = types.UserStatusActive
		}

		if err := s.userRepo.Update(ctx, user); err != nil {
			return err
		}
		return s.tokenRepo.MarkEmailVerificationTokenUsed(ctx, tokenID)
	})
}

// ChangePassword changes a user's password

func (s *AuthService) registerOrLogin(ctx context.Context, existing *domain.User, input RegisterInput) (*RegisterResult, error) {
	loginResult, err := s.Login(ctx, LoginInput{
		Email:    input.Email,
		Password: input.Password,
		// Forward the app context so register_or_login honors the same
		// app scoping (and, via migration 017, the same read namespaces)
		// as a direct login. Without this, an existing user entering a
		// new app through register_or_login hit "app_code is required".
		AppCode: input.AppCode,
	})
	if err != nil {
		// Failed login → match the response shape of an ordinary bad-password
		// attempt. Don't reveal that the email existed.
		return nil, err
	}
	return &RegisterResult{
		User:      loginResult.User,
		LoggedIn:  true,
		TokenPair: loginResult.TokenPair,
	}, nil
}

// LoginInput is the input for the Login method, declared here so
// registerOrLogin can reach it. The actual Login struct definition is
// below; this is just a forward declaration via type alias if Go required
// it. (It doesn't — Login(...) lives in the same file. Keep this comment
// as a navigation hint.)

// tryMigrateFromLegacy is invoked from Login when the email isn't found in
// the internal store and a legacy auth provider is configured. Returns a
// freshly-created internal User on success, or an error indicating the
// legacy lookup also failed (treated by the caller as "user doesn't exist
// anywhere" without leaking which branch broke).
//
// On success:
//   - The submitted password is hashed with bcrypt at the configured cost
//     and stored on the new user row. The plaintext never persists.
//   - Legacy roles are translated via the configured RoleMapper, which
//     enforces "never auto-grant system_admin" (see RoleMapper contract).
//   - The user is marked email_verified=true if the legacy system said so,
//     since that system was the prior source of truth.
//   - An audit event is recorded so operators see who migrated and when.
