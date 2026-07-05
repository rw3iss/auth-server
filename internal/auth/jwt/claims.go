// Package jwt provides JWT token management for the auth service
package jwt

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/ven/auth/pkg/shared/types"
)

// TokenClaims represents the claims in a JWT token
type TokenClaims struct {
	jwt.RegisteredClaims

	// User information
	UserID      types.ID `json:"uid"`
	Email       string   `json:"email"`
	FirstName   string   `json:"first_name,omitempty"`
	LastName    string   `json:"last_name,omitempty"`
	DisplayName string   `json:"display_name,omitempty"`

	// Organization context (nil if logged in without organization)
	OrganizationID   *types.ID `json:"org_id,omitempty"`
	OrganizationSlug string    `json:"org_slug,omitempty"`
	OrganizationName string    `json:"org_name,omitempty"`

	// Role and permission information
	Roles       []string `json:"roles"`       // Role codes
	Permissions []string `json:"permissions"` // Permission codes

	// Token metadata
	TokenType    types.TokenType `json:"token_type"`
	SessionID    *types.ID       `json:"session_id,omitempty"`
	RememberMe   bool            `json:"remember_me,omitempty"`
	AuthProvider string          `json:"auth_provider,omitempty"`

	// TokenVersion is the per-user token-version counter captured at issue
	// time. Validators reject tokens whose stored version is below the
	// current per-user version. Combined with BumpUserTokenVersion on
	// logout-all / role-change, this gives immediate cross-replica
	// invalidation of every outstanding access token without per-jti
	// blacklist writes — AUDIT 1.10 and 3.4.
	TokenVersion int64 `json:"tv,omitempty"`

	// AppID + AppCode scope the token to a registered consuming app
	// (AUDIT 8.3, docs/APP_REGISTRATION.md). Downstream services validate
	// claims.AppCode == self.AppCode so a token minted for app A can
	// never be accepted by app B. Nil when AUTH_ALLOW_BASE_USER_LOGIN
	// is set and the login carried no app_code — the base-user mode for
	// tracking/form contexts.
	AppID   *types.ID `json:"app_id,omitempty"`
	AppCode string    `json:"app_code,omitempty"`

	// Namespace is the user's home pool (migration 017 /
	// docs/USER_POOLS.md). Lets downstream services + the client see
	// which pool the identity belongs to. Omitted for the `default`
	// pool to keep the common-case token small.
	Namespace string `json:"namespace,omitempty"`

	// ImpersonatorUserID is set when an admin is acting as another user via
	// `/admin/users/{userId}/impersonate` (AUDIT C7). The token's `sub` /
	// `uid` are the TARGET user — downstream authz sees them as the target.
	// The impersonator-id is purely audit-trail metadata, surfaced in every
	// audit event emitted under this session. ImpersonatorEmail is included
	// alongside for log readability.
	//
	// Critical: an impersonation token MUST NOT itself initiate another
	// impersonation. The /impersonate handler rejects when the actor's token
	// already carries ImpersonatorUserID, preventing chaining.
	ImpersonatorUserID *types.ID `json:"imp_uid,omitempty"`
	ImpersonatorEmail  string    `json:"imp_email,omitempty"`

	// Service-principal fields. Populated when this token was issued via
	// the OAuth2 client_credentials grant (POST /oauth/token) — see
	// service.M2MService.IssueToken. When ClientID is non-empty, the
	// TokenType is types.TokenTypeService and the user-shaped fields
	// (UserID, Email, Roles) are zero values; consumers should branch on
	// IsServicePrincipal() rather than treat the principal uniformly.
	//
	// The NestJS adapter's TokenValidatorService (auth-server-client
	// services/token-validator.service.ts:68) already keys on
	// token_type === 'service' to emit a ServicePrincipal — these fields
	// are what populate that shape.
	//
	// ClientID is the operator-chosen identifier (e.g. "rm-prod-abc123").
	// ServiceName is an optional friendly label for logs / dashboards.
	// Scopes is the granted scope slice (intersection of the client's
	// configured scopes and any `scope` parameter on the grant request).
	ClientID    string   `json:"client_id,omitempty"`
	ServiceName string   `json:"service_name,omitempty"`
	Scopes      []string `json:"scopes,omitempty"`
}

// IsServicePrincipal reports whether this token was minted via the
// client_credentials grant. Discriminator for the user/service union —
// downstream authz code should branch on this rather than inspect
// UserID directly, which is the zero value for service tokens.
func (c *TokenClaims) IsServicePrincipal() bool {
	return c.TokenType == types.TokenTypeService || c.ClientID != ""
}

// IsImpersonating reports whether this token was minted by an admin acting
// as another user (AUDIT C7). Downstream services that want to refuse
// destructive operations under impersonation (e.g. account-delete,
// password-change) gate on this flag.
func (c *TokenClaims) IsImpersonating() bool {
	return c.ImpersonatorUserID != nil
}

// HasRole checks if the token has a specific role
func (c *TokenClaims) HasRole(roleCode string) bool {
	for _, r := range c.Roles {
		if r == roleCode {
			return true
		}
	}
	return false
}

// HasAnyRole checks if the token has any of the specified roles
func (c *TokenClaims) HasAnyRole(roleCodes ...string) bool {
	for _, code := range roleCodes {
		if c.HasRole(code) {
			return true
		}
	}
	return false
}

// HasAllRoles checks if the token has all specified roles
func (c *TokenClaims) HasAllRoles(roleCodes ...string) bool {
	for _, code := range roleCodes {
		if !c.HasRole(code) {
			return false
		}
	}
	return true
}

// HasPermission checks if the token has a specific permission
func (c *TokenClaims) HasPermission(permissionCode string) bool {
	for _, p := range c.Permissions {
		if p == permissionCode {
			return true
		}
	}
	return false
}

// HasAnyPermission checks if the token has any of the specified permissions
func (c *TokenClaims) HasAnyPermission(permissionCodes ...string) bool {
	for _, code := range permissionCodes {
		if c.HasPermission(code) {
			return true
		}
	}
	return false
}

// HasAllPermissions checks if the token has all specified permissions
func (c *TokenClaims) HasAllPermissions(permissionCodes ...string) bool {
	for _, code := range permissionCodes {
		if !c.HasPermission(code) {
			return false
		}
	}
	return true
}

// IsOrgContext checks if the token has organization context
func (c *TokenClaims) IsOrgContext() bool {
	return c.OrganizationID != nil
}

// IsSystemAdmin checks if the token represents a system admin
func (c *TokenClaims) IsSystemAdmin() bool {
	return c.HasRole("system_admin")
}

// IsOrgAdmin checks if the token represents an organization admin
func (c *TokenClaims) IsOrgAdmin() bool {
	return c.IsOrgContext() && c.HasRole("org_admin")
}

// RefreshTokenClaims represents claims for refresh tokens
type RefreshTokenClaims struct {
	jwt.RegisteredClaims

	UserID         types.ID  `json:"uid"`
	OrganizationID *types.ID `json:"org_id,omitempty"`
	TokenID        types.ID  `json:"tid"` // Reference to stored token
	RememberMe     bool      `json:"remember_me,omitempty"`
	// AppCode carries the app the session was scoped to so /auth/refresh can
	// re-mint an access token with the same app_id/app_code claims — otherwise
	// refresh silently drops app scope. Empty = base-user / no app context.
	AppCode string `json:"app_code,omitempty"`
}

// Token purpose constants. AUDIT 1.6/1.7: every non-session JWT carries an
// explicit `purpose` claim so a leaked password-reset token can never be
// presented as an access/verify token even if (somehow) signed with a shared
// secret. Validators check this claim alongside signature, audience, and
// issuer.
const (
	PurposePasswordReset     = "password_reset"
	PurposeEmailVerification = "email_verification"
)

// PasswordResetClaims represents claims for password reset tokens
type PasswordResetClaims struct {
	jwt.RegisteredClaims

	UserID  types.ID `json:"uid"`
	Email   string   `json:"email"`
	Purpose string   `json:"purpose"`
}

// EmailVerificationClaims represents claims for email verification tokens
type EmailVerificationClaims struct {
	jwt.RegisteredClaims

	UserID  types.ID `json:"uid"`
	Email   string   `json:"email"`
	Purpose string   `json:"purpose"`
}

// InvitationClaims represents claims for invitation tokens
type InvitationClaims struct {
	jwt.RegisteredClaims

	InvitationID   types.ID `json:"invite_id"`
	OrganizationID types.ID `json:"org_id"`
	Email          string   `json:"email"`
}
