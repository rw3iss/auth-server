// Package domain contains the domain models for the auth service
package domain

import (
	"github.com/ven/auth/pkg/shared/models"
	"github.com/ven/auth/pkg/shared/types"
)

// DefaultNamespace is the home user pool for any user without an
// explicit one. Migration 017 / docs/USER_POOLS.md.
const DefaultNamespace = "default"

// User extends BaseUser with authentication-specific fields
type User struct {
	models.BaseUser

	// Namespace is the user's home pool (migration 017). Defaults to
	// DefaultNamespace. Email is unique per (namespace, email), so the
	// same address can be a distinct identity in two pools. See
	// docs/USER_POOLS.md.
	Namespace string `json:"namespace" db:"namespace"`

	// Authentication fields (internal to auth service)
	PasswordHash     string              `json:"-" db:"password_hash"`
	AuthProvider     types.AuthProvider  `json:"auth_provider" db:"auth_provider"`
	ProviderUserID   string              `json:"-" db:"provider_user_id"`
	TwoFactorEnabled     bool             `json:"two_factor_enabled" db:"two_factor_enabled"`
	TwoFactorSecret      string           `json:"-" db:"two_factor_secret"`
	TwoFactorConfirmedAt *types.Timestamp `json:"two_factor_confirmed_at,omitempty" db:"two_factor_confirmed_at"`

	// Security fields
	FailedLoginAttempts int              `json:"-" db:"failed_login_attempts"`
	LockedUntil         *types.Timestamp `json:"-" db:"locked_until"`
	LastPasswordChange  *types.Timestamp `json:"-" db:"last_password_change"`

	// Associations (loaded separately)
	Organizations []OrganizationMembership `json:"organizations,omitempty" db:"-"`
	BaseRole      *Role                    `json:"base_role,omitempty" db:"-"`
}

// NewUser creates a new User with default values
func NewUser(email types.Email, firstName, lastName string) *User {
	return &User{
		BaseUser: models.BaseUser{
			BaseModel:     models.NewBaseModel(),
			Email:         email,
			FirstName:     firstName,
			LastName:      lastName,
			Status:        types.UserStatusPending,
			EmailVerified: false,
		},
		Namespace:    DefaultNamespace,
		AuthProvider: types.AuthProviderLocal,
	}
}

// IsTwoFactorActive reports whether 2FA is enrolled AND confirmed for this
// user. Setup writes the secret + flags Enabled=true, but the user has to
// submit one valid code (Enable) before ConfirmedAt is populated. Until
// then, login does NOT require the second factor — otherwise a half-finished
// enrollment would lock the user out. AUDIT C4.
func (u *User) IsTwoFactorActive() bool {
	return u.TwoFactorEnabled && u.TwoFactorConfirmedAt != nil && u.TwoFactorSecret != ""
}

// IsLocked checks if the user account is locked
func (u *User) IsLocked() bool {
	if u.LockedUntil == nil {
		return false
	}
	return types.Now().Before(*u.LockedUntil)
}

// IncrementFailedLogin increments the failed login counter
func (u *User) IncrementFailedLogin(maxAttempts int, lockDuration types.Duration) {
	u.FailedLoginAttempts++
	if u.FailedLoginAttempts >= maxAttempts {
		lockUntil := types.Now().Add(lockDuration)
		u.LockedUntil = &lockUntil
	}
}

// ResetFailedLogin resets the failed login counter
func (u *User) ResetFailedLogin() {
	u.FailedLoginAttempts = 0
	u.LockedUntil = nil
}

// SetPassword sets the password hash for the user
func (u *User) SetPassword(hash string) {
	u.PasswordHash = hash
	now := types.Now()
	u.LastPasswordChange = &now
}

// Activate activates the user account
func (u *User) Activate() {
	u.Status = types.UserStatusActive
	u.EmailVerified = true
}

// Suspend suspends the user account
func (u *User) Suspend() {
	u.Status = types.UserStatusSuspended
}

// UserAuthProvider represents a linked authentication provider for a user
type UserAuthProvider struct {
	models.BaseModel

	UserID         types.ID            `json:"user_id" db:"user_id"`
	Provider       types.AuthProvider  `json:"provider" db:"provider"`
	ProviderUserID string              `json:"provider_user_id" db:"provider_user_id"`
	AccessToken    string              `json:"-" db:"access_token"`
	RefreshToken   string              `json:"-" db:"refresh_token"`
	TokenExpiry    *types.Timestamp    `json:"-" db:"token_expiry"`
	ProviderData   types.JSON          `json:"-" db:"provider_data"`
}

// NewUserAuthProvider creates a new authentication provider link
func NewUserAuthProvider(userID types.ID, provider types.AuthProvider, providerUserID string) *UserAuthProvider {
	return &UserAuthProvider{
		BaseModel:      models.NewBaseModel(),
		UserID:         userID,
		Provider:       provider,
		ProviderUserID: providerUserID,
	}
}
