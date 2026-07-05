package models

import (
	"github.com/rw3iss/auth/pkg/shared/types"
)

// BaseUser represents the core user information shared across the platform
// This is the foundational user that can belong to multiple organizations
type BaseUser struct {
	BaseModel
	SoftDeletable

	Email           types.Email      `json:"email" db:"email"`
	EmailVerified   bool             `json:"email_verified" db:"email_verified"`
	Phone           types.PhoneNumber `json:"phone,omitempty" db:"phone"`
	PhoneVerified   bool             `json:"phone_verified" db:"phone_verified"`
	FirstName       string           `json:"first_name" db:"first_name"`
	LastName        string           `json:"last_name" db:"last_name"`
	DisplayName     string           `json:"display_name,omitempty" db:"display_name"`
	AvatarURL       string           `json:"avatar_url,omitempty" db:"avatar_url"`
	Status          types.UserStatus `json:"status" db:"status"`
	LastLoginAt     *types.Timestamp `json:"last_login_at,omitempty" db:"last_login_at"`
	PasswordResetAt *types.Timestamp `json:"password_reset_at,omitempty" db:"password_reset_at"`

	// Metadata for extensibility
	Metadata types.JSON `json:"metadata,omitempty" db:"metadata"`
}

// FullName returns the user's full name
func (u *BaseUser) FullName() string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	return u.FirstName + " " + u.LastName
}

// IsActive checks if the user account is active
func (u *BaseUser) IsActive() bool {
	return u.Status == types.UserStatusActive && !u.IsDeleted()
}

// CanLogin checks if the user can log in
func (u *BaseUser) CanLogin() bool {
	return u.IsActive() && u.EmailVerified
}

// BaseUserSummary provides a minimal view of user data for listings
type BaseUserSummary struct {
	ID          types.ID         `json:"id"`
	Email       types.Email      `json:"email"`
	FirstName   string           `json:"first_name"`
	LastName    string           `json:"last_name"`
	DisplayName string           `json:"display_name,omitempty"`
	AvatarURL   string           `json:"avatar_url,omitempty"`
	Status      types.UserStatus `json:"status"`
}

// ToSummary converts a BaseUser to BaseUserSummary
func (u *BaseUser) ToSummary() BaseUserSummary {
	return BaseUserSummary{
		ID:          u.ID,
		Email:       u.Email,
		FirstName:   u.FirstName,
		LastName:    u.LastName,
		DisplayName: u.DisplayName,
		AvatarURL:   u.AvatarURL,
		Status:      u.Status,
	}
}
