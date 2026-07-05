package dto

import (
	"github.com/ven/auth/internal/domain"
)

// UserResponse represents a user in API responses
type UserResponse struct {
	ID              string `json:"id"`
	Email           string `json:"email"`
	EmailVerified   bool   `json:"email_verified"`
	Phone           string `json:"phone,omitempty"`
	PhoneVerified   bool   `json:"phone_verified,omitempty"`
	FirstName       string `json:"first_name"`
	LastName        string `json:"last_name"`
	DisplayName     string `json:"display_name,omitempty"`
	AvatarURL       string `json:"avatar_url,omitempty"`
	Status          string `json:"status"`
	AuthProvider    string `json:"auth_provider"`
	TwoFactorEnabled bool  `json:"two_factor_enabled"`
	LastLoginAt     string `json:"last_login_at,omitempty"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
	// Base roles assigned to this user. Populated by /admin/users
	// (list + search); omitted on endpoints that don't aggregate them
	// (e.g. /auth/me uses a separate roles claim path). nil vs empty
	// slice carries meaning — nil = "not populated", [] = "no roles".
	Roles           []UserRoleSummary `json:"roles,omitempty"`
}

// UserRoleSummary is the slim role shape inlined on user list
// responses. Mirrors auth-shared's LookupUserRecord.UserRoleSummary.
type UserRoleSummary struct {
	Code string `json:"code"`
	Name string `json:"name"`
}

// ToUserResponse converts a domain user to response
func ToUserResponse(user *domain.User) *UserResponse {
	resp := &UserResponse{
		ID:               user.ID.String(),
		Email:            string(user.Email),
		EmailVerified:    user.EmailVerified,
		Phone:            string(user.Phone),
		PhoneVerified:    user.PhoneVerified,
		FirstName:        user.FirstName,
		LastName:         user.LastName,
		DisplayName:      user.DisplayName,
		AvatarURL:        user.AvatarURL,
		Status:           string(user.Status),
		AuthProvider:     string(user.AuthProvider),
		TwoFactorEnabled: user.TwoFactorEnabled,
		CreatedAt:        user.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:        user.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	if user.LastLoginAt != nil {
		resp.LastLoginAt = user.LastLoginAt.Format("2006-01-02T15:04:05Z07:00")
	}

	return resp
}

// UpdateUserRequest represents a user update request
type UpdateUserRequest struct {
	FirstName   *string `json:"first_name,omitempty"`
	LastName    *string `json:"last_name,omitempty"`
	DisplayName *string `json:"display_name,omitempty"`
	Phone       *string `json:"phone,omitempty"`
	AvatarURL   *string `json:"avatar_url,omitempty"`
}

// ListUsersRequest represents a request to list users
type ListUsersRequest struct {
	Status         string `query:"status"`
	EmailVerified  *bool  `query:"email_verified"`
	AuthProvider   string `query:"auth_provider"`
	OrganizationID string `query:"organization_id"`
	Page           int    `query:"page"`
	PageSize       int    `query:"page_size"`
	SortBy         string `query:"sort_by"`
	SortOrder      string `query:"sort_order"`
}

// ListUsersResponse represents the response for listing users
type ListUsersResponse struct {
	Users      []*UserResponse  `json:"users"`
	Pagination PaginationResponse `json:"pagination"`
}

// PaginationResponse represents pagination info in responses
type PaginationResponse struct {
	Page     int `json:"page"`
	PageSize int `json:"page_size"`
	Total    int `json:"total"`
}

// SearchUsersRequest represents a user search request
type SearchUsersRequest struct {
	Query    string `query:"q" validate:"required"`
	Page     int    `query:"page"`
	PageSize int    `query:"page_size"`
}

// UserAuthProviderResponse represents a linked auth provider
type UserAuthProviderResponse struct {
	Provider   string `json:"provider"`
	LinkedAt   string `json:"linked_at"`
}

// ToUserAuthProviderResponse converts a domain auth provider to response
func ToUserAuthProviderResponse(provider *domain.UserAuthProvider) *UserAuthProviderResponse {
	return &UserAuthProviderResponse{
		Provider: string(provider.Provider),
		LinkedAt: provider.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
}
