// Package sso provides SSO authentication provider implementations
package sso

import (
	"context"

	"github.com/rw3iss/auth/pkg/shared/types"
)

// UserInfo represents user information from an SSO provider
type UserInfo struct {
	ProviderUserID string
	Email          string
	EmailVerified  bool
	FirstName      string
	LastName       string
	DisplayName    string
	AvatarURL      string
	Provider       types.AuthProvider
	RawData        map[string]interface{}
}

// Provider defines the interface for SSO providers
type Provider interface {
	// GetAuthURL returns the URL to redirect users for authentication
	GetAuthURL(state string, redirectURL string) string

	// ExchangeCode exchanges an authorization code for tokens
	ExchangeCode(ctx context.Context, code string, redirectURL string) (*TokenResponse, error)

	// GetUserInfo retrieves user information using an access token
	GetUserInfo(ctx context.Context, accessToken string) (*UserInfo, error)

	// ValidateIDToken validates and parses an ID token (for providers that use OIDC)
	ValidateIDToken(ctx context.Context, idToken string) (*UserInfo, error)

	// RefreshToken refreshes the access token using a refresh token
	RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error)

	// GetProviderName returns the provider name
	GetProviderName() types.AuthProvider

	// IsEnabled returns whether the provider is enabled
	IsEnabled() bool
}

// TokenResponse represents the response from token exchange
type TokenResponse struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	TokenType    string
	ExpiresIn    int
	Scope        string
}

// OAuthConfig represents OAuth2 configuration
type OAuthConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	AuthURL      string
	TokenURL     string
	UserInfoURL  string
}
