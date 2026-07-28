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

// ProviderPKCE is an OPTIONAL capability implemented by providers that require
// their OWN PKCE (RFC 7636) verifier on the auth-server↔provider token-exchange
// leg — distinct from the client↔auth-server PKCE the manager already runs
// (StateData.CodeChallenge). X/Twitter mandates PKCE even for confidential
// clients, but the base Provider interface's GetAuthURL/ExchangeCode carry no
// verifier and ExchangeCode never sees `state`, so it can't recover a
// state-keyed secret on its own.
//
// The manager owns the (Redis-backed) state record, so IT generates the
// verifier, persists it in StateData.ProviderVerifier, embeds the derived
// S256 challenge on the authorize URL via BuildAuthURLWithPKCE, and hands the
// verifier back at callback time via ExchangeCodeWithVerifier. Keeping the
// verifier in state (not a provider-local map) makes the flow multi-replica
// safe: GetAuthURL and the callback may land on different replicas.
type ProviderPKCE interface {
	// BuildAuthURLWithPKCE returns the authorize URL carrying code_challenge
	// (S256) alongside state + redirect_uri.
	BuildAuthURLWithPKCE(state, redirectURL, codeChallenge string) string
	// ExchangeCodeWithVerifier exchanges the authorization code, including the
	// PKCE code_verifier (and, for confidential clients, HTTP Basic auth).
	ExchangeCodeWithVerifier(ctx context.Context, code, redirectURL, codeVerifier string) (*TokenResponse, error)
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
