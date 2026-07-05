package sso

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/ven/auth/internal/config"
	"github.com/ven/auth/pkg/shared/errors"
	"github.com/ven/auth/pkg/shared/types"
)

// CustomProvider implements the Provider interface for custom OAuth providers
type CustomProvider struct {
	name      string
	config    config.OAuthProviderConfig
	client    *http.Client
	userMapping UserFieldMapping
}

// UserFieldMapping defines how to map user fields from the provider's response
type UserFieldMapping struct {
	IDField           string // JSON path to user ID
	EmailField        string // JSON path to email
	EmailVerifiedField string // JSON path to email verified
	FirstNameField    string // JSON path to first name
	LastNameField     string // JSON path to last name
	DisplayNameField  string // JSON path to display name
	AvatarURLField    string // JSON path to avatar URL
}

// DefaultUserFieldMapping returns the default field mapping
func DefaultUserFieldMapping() UserFieldMapping {
	return UserFieldMapping{
		IDField:           "id",
		EmailField:        "email",
		EmailVerifiedField: "email_verified",
		FirstNameField:    "first_name",
		LastNameField:     "last_name",
		DisplayNameField:  "name",
		AvatarURLField:    "avatar_url",
	}
}

// NewCustomProvider creates a new custom OAuth provider
func NewCustomProvider(name string, cfg config.OAuthProviderConfig, mapping UserFieldMapping) *CustomProvider {
	return &CustomProvider{
		name:        name,
		config:      cfg,
		client:      &http.Client{},
		userMapping: mapping,
	}
}

// GetProviderName returns the provider name
func (p *CustomProvider) GetProviderName() types.AuthProvider {
	return types.AuthProviderCustom
}

// GetCustomProviderName returns the custom provider's specific name
func (p *CustomProvider) GetCustomProviderName() string {
	return p.name
}

// IsEnabled returns whether the provider is enabled
func (p *CustomProvider) IsEnabled() bool {
	return p.config.Enabled && p.config.ClientID != "" && p.config.ClientSecret != ""
}

// GetAuthURL returns the OAuth authorization URL
func (p *CustomProvider) GetAuthURL(state string, redirectURL string) string {
	params := url.Values{
		"client_id":     {p.config.ClientID},
		"redirect_uri":  {redirectURL},
		"response_type": {"code"},
		"scope":         {strings.Join(p.config.Scopes, " ")},
		"state":         {state},
	}
	return p.config.AuthURL + "?" + params.Encode()
}

// ExchangeCode exchanges an authorization code for tokens
func (p *CustomProvider) ExchangeCode(ctx context.Context, code string, redirectURL string) (*TokenResponse, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {p.config.ClientID},
		"client_secret": {p.config.ClientSecret},
		"redirect_uri":  {redirectURL},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", p.config.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.SSOProviderError(p.name, string(body))
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		Scope        string `json:"scope"`
	}

	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	return &TokenResponse{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		IDToken:      tokenResp.IDToken,
		TokenType:    tokenResp.TokenType,
		ExpiresIn:    tokenResp.ExpiresIn,
		Scope:        tokenResp.Scope,
	}, nil
}

// GetUserInfo retrieves user information from the provider
func (p *CustomProvider) GetUserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	if p.config.UserInfoURL == "" {
		return nil, errors.SSOProviderError(p.name, "user info URL not configured")
	}

	req, err := http.NewRequestWithContext(ctx, "GET", p.config.UserInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.SSOProviderError(p.name, string(body))
	}

	var rawData map[string]interface{}
	if err := json.Unmarshal(body, &rawData); err != nil {
		return nil, fmt.Errorf("failed to parse user info: %w", err)
	}

	return p.mapUserInfo(rawData), nil
}

// mapUserInfo maps the raw response to UserInfo based on field mapping
func (p *CustomProvider) mapUserInfo(data map[string]interface{}) *UserInfo {
	getString := func(field string) string {
		if v, ok := data[field]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
		return ""
	}

	getBool := func(field string) bool {
		if v, ok := data[field]; ok {
			switch b := v.(type) {
			case bool:
				return b
			case string:
				return b == "true"
			}
		}
		return false
	}

	return &UserInfo{
		ProviderUserID: getString(p.userMapping.IDField),
		Email:          getString(p.userMapping.EmailField),
		EmailVerified:  getBool(p.userMapping.EmailVerifiedField),
		FirstName:      getString(p.userMapping.FirstNameField),
		LastName:       getString(p.userMapping.LastNameField),
		DisplayName:    getString(p.userMapping.DisplayNameField),
		AvatarURL:      getString(p.userMapping.AvatarURLField),
		Provider:       types.AuthProviderCustom,
		RawData:        data,
	}
}

// ValidateIDToken validates an ID token (not all custom providers support this)
func (p *CustomProvider) ValidateIDToken(ctx context.Context, idToken string) (*UserInfo, error) {
	return nil, errors.SSOProviderError(p.name, "ID token validation not supported for custom providers")
}

// RefreshToken refreshes the access token
func (p *CustomProvider) RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {p.config.ClientID},
		"client_secret": {p.config.ClientSecret},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", p.config.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.SSOProviderError(p.name, string(body))
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
	}

	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	newRefreshToken := tokenResp.RefreshToken
	if newRefreshToken == "" {
		newRefreshToken = refreshToken
	}

	return &TokenResponse{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: newRefreshToken,
		TokenType:    tokenResp.TokenType,
		ExpiresIn:    tokenResp.ExpiresIn,
	}, nil
}
