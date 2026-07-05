package sso

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/rw3iss/auth/internal/config"
	"github.com/rw3iss/auth/pkg/shared/errors"
	"github.com/rw3iss/auth/pkg/shared/types"
)

const (
	googleAuthURL     = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL    = "https://oauth2.googleapis.com/token"
	googleUserInfoURL = "https://www.googleapis.com/oauth2/v2/userinfo"
)

// GoogleProvider implements the Provider interface for Google OAuth
type GoogleProvider struct {
	config  config.OAuthProviderConfig
	client  *http.Client
}

// NewGoogleProvider creates a new Google OAuth provider
func NewGoogleProvider(cfg config.OAuthProviderConfig) *GoogleProvider {
	return &GoogleProvider{
		config: cfg,
		client: &http.Client{},
	}
}

// GetProviderName returns the provider name
func (p *GoogleProvider) GetProviderName() types.AuthProvider {
	return types.AuthProviderGoogle
}

// IsEnabled returns whether the provider is enabled
func (p *GoogleProvider) IsEnabled() bool {
	return p.config.Enabled && p.config.ClientID != "" && p.config.ClientSecret != ""
}

// GetAuthURL returns the Google OAuth authorization URL
func (p *GoogleProvider) GetAuthURL(state string, redirectURL string) string {
	params := url.Values{
		"client_id":     {p.config.ClientID},
		"redirect_uri":  {redirectURL},
		"response_type": {"code"},
		"scope":         {strings.Join(p.config.Scopes, " ")},
		"state":         {state},
		"access_type":   {"offline"},
		"prompt":        {"consent"},
	}
	return googleAuthURL + "?" + params.Encode()
}

// ExchangeCode exchanges an authorization code for tokens
func (p *GoogleProvider) ExchangeCode(ctx context.Context, code string, redirectURL string) (*TokenResponse, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {p.config.ClientID},
		"client_secret": {p.config.ClientSecret},
		"redirect_uri":  {redirectURL},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", googleTokenURL, strings.NewReader(data.Encode()))
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
		return nil, errors.SSOProviderError("google", string(body))
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

// GetUserInfo retrieves user information from Google
func (p *GoogleProvider) GetUserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", googleUserInfoURL, nil)
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
		return nil, errors.SSOProviderError("google", string(body))
	}

	var googleUser struct {
		ID            string `json:"id"`
		Email         string `json:"email"`
		VerifiedEmail bool   `json:"verified_email"`
		Name          string `json:"name"`
		GivenName     string `json:"given_name"`
		FamilyName    string `json:"family_name"`
		Picture       string `json:"picture"`
	}

	if err := json.Unmarshal(body, &googleUser); err != nil {
		return nil, fmt.Errorf("failed to parse user info: %w", err)
	}

	rawData := make(map[string]interface{})
	_ = json.Unmarshal(body, &rawData)

	return &UserInfo{
		ProviderUserID: googleUser.ID,
		Email:          googleUser.Email,
		EmailVerified:  googleUser.VerifiedEmail,
		FirstName:      googleUser.GivenName,
		LastName:       googleUser.FamilyName,
		DisplayName:    googleUser.Name,
		AvatarURL:      googleUser.Picture,
		Provider:       types.AuthProviderGoogle,
		RawData:        rawData,
	}, nil
}

// ValidateIDToken validates a Google ID token
func (p *GoogleProvider) ValidateIDToken(ctx context.Context, idToken string) (*UserInfo, error) {
	// For simplicity, we'll validate by calling the tokeninfo endpoint
	// In production, you should validate the JWT locally
	url := fmt.Sprintf("https://oauth2.googleapis.com/tokeninfo?id_token=%s", idToken)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to validate ID token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.SSOProviderError("google", "invalid ID token")
	}

	var tokenInfo struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified string `json:"email_verified"`
		Name          string `json:"name"`
		GivenName     string `json:"given_name"`
		FamilyName    string `json:"family_name"`
		Picture       string `json:"picture"`
		Aud           string `json:"aud"`
	}

	if err := json.Unmarshal(body, &tokenInfo); err != nil {
		return nil, fmt.Errorf("failed to parse token info: %w", err)
	}

	// Verify audience
	if tokenInfo.Aud != p.config.ClientID {
		return nil, errors.SSOProviderError("google", "invalid audience")
	}

	return &UserInfo{
		ProviderUserID: tokenInfo.Sub,
		Email:          tokenInfo.Email,
		EmailVerified:  tokenInfo.EmailVerified == "true",
		FirstName:      tokenInfo.GivenName,
		LastName:       tokenInfo.FamilyName,
		DisplayName:    tokenInfo.Name,
		AvatarURL:      tokenInfo.Picture,
		Provider:       types.AuthProviderGoogle,
	}, nil
}

// RefreshToken refreshes the access token
func (p *GoogleProvider) RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {p.config.ClientID},
		"client_secret": {p.config.ClientSecret},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", googleTokenURL, strings.NewReader(data.Encode()))
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
		return nil, errors.SSOProviderError("google", string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		Scope       string `json:"scope"`
	}

	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	return &TokenResponse{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: refreshToken, // Google doesn't always return a new refresh token
		TokenType:    tokenResp.TokenType,
		ExpiresIn:    tokenResp.ExpiresIn,
		Scope:        tokenResp.Scope,
	}, nil
}
