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
	facebookAuthURL     = "https://www.facebook.com/v19.0/dialog/oauth"
	facebookTokenURL    = "https://graph.facebook.com/v19.0/oauth/access_token"
	facebookUserInfoURL = "https://graph.facebook.com/v19.0/me?fields=id,email,first_name,last_name"
)

// FacebookProvider implements the Provider interface for Facebook Login
// (OAuth2 authorization-code). Profile comes from the Graph API; Facebook
// returns no id_token in this flow, so identity is read from /me.
type FacebookProvider struct {
	config config.OAuthProviderConfig
	client *http.Client
	// userInfoURL is overridable in tests; defaults to the Graph endpoint.
	userInfoURL string
}

// NewFacebookProvider creates a new Facebook OAuth provider.
func NewFacebookProvider(cfg config.OAuthProviderConfig) *FacebookProvider {
	return &FacebookProvider{config: cfg, client: &http.Client{}, userInfoURL: facebookUserInfoURL}
}

func (p *FacebookProvider) GetProviderName() types.AuthProvider {
	return types.AuthProviderFacebook
}

func (p *FacebookProvider) IsEnabled() bool {
	return p.config.Enabled && p.config.ClientID != "" && p.config.ClientSecret != ""
}

func (p *FacebookProvider) GetAuthURL(state string, redirectURL string) string {
	params := url.Values{
		"client_id":     {p.config.ClientID},
		"redirect_uri":  {redirectURL},
		"response_type": {"code"},
		"scope":         {strings.Join(p.config.Scopes, " ")},
		"state":         {state},
	}
	return facebookAuthURL + "?" + params.Encode()
}

func (p *FacebookProvider) ExchangeCode(ctx context.Context, code string, redirectURL string) (*TokenResponse, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {p.config.ClientID},
		"client_secret": {p.config.ClientSecret},
		"redirect_uri":  {redirectURL},
	}
	// Facebook accepts the token request as a GET with query params or a POST
	// form; POST keeps the secret out of any intermediary's query logs.
	req, err := http.NewRequestWithContext(ctx, "POST", facebookTokenURL, strings.NewReader(data.Encode()))
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
		return nil, errors.SSOProviderError("facebook", string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}
	return &TokenResponse{
		AccessToken: tokenResp.AccessToken,
		TokenType:   tokenResp.TokenType,
		ExpiresIn:   tokenResp.ExpiresIn,
	}, nil
}

// GetUserInfo reads the profile from the Graph API. Email may be ABSENT when
// the user registered with a phone number and granted no email — that is not
// an error (mirrors Apple's no-email case); the upsert resolves by
// provider_user_id on subsequent logins.
func (p *FacebookProvider) GetUserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", p.userInfoURL, nil)
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
		return nil, errors.SSOProviderError("facebook", string(body))
	}

	var fbUser struct {
		ID        string `json:"id"`
		Email     string `json:"email"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
	}
	if err := json.Unmarshal(body, &fbUser); err != nil {
		return nil, fmt.Errorf("failed to parse user info: %w", err)
	}
	if fbUser.ID == "" {
		return nil, errors.SSOProviderError("facebook", "profile missing id")
	}

	rawData := make(map[string]interface{})
	_ = json.Unmarshal(body, &rawData)

	display := strings.TrimSpace(fbUser.FirstName + " " + fbUser.LastName)
	return &UserInfo{
		ProviderUserID: fbUser.ID,
		Email:          fbUser.Email,
		// Facebook only returns an email it has already verified.
		EmailVerified: fbUser.Email != "",
		FirstName:     fbUser.FirstName,
		LastName:      fbUser.LastName,
		DisplayName:   display,
		Provider:      types.AuthProviderFacebook,
		RawData:       rawData,
	}, nil
}

// ValidateIDToken is unused for Facebook (the Graph flow returns no id_token);
// the manager falls back to GetUserInfo. Implemented to satisfy the interface.
func (p *FacebookProvider) ValidateIDToken(ctx context.Context, idToken string) (*UserInfo, error) {
	return nil, errors.SSOProviderError("facebook", "facebook does not issue an id_token; use GetUserInfo")
}

// RefreshToken — Facebook long-lived tokens are exchanged differently and the
// auth-server doesn't persist provider refresh tokens, so this is a no-op
// error to satisfy the interface.
func (p *FacebookProvider) RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	return nil, errors.SSOProviderError("facebook", "refresh not supported")
}
