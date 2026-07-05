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
	linkedinAuthURL     = "https://www.linkedin.com/oauth/v2/authorization"
	linkedinTokenURL    = "https://www.linkedin.com/oauth/v2/accessToken"
	linkedinUserInfoURL = "https://api.linkedin.com/v2/userinfo"
)

// LinkedInProvider implements the Provider interface for "Sign In with
// LinkedIn using OpenID Connect". Identity is read from the OIDC userinfo
// endpoint with the access token — authoritative and obtained over the same
// TLS back-channel as the code exchange (mirrors the Google adapter), so no
// separate id_token signature verification is needed.
type LinkedInProvider struct {
	config config.OAuthProviderConfig
	client *http.Client
	// userInfoURL is overridable in tests; defaults to the OIDC userinfo endpoint.
	userInfoURL string
}

// NewLinkedInProvider creates a new LinkedIn OIDC provider.
func NewLinkedInProvider(cfg config.OAuthProviderConfig) *LinkedInProvider {
	return &LinkedInProvider{config: cfg, client: &http.Client{}, userInfoURL: linkedinUserInfoURL}
}

func (p *LinkedInProvider) GetProviderName() types.AuthProvider {
	return types.AuthProviderLinkedIn
}

func (p *LinkedInProvider) IsEnabled() bool {
	return p.config.Enabled && p.config.ClientID != "" && p.config.ClientSecret != ""
}

func (p *LinkedInProvider) GetAuthURL(state string, redirectURL string) string {
	params := url.Values{
		"client_id":     {p.config.ClientID},
		"redirect_uri":  {redirectURL},
		"response_type": {"code"},
		"scope":         {strings.Join(p.config.Scopes, " ")},
		"state":         {state},
	}
	return linkedinAuthURL + "?" + params.Encode()
}

func (p *LinkedInProvider) ExchangeCode(ctx context.Context, code string, redirectURL string) (*TokenResponse, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {p.config.ClientID},
		"client_secret": {p.config.ClientSecret},
		"redirect_uri":  {redirectURL},
	}
	req, err := http.NewRequestWithContext(ctx, "POST", linkedinTokenURL, strings.NewReader(data.Encode()))
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
		return nil, errors.SSOProviderError("linkedin", string(body))
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
	// Deliberately drop the id_token: identity is read authoritatively from
	// the userinfo endpoint (the manager falls back to GetUserInfo when
	// IDToken is empty).
	return &TokenResponse{
		AccessToken: tokenResp.AccessToken,
		TokenType:   tokenResp.TokenType,
		ExpiresIn:   tokenResp.ExpiresIn,
		Scope:       tokenResp.Scope,
	}, nil
}

// GetUserInfo reads the OIDC userinfo claims with the access token.
func (p *LinkedInProvider) GetUserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
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
		return nil, errors.SSOProviderError("linkedin", string(body))
	}

	var li struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		GivenName     string `json:"given_name"`
		FamilyName    string `json:"family_name"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
	}
	if err := json.Unmarshal(body, &li); err != nil {
		return nil, fmt.Errorf("failed to parse user info: %w", err)
	}
	if li.Sub == "" {
		return nil, errors.SSOProviderError("linkedin", "userinfo missing sub")
	}

	rawData := make(map[string]interface{})
	_ = json.Unmarshal(body, &rawData)

	return &UserInfo{
		ProviderUserID: li.Sub,
		Email:          li.Email,
		EmailVerified:  li.EmailVerified,
		FirstName:      li.GivenName,
		LastName:       li.FamilyName,
		DisplayName:    li.Name,
		AvatarURL:      li.Picture,
		Provider:       types.AuthProviderLinkedIn,
		RawData:        rawData,
	}, nil
}

// ValidateIDToken is unused (ExchangeCode drops the id_token so the manager
// uses GetUserInfo). Implemented to satisfy the Provider interface.
func (p *LinkedInProvider) ValidateIDToken(ctx context.Context, idToken string) (*UserInfo, error) {
	return nil, errors.SSOProviderError("linkedin", "use GetUserInfo (userinfo endpoint)")
}

// RefreshToken — the auth-server doesn't persist provider refresh tokens.
func (p *LinkedInProvider) RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	return nil, errors.SSOProviderError("linkedin", "refresh not supported")
}
