package sso

import (
	"context"
	"encoding/base64"
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
	// Host aliases: x.com and twitter.com are interchangeable, as are api.x.com
	// and api.twitter.com. These are the current (x.com) forms per
	// https://docs.x.com/resources/fundamentals/authentication/oauth-2-0/authorization-code
	xAuthURL     = "https://x.com/i/oauth2/authorize"
	xTokenURL    = "https://api.x.com/2/oauth2/token"
	xUserInfoURL = "https://api.x.com/2/users/me?user.fields=profile_image_url,name,username,verified"
)

// XProvider implements the Provider interface for "Login with X" (x.com /
// Twitter OAuth 2.0, authorization-code grant).
//
// Two things make X different from the other OAuth2 providers here:
//
//  1. PKCE is MANDATORY on the auth-server↔X leg, even though we authenticate
//     as a confidential client (HTTP Basic on the token endpoint). The base
//     Provider interface carries no verifier and ExchangeCode never sees
//     `state`, so X implements the optional ProviderPKCE interface: the
//     manager mints the verifier, stores it in the (Redis-backed) state
//     record, embeds the S256 challenge via BuildAuthURLWithPKCE, and hands
//     the verifier back via ExchangeCodeWithVerifier. Multi-replica safe.
//
//  2. X returns NO email for the vast majority of apps (there is no email
//     scope in the standard OAuth2 product). GetUserInfo therefore synthesizes
//     a stable, unique, non-deliverable placeholder derived from the X user id
//     when email is absent — see xPlaceholderEmail. This keeps the identity
//     keyed on ProviderUserID and avoids the users(namespace, email) unique
//     constraint collapsing multiple email-less X users onto one row.
type XProvider struct {
	config config.OAuthProviderConfig
	client *http.Client
	// authURL/tokenURL/userInfoURL are overridable in tests; default to the
	// live X endpoints.
	authURL     string
	tokenURL    string
	userInfoURL string
}

// NewXProvider creates a new X (Twitter) OAuth 2.0 provider.
func NewXProvider(cfg config.OAuthProviderConfig) *XProvider {
	return &XProvider{
		config:      cfg,
		client:      &http.Client{},
		authURL:     xAuthURL,
		tokenURL:    xTokenURL,
		userInfoURL: xUserInfoURL,
	}
}

func (p *XProvider) GetProviderName() types.AuthProvider {
	return types.AuthProviderX
}

func (p *XProvider) IsEnabled() bool {
	return p.config.Enabled && p.config.ClientID != "" && p.config.ClientSecret != ""
}

// GetAuthURL satisfies the base Provider interface but is NOT used for X: the
// manager detects ProviderPKCE and calls BuildAuthURLWithPKCE instead, because
// X rejects an authorize request that lacks code_challenge. Implemented for
// completeness; a URL built here (no challenge) would be refused by X.
func (p *XProvider) GetAuthURL(state string, redirectURL string) string {
	return p.buildAuthURL(state, redirectURL, "")
}

// BuildAuthURLWithPKCE builds the authorize URL carrying the S256
// code_challenge. This is the path the manager actually uses (ProviderPKCE).
func (p *XProvider) BuildAuthURLWithPKCE(state, redirectURL, codeChallenge string) string {
	return p.buildAuthURL(state, redirectURL, codeChallenge)
}

func (p *XProvider) buildAuthURL(state, redirectURL, codeChallenge string) string {
	params := url.Values{
		"response_type": {"code"},
		"client_id":     {p.config.ClientID},
		"redirect_uri":  {redirectURL},
		"scope":         {strings.Join(p.config.Scopes, " ")},
		"state":         {state},
	}
	if codeChallenge != "" {
		params.Set("code_challenge", codeChallenge)
		params.Set("code_challenge_method", CodeChallengeMethodS256)
	}
	return p.authURL + "?" + params.Encode()
}

// ExchangeCode satisfies the base Provider interface but is unreachable for X
// (the manager routes X through ExchangeCodeWithVerifier). Without the
// code_verifier the exchange cannot succeed, so fail loudly rather than send a
// request X will reject.
func (p *XProvider) ExchangeCode(ctx context.Context, code string, redirectURL string) (*TokenResponse, error) {
	return nil, errors.SSOProviderError("x", "X requires PKCE; token exchange must go through ExchangeCodeWithVerifier")
}

// ExchangeCodeWithVerifier exchanges the authorization code for tokens. X is a
// confidential client here, so we authenticate with HTTP Basic
// (base64(client_id:client_secret)) AND include the PKCE code_verifier in the
// form body. offline.access in the requested scopes yields a refresh_token.
func (p *XProvider) ExchangeCodeWithVerifier(ctx context.Context, code, redirectURL, codeVerifier string) (*TokenResponse, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURL},
		"code_verifier": {codeVerifier},
	}
	req, err := http.NewRequestWithContext(ctx, "POST", p.tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", p.basicAuthHeader())

	return p.doTokenRequest(req)
}

// GetUserInfo reads the profile from GET /2/users/me. X returns
// { data: { id, name, username, profile_image_url, verified } }. Email is
// ABSENT for standard apps — we synthesize a stable placeholder (see
// xPlaceholderEmail) so downstream user-upsert keys cleanly on the X user id
// without tripping the per-namespace email-uniqueness index. This must NEVER
// error on missing email.
func (p *XProvider) GetUserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
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
		return nil, errors.SSOProviderError("x", string(body))
	}

	var out struct {
		Data struct {
			ID              string `json:"id"`
			Name            string `json:"name"`
			Username        string `json:"username"`
			ProfileImageURL string `json:"profile_image_url"`
			Verified        bool   `json:"verified"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("failed to parse user info: %w", err)
	}
	if out.Data.ID == "" {
		return nil, errors.SSOProviderError("x", "profile missing id")
	}

	// X emails are almost never present; synthesize a stable placeholder keyed
	// on the X user id. EmailVerified stays false — it's a placeholder, not a
	// confirmed address.
	email := xPlaceholderEmail(out.Data.ID)

	// Prefer the larger avatar: X returns the `_normal` (48px) variant by
	// default; `_400x400` is the standard large size.
	avatar := out.Data.ProfileImageURL
	if avatar != "" {
		avatar = strings.Replace(avatar, "_normal", "_400x400", 1)
	}

	rawData := make(map[string]interface{})
	_ = json.Unmarshal(body, &rawData)
	// Surface the handle at the top level of RawData too, so consumers don't
	// have to reach into the nested `data` object.
	rawData["username"] = out.Data.Username

	return &UserInfo{
		ProviderUserID: out.Data.ID,
		Email:          email,
		EmailVerified:  false,
		DisplayName:    out.Data.Name,
		FirstName:      out.Data.Name,
		AvatarURL:      avatar,
		Provider:       types.AuthProviderX,
		RawData:        rawData,
	}, nil
}

// ValidateIDToken is unsupported: X OAuth 2.0 issues no id_token. Implemented
// to satisfy the Provider interface; the manager falls back to GetUserInfo.
func (p *XProvider) ValidateIDToken(ctx context.Context, idToken string) (*UserInfo, error) {
	return nil, errors.SSOProviderError("x", "X OAuth2 issues no id_token; use GetUserInfo")
}

// RefreshToken refreshes the access token via grant_type=refresh_token with
// HTTP Basic auth (confidential client). Requires the app to have requested
// offline.access.
func (p *XProvider) RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}
	req, err := http.NewRequestWithContext(ctx, "POST", p.tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", p.basicAuthHeader())

	resp, err := p.doTokenRequest(req)
	if err != nil {
		return nil, err
	}
	// X may not echo the refresh_token on rotation; preserve the presented one
	// if the response omits it (mirrors the Google adapter).
	if resp.RefreshToken == "" {
		resp.RefreshToken = refreshToken
	}
	return resp, nil
}

// doTokenRequest executes a prepared token-endpoint request and parses the
// standard OAuth2 token response.
func (p *XProvider) doTokenRequest(req *http.Request) (*TokenResponse, error) {
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
		return nil, errors.SSOProviderError("x", string(body))
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
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
		TokenType:    tokenResp.TokenType,
		ExpiresIn:    tokenResp.ExpiresIn,
		Scope:        tokenResp.Scope,
	}, nil
}

func (p *XProvider) basicAuthHeader() string {
	raw := p.config.ClientID + ":" + p.config.ClientSecret
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(raw))
}

// xPlaceholderEmail builds a stable, unique, guaranteed-undeliverable email for
// an X account that exposed no real address. The `.invalid` TLD is reserved by
// RFC 2606 so it can never resolve or receive mail. Keyed on the immutable X
// user id, so the same X account always maps to the same synthetic address —
// which is what makes the by-email upsert path idempotent for X users.
func xPlaceholderEmail(providerUserID string) string {
	return "x-" + providerUserID + "@users.x.invalid"
}

// compile-time assertion that XProvider offers the provider-leg PKCE capability.
var _ ProviderPKCE = (*XProvider)(nil)
