package sso

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ven/auth/internal/config"
	"github.com/ven/auth/pkg/shared/errors"
	"github.com/ven/auth/pkg/shared/types"
)

const (
	appleAuthURL  = "https://appleid.apple.com/auth/authorize"
	appleTokenURL = "https://appleid.apple.com/auth/token"
	appleKeysURL  = "https://appleid.apple.com/auth/keys"
	appleIssuer   = "https://appleid.apple.com"

	// appleJWKSTTL bounds how long a fetched JWKS set is reused before a
	// re-fetch. Apple rotates these keys; an hour is well within their
	// rotation cadence while keeping the verification path off the network
	// on the hot path.
	appleJWKSTTL = time.Hour
)

// AppleProvider implements the Provider interface for Apple Sign In
type AppleProvider struct {
	config     config.OAuthProviderConfig
	client     *http.Client
	teamID     string
	keyID      string
	privateKey *ecdsa.PrivateKey

	// jwks caches Apple's published public keys (keyed by `kid`) for
	// id_token signature verification, refreshed at most every appleJWKSTTL.
	jwksMu      sync.RWMutex
	jwks        map[string]*rsa.PublicKey
	jwksFetched time.Time
}

// NewAppleProvider creates a new Apple Sign In provider. privateKeyPEM is the
// PKCS#8 .p8 contents — accepted as raw PEM or base64-encoded PEM (the .env
// transport for a multiline key).
func NewAppleProvider(cfg config.OAuthProviderConfig, teamID, keyID, privateKeyPEM string) (*AppleProvider, error) {
	var privateKey *ecdsa.PrivateKey

	if privateKeyPEM != "" {
		key, err := parseApplePrivateKey(privateKeyPEM)
		if err != nil {
			return nil, err
		}
		privateKey = key
	}

	return &AppleProvider{
		config:     cfg,
		client:     &http.Client{Timeout: 10 * time.Second},
		teamID:     teamID,
		keyID:      keyID,
		privateKey: privateKey,
		jwks:       map[string]*rsa.PublicKey{},
	}, nil
}

// parseApplePrivateKey decodes the .p8 key from PEM, transparently handling a
// base64-wrapped PEM (how a multiline key is usually carried through a single
// env var).
func parseApplePrivateKey(raw string) (*ecdsa.PrivateKey, error) {
	pemBytes := []byte(raw)
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		// Not raw PEM — try base64-decoding first, then PEM-decode.
		decoded, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
		if derr != nil {
			return nil, fmt.Errorf("apple private key: not valid PEM nor base64")
		}
		block, _ = pem.Decode(decoded)
		if block == nil {
			return nil, fmt.Errorf("apple private key: failed to PEM-decode")
		}
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("apple private key: failed to parse PKCS#8: %w", err)
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("apple private key is not ECDSA")
	}
	return ecKey, nil
}

// GetProviderName returns the provider name
func (p *AppleProvider) GetProviderName() types.AuthProvider {
	return types.AuthProviderApple
}

// IsEnabled returns whether the provider is enabled
func (p *AppleProvider) IsEnabled() bool {
	return p.config.Enabled && p.config.ClientID != "" && p.privateKey != nil
}

// GetAuthURL returns the Apple Sign In authorization URL
func (p *AppleProvider) GetAuthURL(state string, redirectURL string) string {
	params := url.Values{
		"client_id":     {p.config.ClientID},
		"redirect_uri":  {redirectURL},
		"response_type": {"code id_token"},
		"response_mode": {"form_post"},
		"scope":         {strings.Join(p.config.Scopes, " ")},
		"state":         {state},
	}
	return appleAuthURL + "?" + params.Encode()
}

// generateClientSecret generates a client secret JWT for Apple
func (p *AppleProvider) generateClientSecret() (string, error) {
	if p.privateKey == nil {
		return "", fmt.Errorf("private key not configured")
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"iss": p.teamID,
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
		"aud": "https://appleid.apple.com",
		"sub": p.config.ClientID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = p.keyID

	return token.SignedString(p.privateKey)
}

// ExchangeCode exchanges an authorization code for tokens
func (p *AppleProvider) ExchangeCode(ctx context.Context, code string, redirectURL string) (*TokenResponse, error) {
	clientSecret, err := p.generateClientSecret()
	if err != nil {
		return nil, fmt.Errorf("failed to generate client secret: %w", err)
	}

	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {p.config.ClientID},
		"client_secret": {clientSecret},
		"redirect_uri":  {redirectURL},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", appleTokenURL, strings.NewReader(data.Encode()))
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
		return nil, errors.SSOProviderError("apple", string(body))
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
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
	}, nil
}

// GetUserInfo retrieves user information from Apple ID token
// Apple doesn't provide a userinfo endpoint, so we parse the ID token
func (p *AppleProvider) GetUserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	// Apple doesn't provide user info via access token
	// User info should be extracted from the ID token
	return nil, errors.SSOProviderError("apple", "use ValidateIDToken to get user info")
}

// ValidateIDToken validates and parses an Apple ID token. The signature is
// verified against Apple's published JWKS (RS256), and the audience + issuer
// are checked. Email/name arrive only on the FIRST authorization for a given
// Apple ID — on subsequent logins `email` may be absent; that's expected and
// not an error (the caller resolves the user by ProviderUserID / `sub`).
func (p *AppleProvider) ValidateIDToken(ctx context.Context, idToken string) (*UserInfo, error) {
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		kid, _ := token.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("id_token missing kid")
		}
		return p.publicKeyForKID(ctx, kid)
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(appleIssuer),
		jwt.WithAudience(p.config.ClientID),
	)
	token, err := parser.Parse(idToken, keyFunc)
	if err != nil {
		return nil, errors.SSOProviderError("apple", "invalid id_token: "+err.Error())
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.SSOProviderError("apple", "invalid token claims")
	}

	sub, _ := claims["sub"].(string)
	email, _ := claims["email"].(string)
	// `email_verified` is a string ("true"/"false") on Apple tokens, but
	// some flows deliver it as a bool — tolerate both.
	emailVerified := false
	switch v := claims["email_verified"].(type) {
	case string:
		emailVerified = v == "true"
	case bool:
		emailVerified = v
	}

	return &UserInfo{
		ProviderUserID: sub,
		Email:          email,
		EmailVerified:  emailVerified,
		Provider:       types.AuthProviderApple,
		RawData:        claims,
	}, nil
}

// publicKeyForKID returns the RSA public key for the given key id, fetching
// and caching Apple's JWKS as needed. A cache miss after a fresh fetch is an
// error (unknown signing key) rather than a silent pass.
func (p *AppleProvider) publicKeyForKID(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	p.jwksMu.RLock()
	key, ok := p.jwks[kid]
	fresh := time.Since(p.jwksFetched) < appleJWKSTTL
	p.jwksMu.RUnlock()
	if ok && fresh {
		return key, nil
	}

	if err := p.refreshJWKS(ctx); err != nil {
		// Fall back to a stale-but-present key rather than failing login on a
		// transient JWKS-endpoint outage.
		if ok {
			return key, nil
		}
		return nil, err
	}

	p.jwksMu.RLock()
	key, ok = p.jwks[kid]
	p.jwksMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("apple jwks: no key for kid %q", kid)
	}
	return key, nil
}

// refreshJWKS fetches Apple's published keys and rebuilds the cache.
func (p *AppleProvider) refreshJWKS(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", appleKeysURL, nil)
	if err != nil {
		return err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("apple jwks fetch: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("apple jwks fetch: status %d", resp.StatusCode)
	}

	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("apple jwks parse: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(jwks.Keys))
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" {
			continue
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			continue
		}
		e := 0
		for _, b := range eBytes {
			e = e<<8 | int(b)
		}
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}
	}
	if len(keys) == 0 {
		return fmt.Errorf("apple jwks: no usable RSA keys")
	}

	p.jwksMu.Lock()
	p.jwks = keys
	p.jwksFetched = time.Now()
	p.jwksMu.Unlock()
	return nil
}

// ParseAppleUserName extracts first/last name from the JSON Apple posts in the
// `user` form field on the FIRST authorization only (form_post response mode).
// Shape: {"name":{"firstName":"Jane","lastName":"Doe"},"email":"..."}.
// Returns empty strings when the field is absent/malformed — every subsequent
// login omits it, so callers must tolerate that.
func ParseAppleUserName(userJSON string) (firstName, lastName string) {
	if strings.TrimSpace(userJSON) == "" {
		return "", ""
	}
	var parsed struct {
		Name struct {
			FirstName string `json:"firstName"`
			LastName  string `json:"lastName"`
		} `json:"name"`
	}
	if err := json.Unmarshal([]byte(userJSON), &parsed); err != nil {
		return "", ""
	}
	return parsed.Name.FirstName, parsed.Name.LastName
}

// RefreshToken refreshes the access token
func (p *AppleProvider) RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	clientSecret, err := p.generateClientSecret()
	if err != nil {
		return nil, fmt.Errorf("failed to generate client secret: %w", err)
	}

	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {p.config.ClientID},
		"client_secret": {clientSecret},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", appleTokenURL, strings.NewReader(data.Encode()))
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
		return nil, errors.SSOProviderError("apple", string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		IDToken     string `json:"id_token"`
	}

	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	return &TokenResponse{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: refreshToken,
		IDToken:      tokenResp.IDToken,
		TokenType:    tokenResp.TokenType,
		ExpiresIn:    tokenResp.ExpiresIn,
	}, nil
}
