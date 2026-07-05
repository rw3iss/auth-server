package sso

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/rw3iss/auth/internal/config"
	"github.com/rw3iss/auth/pkg/shared/errors"
	"github.com/rw3iss/auth/pkg/shared/types"
)

// Manager manages SSO providers and state
type Manager struct {
	providers       map[types.AuthProvider]Provider
	customProviders map[string]Provider
	stateStore      StateStore
	// authCodeStore holds short-lived PKCE auth codes minted in the callback
	// and redeemed at /auth/sso/exchange. AUDIT C2.
	authCodeStore AuthCodeStore
	// allowedRedirects is the set of redirect URLs (or URL prefixes) the
	// server will accept in /auth/sso/url. AUDIT 1.13: without this the
	// client can pass any URL, including attacker-controlled ones, and
	// the resulting OAuth flow leaks code+state to the attacker. Empty
	// list = "accept anything" (development default) — operators MUST
	// configure this in production.
	allowedRedirects []string
	mu               sync.RWMutex
}

// StateStore interface for storing OAuth state. AUDIT 1.14: callers MUST
// validate via GetAndDelete (atomic) rather than Get followed by Delete,
// which is racy under concurrent callbacks with the same state value.
type StateStore interface {
	Set(ctx context.Context, state string, data *StateData, expiry time.Duration) error
	Get(ctx context.Context, state string) (*StateData, error)
	Delete(ctx context.Context, state string) error
	// GetAndDelete atomically reads and removes the state record. Returns
	// NotFound if absent. This is the only safe way to consume one-shot
	// state during a callback.
	GetAndDelete(ctx context.Context, state string) (*StateData, error)
}

// StateData represents data stored with OAuth state
type StateData struct {
	Provider       types.AuthProvider `json:"provider"`
	CustomProvider string             `json:"custom_provider,omitempty"`
	RedirectURL    string             `json:"redirect_url"`
	OrganizationID string             `json:"organization_id,omitempty"`
	InviteCode     string             `json:"invite_code,omitempty"`
	// AppCode carries the consuming app across the SSO redirect round-trip
	// so the callback upsert resolves the right user pool(s) (migration 017
	// / docs/USER_POOLS.md). Captured at /auth/sso/url from X-App-Code.
	AppCode   string    `json:"app_code,omitempty"`
	CreatedAt time.Time `json:"created_at"`

	// AUDIT C2 — PKCE (RFC 7636) for public clients. When non-empty, the
	// callback issues a short-lived auth_code instead of token pair; the
	// public client redeems {auth_code, code_verifier} at /auth/sso/exchange.
	// Empty values mean PKCE was not initiated; the flow behaves as before
	// (callback returns tokens directly). Only S256 is accepted server-side
	// — see internal/auth/sso/pkce.go.
	CodeChallenge       string `json:"code_challenge,omitempty"`
	CodeChallengeMethod string `json:"code_challenge_method,omitempty"`
}

// AuthCodeData is the server-issued post-callback token (AUDIT C2). It
// holds the same provider-confirmed identity payload that SSOLogin would have
// minted tokens for, plus the PKCE challenge that the public client must
// answer before we hand over the tokens. TTL is short (60s) — the public
// client should redeem immediately after the redirect.
type AuthCodeData struct {
	UserID              string             `json:"user_id"`
	Email               string             `json:"email"`
	OrganizationID      string             `json:"organization_id,omitempty"`
	AppCode             string             `json:"app_code,omitempty"`
	Provider            types.AuthProvider `json:"provider"`
	RememberMe          bool               `json:"remember_me"`
	CodeChallenge       string             `json:"code_challenge"`
	CodeChallengeMethod string             `json:"code_challenge_method"`
	CreatedAt           time.Time          `json:"created_at"`
}

// AuthCodeStore is the persistence boundary for one-shot PKCE auth codes.
// Mirrors StateStore in shape (atomic GetAndDelete is the only safe consume
// pattern). Backed by Redis when available; in-memory otherwise.
type AuthCodeStore interface {
	Set(ctx context.Context, code string, data *AuthCodeData, expiry time.Duration) error
	GetAndDelete(ctx context.Context, code string) (*AuthCodeData, error)
}

// InMemoryAuthCodeStore is the development / Redis-unavailable fallback.
// Per the AUDIT 1.14 lesson with state, GetAndDelete takes a write lock
// across the read+remove pair so concurrent redemptions can't both succeed.
type InMemoryAuthCodeStore struct {
	data map[string]*authCodeEntry
	mu   sync.RWMutex
}

type authCodeEntry struct {
	data   *AuthCodeData
	expiry time.Time
}

// NewInMemoryAuthCodeStore returns an in-memory implementation with a
// background cleanup goroutine. Suitable for single-replica dev; production
// should always be backed by Redis. The goroutine exits when ctx is
// cancelled — pass the application's shutdown context (AUDIT 5.6).
func NewInMemoryAuthCodeStore(ctx context.Context) *InMemoryAuthCodeStore {
	store := &InMemoryAuthCodeStore{data: make(map[string]*authCodeEntry)}
	go store.cleanup(ctx)
	return store
}

func (s *InMemoryAuthCodeStore) Set(_ context.Context, code string, data *AuthCodeData, expiry time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[code] = &authCodeEntry{data: data, expiry: time.Now().Add(expiry)}
	return nil
}

func (s *InMemoryAuthCodeStore) GetAndDelete(_ context.Context, code string) (*AuthCodeData, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.data[code]
	if !ok || time.Now().After(entry.expiry) {
		if ok {
			delete(s.data, code)
		}
		return nil, errors.NotFound("auth_code")
	}
	delete(s.data, code)
	return entry.data, nil
}

func (s *InMemoryAuthCodeStore) cleanup(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.mu.Lock()
			now := time.Now()
			for k, v := range s.data {
				if now.After(v.expiry) {
					delete(s.data, k)
				}
			}
			s.mu.Unlock()
		}
	}
}

// logSSONotImplemented emits a structured-friendly warning for the
// Apple / Microsoft / GitHub config flags that don't currently have
// adapter implementations. AUDIT 7.7.
func logSSONotImplemented(vendor string) {
	// Use stdlib log; the SSO package doesn't take a slog logger today.
	// Operators see this once at boot — that's exactly when they need
	// to notice the mismatch.
	log.Printf("[WARN] sso: %s provider enabled in config but no adapter is implemented; "+
		"requests for this provider will fail until an adapter is added", vendor)
}

// InMemoryStateStore is a simple in-memory state store
type InMemoryStateStore struct {
	data map[string]*stateEntry
	mu   sync.RWMutex
}

type stateEntry struct {
	data   *StateData
	expiry time.Time
}

// NewInMemoryStateStore creates a new in-memory state store. The cleanup
// goroutine exits when ctx is cancelled — pass the application's shutdown
// context (AUDIT 5.6).
func NewInMemoryStateStore(ctx context.Context) *InMemoryStateStore {
	store := &InMemoryStateStore{
		data: make(map[string]*stateEntry),
	}
	go store.cleanup(ctx)
	return store
}

func (s *InMemoryStateStore) Set(ctx context.Context, state string, data *StateData, expiry time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[state] = &stateEntry{
		data:   data,
		expiry: time.Now().Add(expiry),
	}
	return nil
}

func (s *InMemoryStateStore) Get(ctx context.Context, state string) (*StateData, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.data[state]
	if !ok || time.Now().After(entry.expiry) {
		return nil, errors.NotFound("OAuth state")
	}
	return entry.data, nil
}

func (s *InMemoryStateStore) Delete(ctx context.Context, state string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, state)
	return nil
}

// GetAndDelete reads and removes the state under a single write lock so two
// concurrent callbacks with the same state can't both see it as present.
// AUDIT 1.14.
func (s *InMemoryStateStore) GetAndDelete(ctx context.Context, state string) (*StateData, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.data[state]
	if !ok || time.Now().After(entry.expiry) {
		// Clean up if expired; either way the caller sees NotFound.
		if ok {
			delete(s.data, state)
		}
		return nil, errors.NotFound("OAuth state")
	}
	delete(s.data, state)
	return entry.data, nil
}

func (s *InMemoryStateStore) cleanup(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.mu.Lock()
			now := time.Now()
			for k, v := range s.data {
				if now.After(v.expiry) {
					delete(s.data, k)
				}
			}
			s.mu.Unlock()
		}
	}
}

// NewManager creates a new SSO manager. `allowedRedirects` is the list of
// acceptable redirect URL prefixes for /auth/sso/url. Pass nil/empty to
// disable the gate (development only).
//
// `ctx` is the application's shutdown context — propagated to any
// in-memory store created as a default so their cleanup goroutines exit
// cleanly on server shutdown (AUDIT 5.6).
//
// The auth_code store (AUDIT C2) defaults to in-memory; callers that boot
// against Redis should swap it in via SetAuthCodeStore before serving
// requests, same way the state store is swapped in main.go.
func NewManager(ctx context.Context, cfg config.SSOConfig, stateStore StateStore, allowedRedirects []string) (*Manager, error) {
	if stateStore == nil {
		stateStore = NewInMemoryStateStore(ctx)
	}

	m := &Manager{
		providers:        make(map[types.AuthProvider]Provider),
		customProviders:  make(map[string]Provider),
		stateStore:       stateStore,
		authCodeStore:    NewInMemoryAuthCodeStore(ctx),
		allowedRedirects: allowedRedirects,
	}

	// Initialize Google provider
	if cfg.Google.Enabled {
		m.providers[types.AuthProviderGoogle] = NewGoogleProvider(cfg.Google)
	}

	// Initialize Apple provider ("Sign in with Apple"). The client secret is
	// an ES256 JWT signed with the .p8 key, so registration can fail if the
	// key is malformed — log loudly and skip rather than aborting boot, so a
	// bad Apple config never takes the whole auth server down.
	if cfg.Apple.Enabled {
		appleProvider, err := NewAppleProvider(cfg.Apple, cfg.Apple.TeamID, cfg.Apple.KeyID, cfg.Apple.PrivateKey)
		if err != nil {
			log.Printf("[WARN] sso: Apple provider enabled but failed to initialize: %v; "+
				"Apple login will be unavailable until the config is fixed", err)
		} else {
			m.providers[types.AuthProviderApple] = appleProvider
		}
	}

	// Facebook (OAuth2 / Graph) + LinkedIn (OIDC) — federate GlobalSKU's
	// FB/LinkedIn logins as first-class providers (integration spec §6).
	if cfg.Facebook.Enabled {
		m.providers[types.AuthProviderFacebook] = NewFacebookProvider(cfg.Facebook)
	}
	if cfg.LinkedIn.Enabled {
		m.providers[types.AuthProviderLinkedIn] = NewLinkedInProvider(cfg.LinkedIn)
	}

	// AUDIT 7.7: Microsoft / GitHub are configured-enabled but not
	// implemented. Log a loud warning so the misconfiguration surfaces at
	// boot. When needed, drop in a `Provider` impl and register it here.
	if cfg.Microsoft.Enabled {
		logSSONotImplemented("Microsoft")
	}
	if cfg.GitHub.Enabled {
		logSSONotImplemented("GitHub")
	}

	// Initialize custom providers
	for name, providerCfg := range cfg.Custom {
		if providerCfg.Enabled {
			m.customProviders[name] = NewCustomProvider(name, providerCfg, DefaultUserFieldMapping())
		}
	}

	return m, nil
}

// GetProvider returns a provider by type
func (m *Manager) GetProvider(providerType types.AuthProvider) (Provider, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	provider, ok := m.providers[providerType]
	if !ok || !provider.IsEnabled() {
		return nil, errors.SSONotConfigured(string(providerType))
	}
	return provider, nil
}

// GetCustomProvider returns a custom provider by name
func (m *Manager) GetCustomProvider(name string) (Provider, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	provider, ok := m.customProviders[name]
	if !ok || !provider.IsEnabled() {
		return nil, errors.SSONotConfigured(name)
	}
	return provider, nil
}

// GetEnabledProviders returns all enabled providers
func (m *Manager) GetEnabledProviders() []types.AuthProvider {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var providers []types.AuthProvider
	for providerType, provider := range m.providers {
		if provider.IsEnabled() {
			providers = append(providers, providerType)
		}
	}
	return providers
}

// GetEnabledCustomProviders returns all enabled custom providers
func (m *Manager) GetEnabledCustomProviders() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var providers []string
	for name, provider := range m.customProviders {
		if provider.IsEnabled() {
			providers = append(providers, name)
		}
	}
	return providers
}

// RegisterCustomProvider registers a custom provider at runtime
func (m *Manager) RegisterCustomProvider(name string, provider Provider) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.customProviders[name] = provider
}

// GenerateState generates a new OAuth state token
func (m *Manager) GenerateState(ctx context.Context, data *StateData) (string, error) {
	// Generate random state
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate state: %w", err)
	}
	state := base64.URLEncoding.EncodeToString(b)

	data.CreatedAt = time.Now()

	// Store state with 10 minute expiry
	if err := m.stateStore.Set(ctx, state, data, 10*time.Minute); err != nil {
		return "", fmt.Errorf("failed to store state: %w", err)
	}

	return state, nil
}

// ValidateState validates and retrieves state data atomically — get-and-delete
// in one operation so two concurrent callbacks with the same state value
// can't both succeed (AUDIT 1.14). Backed by Redis GETDEL when available;
// the in-memory fallback uses a single write lock around both steps.
func (m *Manager) ValidateState(ctx context.Context, state string) (*StateData, error) {
	return m.stateStore.GetAndDelete(ctx, state)
}

// validateRedirectURL returns nil if the supplied URL is acceptable per the
// allowlist. AUDIT 1.13: without this, an attacker can request an SSO URL
// pointing back to attacker-controlled origin and harvest code+state. Empty
// allowlist short-circuits to "accept anything" — development only, never
// production.
func (m *Manager) validateRedirectURL(redirectURL string) error {
	if redirectURL == "" {
		return errors.New(errors.ErrCodeValidation, "redirect_url is required", 400)
	}
	if len(m.allowedRedirects) == 0 {
		return nil
	}
	for _, allowed := range m.allowedRedirects {
		// Exact-match OR prefix-match when the allowlist entry ends with
		// `*` (path-suffix wildcards). Prefix matching against the
		// scheme://host portion is required to be safe; we let operators
		// configure the precise form they want via the trailing `*`.
		if allowed == redirectURL {
			return nil
		}
		if len(allowed) > 0 && allowed[len(allowed)-1] == '*' {
			prefix := allowed[:len(allowed)-1]
			if len(redirectURL) >= len(prefix) && redirectURL[:len(prefix)] == prefix {
				return nil
			}
		}
	}
	return errors.New(errors.ErrCodeValidation, "redirect_url is not allowed", 400)
}

// SetAuthCodeStore swaps the auth-code backend. Used in main.go to wire a
// Redis-backed store when Redis is connected. Must be called before serving
// requests; not safe for concurrent swap.
func (m *Manager) SetAuthCodeStore(s AuthCodeStore) {
	if s != nil {
		m.authCodeStore = s
	}
}

// IssueAuthCode mints a one-time auth code (AUDIT C2 — PKCE). The caller
// (auth_service.SSOLogin path) populates AuthCodeData after the upstream
// provider exchange completes, with the same identity payload that would
// have minted tokens directly. Returned code is base64url-encoded random
// bytes; lifetime is short — the public client should redeem within seconds.
func (m *Manager) IssueAuthCode(ctx context.Context, data *AuthCodeData, expiry time.Duration) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate auth_code: %w", err)
	}
	code := base64.URLEncoding.EncodeToString(b)
	data.CreatedAt = time.Now()
	if err := m.authCodeStore.Set(ctx, code, data, expiry); err != nil {
		return "", fmt.Errorf("failed to store auth_code: %w", err)
	}
	return code, nil
}

// ConsumeAuthCode atomically reads-and-deletes an auth code. Returns NotFound
// if the code has already been redeemed, expired, or was never issued.
// One-shot guarantees the same code can't be exchanged twice.
func (m *Manager) ConsumeAuthCode(ctx context.Context, code string) (*AuthCodeData, error) {
	return m.authCodeStore.GetAndDelete(ctx, code)
}

// AuthURLInput parameterizes /auth/sso/url. Bundling fields rather than
// adding to the positional argument list keeps the API stable as PKCE-style
// extensions accrete. Required: Provider + RedirectURL. Optional: org / invite /
// PKCE pair. PKCE is initiated atomically (challenge AND method together).
type AuthURLInput struct {
	Provider            types.AuthProvider
	CustomProvider      string // when Provider == Custom
	RedirectURL         string
	OrganizationID      string
	InviteCode          string
	AppCode             string
	CodeChallenge       string
	CodeChallengeMethod string
}

// GetAuthURL generates an authorization URL for a provider. AUDIT 1.13:
// redirectURL is validated against the configured allowlist before any
// state is minted. AUDIT C2: when CodeChallenge is non-empty, PKCE is
// initiated and persisted with the state record.
func (m *Manager) GetAuthURL(ctx context.Context, input AuthURLInput) (string, string, error) {
	if err := m.validateRedirectURL(input.RedirectURL); err != nil {
		return "", "", err
	}
	if input.CodeChallenge != "" {
		if err := ValidateCodeChallenge(input.CodeChallenge, input.CodeChallengeMethod); err != nil {
			return "", "", err
		}
	}
	provider, err := m.GetProvider(input.Provider)
	if err != nil {
		return "", "", err
	}

	state, err := m.GenerateState(ctx, &StateData{
		Provider:            input.Provider,
		RedirectURL:         input.RedirectURL,
		OrganizationID:      input.OrganizationID,
		InviteCode:          input.InviteCode,
		AppCode:             input.AppCode,
		CodeChallenge:       input.CodeChallenge,
		CodeChallengeMethod: input.CodeChallengeMethod,
	})
	if err != nil {
		return "", "", err
	}

	return provider.GetAuthURL(state, input.RedirectURL), state, nil
}

// GetCustomAuthURL generates an authorization URL for a custom provider.
// AUDIT 1.13: same redirect-allowlist check as GetAuthURL. AUDIT C2: same
// PKCE-initiation path.
func (m *Manager) GetCustomAuthURL(ctx context.Context, input AuthURLInput) (string, string, error) {
	if err := m.validateRedirectURL(input.RedirectURL); err != nil {
		return "", "", err
	}
	if input.CodeChallenge != "" {
		if err := ValidateCodeChallenge(input.CodeChallenge, input.CodeChallengeMethod); err != nil {
			return "", "", err
		}
	}
	provider, err := m.GetCustomProvider(input.CustomProvider)
	if err != nil {
		return "", "", err
	}

	state, err := m.GenerateState(ctx, &StateData{
		Provider:            types.AuthProviderCustom,
		CustomProvider:      input.CustomProvider,
		RedirectURL:         input.RedirectURL,
		OrganizationID:      input.OrganizationID,
		InviteCode:          input.InviteCode,
		AppCode:             input.AppCode,
		CodeChallenge:       input.CodeChallenge,
		CodeChallengeMethod: input.CodeChallengeMethod,
	})
	if err != nil {
		return "", "", err
	}

	return provider.GetAuthURL(state, input.RedirectURL), state, nil
}

// HandleCallback handles the OAuth callback
func (m *Manager) HandleCallback(ctx context.Context, state string, code string) (*UserInfo, *StateData, error) {
	// Validate state
	stateData, err := m.ValidateState(ctx, state)
	if err != nil {
		return nil, nil, errors.New(errors.ErrCodeSSOTokenInvalid, "invalid OAuth state", 400)
	}

	// Get provider
	var provider Provider
	if stateData.Provider == types.AuthProviderCustom {
		provider, err = m.GetCustomProvider(stateData.CustomProvider)
	} else {
		provider, err = m.GetProvider(stateData.Provider)
	}
	if err != nil {
		return nil, nil, err
	}

	// Exchange code for tokens
	tokenResp, err := provider.ExchangeCode(ctx, code, stateData.RedirectURL)
	if err != nil {
		return nil, nil, err
	}

	// Get user info
	var userInfo *UserInfo

	// Try ID token first (for OIDC providers)
	if tokenResp.IDToken != "" {
		userInfo, err = provider.ValidateIDToken(ctx, tokenResp.IDToken)
		if err != nil {
			// Fall back to user info endpoint
			userInfo, err = provider.GetUserInfo(ctx, tokenResp.AccessToken)
		}
	} else {
		userInfo, err = provider.GetUserInfo(ctx, tokenResp.AccessToken)
	}

	if err != nil {
		return nil, nil, err
	}

	return userInfo, stateData, nil
}

// SSOProviderInfo represents information about an SSO provider
type SSOProviderInfo struct {
	Name    string             `json:"name"`
	Type    types.AuthProvider `json:"type"`
	Enabled bool               `json:"enabled"`
}

// GetProviderInfo returns information about all configured providers
func (m *Manager) GetProviderInfo() []SSOProviderInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var info []SSOProviderInfo

	providerNames := map[types.AuthProvider]string{
		types.AuthProviderGoogle:    "Google",
		types.AuthProviderApple:     "Apple",
		types.AuthProviderMicrosoft: "Microsoft",
		types.AuthProviderGitHub:    "GitHub",
		types.AuthProviderFacebook:  "Facebook",
		types.AuthProviderLinkedIn:  "LinkedIn",
	}

	for providerType, provider := range m.providers {
		info = append(info, SSOProviderInfo{
			Name:    providerNames[providerType],
			Type:    providerType,
			Enabled: provider.IsEnabled(),
		})
	}

	for name, provider := range m.customProviders {
		info = append(info, SSOProviderInfo{
			Name:    name,
			Type:    types.AuthProviderCustom,
			Enabled: provider.IsEnabled(),
		})
	}

	return info
}

// ProviderInfoJSON returns provider info as JSON
func (m *Manager) ProviderInfoJSON() ([]byte, error) {
	return json.Marshal(m.GetProviderInfo())
}
