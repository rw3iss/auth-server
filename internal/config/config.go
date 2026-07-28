// Package config provides configuration management for the auth service
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all configuration for the auth service
type Config struct {
	Server             ServerConfig
	Database           DatabaseConfig
	JWT                JWTConfig
	Audit              AuditConfig
	CognitoMigration   CognitoMigrationConfig
	GlobalSkuMigration GlobalSkuMigrationConfig
	Auth               AuthConfig
	SSO                SSOConfig
	Email              EmailConfig
	Redis              RedisConfig
	Security           SecurityConfig
}

// ServerConfig holds server configuration
type ServerConfig struct {
	Host            string
	Port            int
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	ShutdownTimeout time.Duration
	CORSOrigins     []string
	Environment     string // development, staging, production
	APIPrefix       string // Route prefix, e.g. "/api/v1" (default: "")
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	Host            string
	Port            int
	User            string
	Password        string
	Name            string
	SSLMode         string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

// DSN returns the database connection string
func (c *DatabaseConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.Name, c.SSLMode,
	)
}

// JWTConfig holds JWT configuration
type JWTConfig struct {
	AccessTokenSecret  string
	RefreshTokenSecret string
	// AccessTokenSecretPrevious / RefreshTokenSecretPrevious — AUDIT C5,
	// zero-downtime JWT secret rotation. When set, validators accept
	// tokens signed under EITHER the active secret or the previous one.
	// Signing always uses the active secret. The intended workflow:
	//
	//   1. Operator generates a new secret. Sets it as JWT_ACCESS_SECRET
	//      and moves the current one into JWT_ACCESS_SECRET_PREVIOUS.
	//   2. Rolling-restart all replicas. New tokens are signed under the
	//      new secret; outstanding tokens continue to validate against
	//      the previous slot until they expire.
	//   3. After max-token-lifetime has elapsed (refresh 7d or 30d with
	//      remember_me), operator clears JWT_ACCESS_SECRET_PREVIOUS and
	//      restarts. Rotation complete.
	//
	// Empty (the default) means rotation is not in progress.
	AccessTokenSecretPrevious  string
	RefreshTokenSecretPrevious string
	AccessTokenExpiry          time.Duration
	RefreshTokenExpiry         time.Duration
	RememberMeExpiry           time.Duration
	// RefreshIdleTimeout — server-side inactivity policy on the refresh
	// chain. When > 0, /auth/refresh rejects (and family-revokes) any
	// refresh presentation whose row was created more than this far in
	// the past. created_at is the right anchor because rotation makes
	// each row's "age" equal to "time since the previous refresh", so
	// the check naturally measures inactivity of the whole chain. A
	// stolen refresh token sitting unused past the threshold is dead
	// even if the JWT signature would still validate.
	//
	// Pairs with the SDK's auto-refresh: an actively-used app refreshes
	// every ~14 minutes, well under any sensible idle threshold; an
	// idle/closed app stops refreshing, ages out, and the next attempt
	// is rejected. Default 0 = disabled (Phase-1 behavior preserved).
	RefreshIdleTimeout time.Duration
	Issuer             string
	Audience           []string
	SigningMethod      string
}

// AuthConfig holds authentication configuration
type AuthConfig struct {
	PasswordMinLength       int
	PasswordMaxLength       int
	PasswordRequireUpper    bool
	PasswordRequireLower    bool
	PasswordRequireDigit    bool
	PasswordRequireSpecial  bool
	MaxLoginAttempts        int
	LockoutDuration         time.Duration
	PasswordResetExpiry     time.Duration
	EmailVerificationExpiry time.Duration
	InvitationExpiry        time.Duration
	SessionTimeout          time.Duration

	// AUDIT 1.17 — per-account rate limit, separate from per-IP. An
	// attacker with a botnet (one attempt per IP) can iterate every
	// popular password against a known email indefinitely; the per-account
	// counter caps total failures per email-window regardless of source IP.
	AccountAttemptsLimit  int           // max failed logins per window (default 20)
	AccountAttemptsWindow time.Duration // window (default 1h)

	// AUDIT 8.3 — App scoping. AllowBaseUserLogin enables the "no app
	// context" login mode for tracking/form-submission contexts where the
	// caller just wants to identify a user without scoping to a
	// registered application. Default false — fail-shut so production
	// always requires an app_code.
	AllowBaseUserLogin bool

	// DefaultAppCode, when set, is used as the implicit app_code when a
	// /auth/login request omits one. Lets us preserve backward-compat for
	// callers that haven't been updated yet. Empty (default) means
	// "require app_code on every login" unless AllowBaseUserLogin is true.
	DefaultAppCode string
}

// SSOConfig holds SSO provider configurations
type SSOConfig struct {
	Google    OAuthProviderConfig
	Apple     OAuthProviderConfig
	Microsoft OAuthProviderConfig
	GitHub    OAuthProviderConfig
	Facebook  OAuthProviderConfig
	LinkedIn  OAuthProviderConfig
	X         OAuthProviderConfig
	Custom    map[string]OAuthProviderConfig
	// AllowedRedirectURLs is the allowlist for /auth/sso/url. AUDIT 1.13:
	// without an allowlist, an attacker can request an SSO URL pointing
	// back to attacker-controlled origin. Each entry is an exact match,
	// or a prefix match when terminated with `*`.
	AllowedRedirectURLs []string
}

// OAuthProviderConfig holds configuration for an OAuth provider
type OAuthProviderConfig struct {
	Enabled      bool
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	AuthURL      string
	TokenURL     string
	UserInfoURL  string

	// Apple-specific. "Sign in with Apple" doesn't use a static
	// ClientSecret; the secret is an ES256 JWT signed with a .p8 key,
	// regenerated per token request. ClientID is the Apple *Service ID*.
	//   - TeamID:     Apple Developer Team ID (the JWT `iss`).
	//   - KeyID:      the .p8 key's Key ID (the JWT header `kid`).
	//   - PrivateKey: the PKCS#8 PEM contents of the .p8 (multiline or
	//                 base64-encoded; the provider decodes both).
	TeamID     string
	KeyID      string
	PrivateKey string
}

// EmailConfig holds email configuration
type EmailConfig struct {
	Provider      string // smtp, sendgrid, ses, mailgun
	FromAddress   string
	FromName      string
	SMTPHost      string
	SMTPPort      int
	SMTPUser      string
	SMTPPassword  string
	SMTPSecure    bool
	APIKey        string // For SendGrid, Mailgun, etc.
	TemplatesPath string
}

// RedisConfig holds Redis configuration
type RedisConfig struct {
	Host         string
	Port         int
	Password     string
	DB           int
	PoolSize     int
	MinIdleConns int
}

// Address returns the Redis address
func (c *RedisConfig) Address() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// CognitoMigrationConfig configures the optional legacy-Cognito
// auto-migration adapter (B7b). When Enabled=false (default), AuthService
// runs without any awareness of Cognito.
type CognitoMigrationConfig struct {
	Enabled      bool
	Region       string
	UserPoolID   string
	ClientID     string
	ClientSecret string // optional, only when app client has a secret
}

// GlobalSkuMigrationConfig configures the optional GlobalSKU JIT legacy
// migration adapter (§5.1). When Enabled=false (default), no GlobalSKU
// provider is registered and the JIT path is a no-op for the globalsku app.
// VerifySecret is the shared HMAC secret gating GlobalSKU's signed
// verify-legacy-password endpoint (NOT a password-hashing key).
type GlobalSkuMigrationConfig struct {
	Enabled      bool
	BaseURL      string
	VerifySecret string
}

// AuditConfig configures the audit-log writer.
type AuditConfig struct {
	// Enabled toggles writes. Off-by-default for tests; production should
	// always have this on. Can be flipped at runtime via the writer's
	// SetEnabled hook once we expose an admin endpoint for it.
	Enabled bool
	// BufferSize bounds the in-memory queue. Overflow drops events with a
	// dropped-counter metric so operators see silent loss.
	BufferSize int
}

// SecurityConfig holds security configuration
type SecurityConfig struct {
	RateLimitRequests int           // Requests per window
	RateLimitWindow   time.Duration // Time window for rate limiting
	BcryptCost        int
	CSRFEnabled       bool
	CSRFSecret        string
	// TrustedProxies is the list of CIDR ranges from which we will honor
	// X-Forwarded-For. AUDIT 1.15. Empty list (the default) means "ignore
	// XFF entirely" — the safest default for servers that aren't behind a
	// known reverse proxy.
	TrustedProxies []string
}

// Load loads configuration from environment variables
func Load() (*Config, error) {
	cfg := &Config{
		Server: ServerConfig{
			Host:            getEnv("SERVER_HOST", "0.0.0.0"),
			Port:            getEnvAsInt("SERVER_PORT", 8080),
			ReadTimeout:     getEnvAsDuration("SERVER_READ_TIMEOUT", 15*time.Second),
			WriteTimeout:    getEnvAsDuration("SERVER_WRITE_TIMEOUT", 15*time.Second),
			ShutdownTimeout: getEnvAsDuration("SERVER_SHUTDOWN_TIMEOUT", 30*time.Second),
			CORSOrigins:     getEnvAsSlice("CORS_ORIGINS", []string{"*"}),
			Environment:     getEnv("ENVIRONMENT", "development"),
			APIPrefix:       getEnv("API_PREFIX", ""),
		},
		Database: DatabaseConfig{
			Host:            getEnv("DB_HOST", "localhost"),
			Port:            getEnvAsInt("DB_PORT", 5432),
			User:            getEnv("DB_USER", "postgres"),
			Password:        getEnv("DB_PASSWORD", ""),
			Name:            getEnv("DB_NAME", "auth"),
			SSLMode:         getEnv("DB_SSL_MODE", "disable"),
			MaxOpenConns:    getEnvAsInt("DB_MAX_OPEN_CONNS", 25),
			MaxIdleConns:    getEnvAsInt("DB_MAX_IDLE_CONNS", 5),
			ConnMaxLifetime: getEnvAsDuration("DB_CONN_MAX_LIFETIME", 5*time.Minute),
		},
		JWT: JWTConfig{
			AccessTokenSecret:          getEnv("JWT_ACCESS_SECRET", ""),
			RefreshTokenSecret:         getEnv("JWT_REFRESH_SECRET", ""),
			AccessTokenSecretPrevious:  getEnv("JWT_ACCESS_SECRET_PREVIOUS", ""),
			RefreshTokenSecretPrevious: getEnv("JWT_REFRESH_SECRET_PREVIOUS", ""),
			AccessTokenExpiry:          getEnvAsDuration("JWT_ACCESS_EXPIRY", 15*time.Minute),
			RefreshTokenExpiry:         getEnvAsDuration("JWT_REFRESH_EXPIRY", 7*24*time.Hour),
			RememberMeExpiry:           getEnvAsDuration("JWT_REMEMBER_ME_EXPIRY", 30*24*time.Hour),
			RefreshIdleTimeout:         getEnvAsDuration("AUTH_REFRESH_IDLE_TIMEOUT", 0),
			Issuer:                     getEnv("JWT_ISSUER", "ven-auth"),
			Audience:                   getEnvAsSlice("JWT_AUDIENCE", []string{"ven-platform"}),
			SigningMethod:              getEnv("JWT_SIGNING_METHOD", "HS256"),
		},
		Auth: AuthConfig{
			PasswordMinLength:       getEnvAsInt("AUTH_PASSWORD_MIN_LENGTH", 8),
			PasswordMaxLength:       getEnvAsInt("AUTH_PASSWORD_MAX_LENGTH", 128),
			PasswordRequireUpper:    getEnvAsBool("AUTH_PASSWORD_REQUIRE_UPPER", true),
			PasswordRequireLower:    getEnvAsBool("AUTH_PASSWORD_REQUIRE_LOWER", true),
			PasswordRequireDigit:    getEnvAsBool("AUTH_PASSWORD_REQUIRE_DIGIT", true),
			PasswordRequireSpecial:  getEnvAsBool("AUTH_PASSWORD_REQUIRE_SPECIAL", false),
			MaxLoginAttempts:        getEnvAsInt("AUTH_MAX_LOGIN_ATTEMPTS", 7),
			LockoutDuration:         getEnvAsDuration("AUTH_LOCKOUT_DURATION", 5*time.Minute),
			PasswordResetExpiry:     getEnvAsDuration("AUTH_PASSWORD_RESET_EXPIRY", 1*time.Hour),
			EmailVerificationExpiry: getEnvAsDuration("AUTH_EMAIL_VERIFICATION_EXPIRY", 24*time.Hour),
			InvitationExpiry:        getEnvAsDuration("AUTH_INVITATION_EXPIRY", 7*24*time.Hour),
			SessionTimeout:          getEnvAsDuration("AUTH_SESSION_TIMEOUT", 24*time.Hour),
			AccountAttemptsLimit:    getEnvAsInt("AUTH_ACCOUNT_ATTEMPTS_LIMIT", 20),
			AccountAttemptsWindow:   getEnvAsDuration("AUTH_ACCOUNT_ATTEMPTS_WINDOW", time.Hour),
			AllowBaseUserLogin:      getEnvAsBool("AUTH_ALLOW_BASE_USER_LOGIN", false),
			DefaultAppCode:          getEnv("AUTH_DEFAULT_APP_CODE", ""),
		},
		SSO: SSOConfig{
			Google: OAuthProviderConfig{
				Enabled:      getEnvAsBool("SSO_GOOGLE_ENABLED", false),
				ClientID:     getEnv("SSO_GOOGLE_CLIENT_ID", ""),
				ClientSecret: getEnv("SSO_GOOGLE_CLIENT_SECRET", ""),
				RedirectURL:  getEnv("SSO_GOOGLE_REDIRECT_URL", ""),
				Scopes:       getEnvAsSlice("SSO_GOOGLE_SCOPES", []string{"openid", "email", "profile"}),
			},
			Apple: OAuthProviderConfig{
				Enabled:      getEnvAsBool("SSO_APPLE_ENABLED", false),
				ClientID:     getEnv("SSO_APPLE_CLIENT_ID", ""),
				ClientSecret: getEnv("SSO_APPLE_CLIENT_SECRET", ""),
				RedirectURL:  getEnv("SSO_APPLE_REDIRECT_URL", ""),
				Scopes:       getEnvAsSlice("SSO_APPLE_SCOPES", []string{"name", "email"}),
				TeamID:       getEnv("SSO_APPLE_TEAM_ID", ""),
				KeyID:        getEnv("SSO_APPLE_KEY_ID", ""),
				PrivateKey:   getEnv("SSO_APPLE_PRIVATE_KEY", ""),
			},
			Microsoft: OAuthProviderConfig{
				Enabled:      getEnvAsBool("SSO_MICROSOFT_ENABLED", false),
				ClientID:     getEnv("SSO_MICROSOFT_CLIENT_ID", ""),
				ClientSecret: getEnv("SSO_MICROSOFT_CLIENT_SECRET", ""),
				RedirectURL:  getEnv("SSO_MICROSOFT_REDIRECT_URL", ""),
				Scopes:       getEnvAsSlice("SSO_MICROSOFT_SCOPES", []string{"openid", "email", "profile"}),
			},
			GitHub: OAuthProviderConfig{
				Enabled:      getEnvAsBool("SSO_GITHUB_ENABLED", false),
				ClientID:     getEnv("SSO_GITHUB_CLIENT_ID", ""),
				ClientSecret: getEnv("SSO_GITHUB_CLIENT_SECRET", ""),
				RedirectURL:  getEnv("SSO_GITHUB_REDIRECT_URL", ""),
				Scopes:       getEnvAsSlice("SSO_GITHUB_SCOPES", []string{"user:email"}),
			},
			Facebook: OAuthProviderConfig{
				Enabled:      getEnvAsBool("SSO_FACEBOOK_ENABLED", false),
				ClientID:     getEnv("SSO_FACEBOOK_CLIENT_ID", ""),
				ClientSecret: getEnv("SSO_FACEBOOK_CLIENT_SECRET", ""),
				RedirectURL:  getEnv("SSO_FACEBOOK_REDIRECT_URL", ""),
				Scopes:       getEnvAsSlice("SSO_FACEBOOK_SCOPES", []string{"email", "public_profile"}),
			},
			LinkedIn: OAuthProviderConfig{
				Enabled:      getEnvAsBool("SSO_LINKEDIN_ENABLED", false),
				ClientID:     getEnv("SSO_LINKEDIN_CLIENT_ID", ""),
				ClientSecret: getEnv("SSO_LINKEDIN_CLIENT_SECRET", ""),
				RedirectURL:  getEnv("SSO_LINKEDIN_REDIRECT_URL", ""),
				Scopes:       getEnvAsSlice("SSO_LINKEDIN_SCOPES", []string{"openid", "profile", "email"}),
			},
			// X ("Login with X" / Twitter OAuth 2.0). Confidential client:
			// ClientSecret is the app's OAuth 2.0 Client Secret (Basic auth on
			// the token leg). X mandates PKCE; offline.access yields a
			// refresh_token. Default scopes are the minimal identity set.
			X: OAuthProviderConfig{
				Enabled:      getEnvAsBool("SSO_X_ENABLED", false),
				ClientID:     getEnv("SSO_X_CLIENT_ID", ""),
				ClientSecret: getEnv("SSO_X_CLIENT_SECRET", ""),
				RedirectURL:  getEnv("SSO_X_REDIRECT_URL", ""),
				Scopes:       getEnvAsSlice("SSO_X_SCOPES", []string{"tweet.read", "users.read", "offline.access"}),
			},
			Custom:              make(map[string]OAuthProviderConfig),
			AllowedRedirectURLs: getEnvAsSlice("SSO_ALLOWED_REDIRECT_URLS", []string{}),
		},
		Email: EmailConfig{
			Provider:      getEnv("EMAIL_PROVIDER", "smtp"),
			FromAddress:   getEnv("EMAIL_FROM_ADDRESS", "noreply@example.com"),
			FromName:      getEnv("EMAIL_FROM_NAME", "rw3iss Auth"),
			SMTPHost:      getEnv("SMTP_HOST", "localhost"),
			SMTPPort:      getEnvAsInt("SMTP_PORT", 587),
			SMTPUser:      getEnv("SMTP_USER", ""),
			SMTPPassword:  getEnv("SMTP_PASSWORD", ""),
			SMTPSecure:    getEnvAsBool("SMTP_SECURE", true),
			APIKey:        getEnv("EMAIL_API_KEY", ""),
			TemplatesPath: getEnv("EMAIL_TEMPLATES_PATH", "./templates/email"),
		},
		Redis: RedisConfig{
			Host:         getEnv("REDIS_HOST", "localhost"),
			Port:         getEnvAsInt("REDIS_PORT", 6379),
			Password:     getEnv("REDIS_PASSWORD", ""),
			DB:           getEnvAsInt("REDIS_DB", 0),
			PoolSize:     getEnvAsInt("REDIS_POOL_SIZE", 10),
			MinIdleConns: getEnvAsInt("REDIS_MIN_IDLE_CONNS", 2),
		},
		Security: SecurityConfig{
			RateLimitRequests: getEnvAsInt("RATE_LIMIT_REQUESTS", 100),
			RateLimitWindow:   getEnvAsDuration("RATE_LIMIT_WINDOW", 1*time.Minute),
			BcryptCost:        getEnvAsInt("BCRYPT_COST", 12),
			CSRFEnabled:       getEnvAsBool("CSRF_ENABLED", true),
			CSRFSecret:        getEnv("CSRF_SECRET", ""),
			TrustedProxies:    getEnvAsSlice("TRUSTED_PROXIES", []string{}),
		},
		Audit: AuditConfig{
			// Default ON so production gets coverage out of the box; tests
			// flip it OFF via env when they don't want audit noise.
			Enabled:    getEnvAsBool("AUDIT_ENABLED", true),
			BufferSize: getEnvAsInt("AUDIT_BUFFER_SIZE", 1024),
		},
		CognitoMigration: CognitoMigrationConfig{
			Enabled:      getEnvAsBool("COGNITO_AUTO_MIGRATE_ENABLED", false),
			Region:       getEnv("COGNITO_REGION", ""),
			UserPoolID:   getEnv("COGNITO_USER_POOL_ID", ""),
			ClientID:     getEnv("COGNITO_CLIENT_ID", ""),
			ClientSecret: getEnv("COGNITO_CLIENT_SECRET", ""),
		},
		GlobalSkuMigration: GlobalSkuMigrationConfig{
			Enabled:      getEnvAsBool("GLOBALSKU_LEGACY_MIGRATION_ENABLED", false),
			BaseURL:      getEnv("GLOBALSKU_BASE_URL", ""),
			VerifySecret: getEnv("GLOBALSKU_LEGACY_VERIFY_SECRET", ""),
		},
	}

	// Validate required fields
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// minJWTSecretLength is the floor accepted at boot. 32 bytes ≈ 256 bits
// matches HS256's recommended key length. Below this we refuse to start —
// see AUDIT 1.8.
const minJWTSecretLength = 32

// weakSecretDenylist catches the most common placeholders that ship in
// example .env files. Not exhaustive; an entropy heuristic would be stronger
// but this catches the embarrassing cases (`secret`, `changeme`, etc.).
var weakSecretDenylist = map[string]struct{}{
	"secret":     {},
	"changeme":   {},
	"change-me":  {},
	"changethis": {},
	"test":       {},
	"password":   {},
	"insecure":   {},
	"default":    {},
}

// Validate validates the configuration. Called from Load() before returning
// the Config — every failure here is fatal at boot, which is the right
// posture for credential and crypto config.
func (c *Config) Validate() error {
	// --- JWT secrets ---
	// AUDIT 1.8: enforce minimum strength and distinct secrets at boot. The
	// existing "non-empty" check let `JWT_ACCESS_SECRET=test` reach prod.
	if c.JWT.AccessTokenSecret == "" {
		return fmt.Errorf("JWT_ACCESS_SECRET is required")
	}
	if c.JWT.RefreshTokenSecret == "" {
		return fmt.Errorf("JWT_REFRESH_SECRET is required")
	}
	if len(c.JWT.AccessTokenSecret) < minJWTSecretLength {
		return fmt.Errorf("JWT_ACCESS_SECRET must be at least %d characters (HS256 key strength)", minJWTSecretLength)
	}
	if len(c.JWT.RefreshTokenSecret) < minJWTSecretLength {
		return fmt.Errorf("JWT_REFRESH_SECRET must be at least %d characters (HS256 key strength)", minJWTSecretLength)
	}
	if c.JWT.AccessTokenSecret == c.JWT.RefreshTokenSecret {
		return fmt.Errorf("JWT_ACCESS_SECRET and JWT_REFRESH_SECRET must differ")
	}
	if _, weak := weakSecretDenylist[strings.ToLower(c.JWT.AccessTokenSecret)]; weak {
		return fmt.Errorf("JWT_ACCESS_SECRET is a known weak value")
	}
	if _, weak := weakSecretDenylist[strings.ToLower(c.JWT.RefreshTokenSecret)]; weak {
		return fmt.Errorf("JWT_REFRESH_SECRET is a known weak value")
	}

	// --- JWT previous-slot secrets (rotation in progress) ---
	// AUDIT C5: when set, they must satisfy the same strength rules as the
	// active secret AND differ from it — sharing a value with the active
	// slot is either a typo or a no-op rotation that gains nothing.
	if err := validatePreviousSecret("JWT_ACCESS_SECRET_PREVIOUS", c.JWT.AccessTokenSecretPrevious, c.JWT.AccessTokenSecret); err != nil {
		return err
	}
	if err := validatePreviousSecret("JWT_REFRESH_SECRET_PREVIOUS", c.JWT.RefreshTokenSecretPrevious, c.JWT.RefreshTokenSecret); err != nil {
		return err
	}

	// --- Bcrypt cost ---
	// AUDIT 1.3: the BCRYPT_COST env was loaded but never used. Now that
	// HashPassword honors the value, validate it's in a sane range.
	if c.Security.BcryptCost < 10 || c.Security.BcryptCost > 14 {
		return fmt.Errorf("BCRYPT_COST=%d outside allowed range [10,14]", c.Security.BcryptCost)
	}

	// --- Password policy sanity ---
	if c.Auth.PasswordMinLength < 1 {
		return fmt.Errorf("AUTH_PASSWORD_MIN_LENGTH must be ≥1")
	}
	if c.Auth.PasswordMaxLength > 0 && c.Auth.PasswordMaxLength < c.Auth.PasswordMinLength {
		return fmt.Errorf("AUTH_PASSWORD_MAX_LENGTH (%d) must be ≥ AUTH_PASSWORD_MIN_LENGTH (%d)",
			c.Auth.PasswordMaxLength, c.Auth.PasswordMinLength)
	}

	// --- DB pool sanity ---
	if c.Database.MaxIdleConns > c.Database.MaxOpenConns {
		return fmt.Errorf("DB_MAX_IDLE_CONNS (%d) must be ≤ DB_MAX_OPEN_CONNS (%d)",
			c.Database.MaxIdleConns, c.Database.MaxOpenConns)
	}

	// --- Rate limit sanity ---
	if c.Security.RateLimitRequests < 1 {
		return fmt.Errorf("RATE_LIMIT_REQUESTS must be ≥1")
	}

	// --- CORS hardening in production ---
	// AUDIT 1.19: refuse the `*` wildcard in production. The CORS middleware
	// already disables credentials for wildcard matches (safer than before)
	// but in production we want explicit origin lists, period.
	if c.IsProduction() {
		for _, o := range c.Server.CORSOrigins {
			if o == "*" {
				return fmt.Errorf("CORS_ORIGINS=* is not allowed in production — set explicit origins")
			}
		}
	}

	return nil
}

// validatePreviousSecret enforces strength + distinctness on a rotation
// previous-slot secret. Empty is allowed (rotation not in progress); when
// set, it must clear the same bar as the active secret.
func validatePreviousSecret(envName, prev, active string) error {
	if prev == "" {
		return nil
	}
	if len(prev) < minJWTSecretLength {
		return fmt.Errorf("%s must be at least %d characters (HS256 key strength)", envName, minJWTSecretLength)
	}
	if _, weak := weakSecretDenylist[strings.ToLower(prev)]; weak {
		return fmt.Errorf("%s is a known weak value", envName)
	}
	if prev == active {
		return fmt.Errorf("%s must differ from its active counterpart — sharing values defeats rotation", envName)
	}
	return nil
}

// IsDevelopment returns true if running in development mode
func (c *Config) IsDevelopment() bool {
	return c.Server.Environment == "development"
}

// IsProduction returns true if running in production mode
func (c *Config) IsProduction() bool {
	return c.Server.Environment == "production"
}

// Helper functions

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	if value, exists := os.LookupEnv(key); exists {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvAsBool(key string, defaultValue bool) bool {
	if value, exists := os.LookupEnv(key); exists {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func getEnvAsDuration(key string, defaultValue time.Duration) time.Duration {
	if value, exists := os.LookupEnv(key); exists {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}

func getEnvAsSlice(key string, defaultValue []string) []string {
	if value, exists := os.LookupEnv(key); exists {
		if value != "" {
			// Simple comma-separated parsing
			result := []string{}
			current := ""
			for _, char := range value {
				if char == ',' {
					if current != "" {
						result = append(result, current)
						current = ""
					}
				} else {
					current += string(char)
				}
			}
			if current != "" {
				result = append(result, current)
			}
			return result
		}
	}
	return defaultValue
}
