// Package dto provides Data Transfer Objects for the API
package dto

import (
	"github.com/rw3iss/auth/internal/domain"
	"github.com/rw3iss/auth/pkg/shared/types"
)

// RegisterRequest represents a registration request
type RegisterRequest struct {
	Email            string `json:"email" validate:"required,email"`
	Password         string `json:"password" validate:"required,min=8"`
	FirstName        string `json:"first_name" validate:"required"`
	LastName         string `json:"last_name" validate:"required"`
	Phone            string `json:"phone,omitempty"`
	DisplayName      string `json:"display_name,omitempty"`
	OrganizationName string `json:"organization_name,omitempty"`
	InviteCode       string `json:"invite_code,omitempty"`
	InviteToken      string `json:"invite_token,omitempty"`
	// AppCode applies the target app's registration policy
	// (allowed_email_domains, allowed_auth_methods, default_organization_id).
	// See migrations/013_*.up.sql. Empty falls back to AUTH_DEFAULT_APP_CODE.
	AppCode string `json:"app_code,omitempty"`
	// Mode: "register" (default), "register_or_login", "register_or_return"
	// — see service.RegistrationMode. AUDIT 8.1.
	Mode string `json:"mode,omitempty"`
	// §7 provisioning overrides. RoleCode overrides the app's
	// default_role_code for the default-org membership (validated server-side
	// as an org-scoped role). LinkedAppCodes overrides the app's
	// linked_app_codes. Both fall back to the app config when omitted.
	RoleCode       string   `json:"role_code,omitempty"`
	LinkedAppCodes []string `json:"linked_app_codes,omitempty"`
}

// RegisterResponse represents a registration response. When the request
// used register_or_login mode and the email already existed, LoggedIn is
// true and Tokens is populated so the client can treat this like a login.
type RegisterResponse struct {
	User                  *UserResponse         `json:"user"`
	Organization          *OrganizationResponse `json:"organization,omitempty"`
	VerificationEmailSent bool                  `json:"verification_email_sent"`
	LoggedIn              bool                  `json:"logged_in,omitempty"`
	Tokens                *TokenResponse        `json:"tokens,omitempty"`
}

// LoginRequest represents a login request
type LoginRequest struct {
	Email          string `json:"email" validate:"required,email"`
	Password       string `json:"password" validate:"required"`
	OrganizationID string `json:"organization_id,omitempty"`
	// AppCode scopes the issued token to a registered consuming app
	// (AUDIT 8.3). Required by default; falls back to AUTH_DEFAULT_APP_CODE
	// or AUTH_ALLOW_BASE_USER_LOGIN per server config.
	AppCode    string `json:"app_code,omitempty"`
	RememberMe bool   `json:"remember_me,omitempty"`
	// TwoFactorCode is the 6-digit TOTP for accounts with 2FA active
	// (AUDIT C4). Omit on the first attempt; the server responds 401 with
	// `{requires_2fa: true}` and the client retries with this set.
	TwoFactorCode string `json:"two_factor_code,omitempty"`
	// §7 provisioning overrides, applied only when the app auto-grants on
	// first contact (new / JIT-migrated / un-granted user). RoleCode is
	// validated server-side as an org-scoped role — no privilege escalation.
	RoleCode       string   `json:"role_code,omitempty"`
	LinkedAppCodes []string `json:"linked_app_codes,omitempty"`
	// CookieMode additionally writes the session as HttpOnly + Secure cookies
	// (middleware/cookie.go). Tokens are STILL returned in the body — the two are
	// not exclusive, and a client that asked for cookies usually also holds a
	// bearer copy for its API calls.
	//
	// This is what makes the server usable as a FedCM identity provider: the
	// browser calls the accounts endpoint itself and has no way to attach an
	// Authorization header, so a cookie is the only credential it can present.
	CookieMode bool `json:"cookie_mode,omitempty"`
}

// LoginResponse represents a login response. When RequiresTwoFactor is true
// (AUDIT C4), Tokens is nil and the caller must retry /auth/login with the
// `two_factor_code` field populated.
type LoginResponse struct {
	User              *UserResponse         `json:"user,omitempty"`
	Organization      *OrganizationResponse `json:"organization,omitempty"`
	Tokens            *TokenResponse        `json:"tokens,omitempty"`
	Roles             []string              `json:"roles,omitempty"`
	Permissions       []string              `json:"permissions,omitempty"`
	RequiresTwoFactor bool                  `json:"requires_2fa,omitempty"`
}

// HardDeleteUserRequest carries the operator-supplied reason for a
// destructive user delete (AUDIT C8). Reason is required so the audit
// log records why, not just who/whom.
type HardDeleteUserRequest struct {
	Reason string `json:"reason" validate:"required"`
}

// ImpersonateRequest carries the operator-supplied reason for an
// impersonation. Required so the audit log records why, not just who/whom
// (AUDIT C7).
type ImpersonateRequest struct {
	Reason string `json:"reason" validate:"required"`
}

// TwoFactorSetupRequest is an empty body — the server only needs the caller's
// authenticated identity to enroll. Kept as a typed struct for symmetry.
type TwoFactorSetupRequest struct{}

// TwoFactorSetupResponse delivers the QR-renderable provisioning URI plus
// the raw base32 secret (for manual entry into the authenticator app).
type TwoFactorSetupResponse struct {
	Secret          string `json:"secret"`
	ProvisioningURI string `json:"provisioning_uri"`
}

// TwoFactorEnableRequest carries the first TOTP code the user transcribes
// from their authenticator after scanning the QR.
type TwoFactorEnableRequest struct {
	Code string `json:"code" validate:"required"`
}

// TwoFactorDisableRequest re-prompts password + code so a stolen access
// token alone can't strip 2FA off an account.
type TwoFactorDisableRequest struct {
	Password string `json:"password" validate:"required"`
	Code     string `json:"code" validate:"required"`
}

// TokenResponse represents tokens in the response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	ExpiresAt    string `json:"expires_at"`
}

// RefreshTokenRequest represents a token refresh request
type RefreshTokenRequest struct {
	RefreshToken   string `json:"refresh_token" validate:"required"`
	OrganizationID string `json:"organization_id,omitempty"`
}

// SSOAuthURLRequest represents a request to get SSO auth URL. AUDIT C2 added
// the optional PKCE fields — when both are present the resulting flow defers
// token issuance to /auth/sso/exchange.
type SSOAuthURLRequest struct {
	Provider       string `json:"provider" validate:"required"`
	RedirectURL    string `json:"redirect_url" validate:"required,url"`
	OrganizationID string `json:"organization_id,omitempty"`
	InviteCode     string `json:"invite_code,omitempty"`
	// AppCode scopes the SSO flow to a consuming app's user pool(s). Usually
	// supplied via the X-App-Code header; this body field is a fallback.
	AppCode string `json:"app_code,omitempty"`
	// PKCE (RFC 7636). CodeChallenge is BASE64URL(SHA256(verifier)) when
	// CodeChallengeMethod is "S256" — the only method server-side accepts.
	// Both fields are required-together or absent-together.
	CodeChallenge       string `json:"code_challenge,omitempty"`
	CodeChallengeMethod string `json:"code_challenge_method,omitempty"`
}

// SSOAuthURLResponse represents the SSO auth URL response
type SSOAuthURLResponse struct {
	AuthURL string `json:"auth_url"`
	State   string `json:"state"`
}

// SSOCallbackRequest represents an SSO callback request
type SSOCallbackRequest struct {
	Provider       string `json:"provider" validate:"required"`
	Code           string `json:"code" validate:"required"`
	State          string `json:"state" validate:"required"`
	OrganizationID string `json:"organization_id,omitempty"`
	InviteCode     string `json:"invite_code,omitempty"`
	// AppCode is a callback-time fallback for the app context (the
	// authoritative value rides in the SSO state).
	AppCode string `json:"app_code,omitempty"`
	// AppleUser is the raw JSON Apple posts in the `user` form field on the
	// first authorization (form_post). Carries the user's name once.
	AppleUser string `json:"user,omitempty"`
}

// SSOAuthCodeResponse is the callback response when PKCE is in flight (AUDIT
// C2). The public client must POST {auth_code, code_verifier} to
// /auth/sso/exchange within ExpiresIn seconds to obtain the token pair.
type SSOAuthCodeResponse struct {
	AuthCode  string `json:"auth_code"`
	ExpiresIn int64  `json:"expires_in"` // seconds
}

// SSOExchangeRequest redeems a PKCE auth_code for an access/refresh token
// pair. The verifier must be the same opaque secret the client used to
// derive the code_challenge it submitted at /auth/sso/url.
type SSOExchangeRequest struct {
	AuthCode     string `json:"auth_code" validate:"required"`
	CodeVerifier string `json:"code_verifier" validate:"required"`
}

// RequestPasswordResetRequest represents a password reset request
type RequestPasswordResetRequest struct {
	Email string `json:"email" validate:"required,email"`
	// AppCode identifies the calling app so the reset email link can
	// point back at that app's frontend (apps.frontend_url). Optional;
	// when empty the email layer falls back to CLIENT_URL.
	AppCode string `json:"app_code,omitempty"`
}

// ResetPasswordRequest represents the actual password reset
type ResetPasswordRequest struct {
	Token       string `json:"token" validate:"required"`
	NewPassword string `json:"new_password" validate:"required,min=8"`
}

// ChangePasswordRequest represents a password change request
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required"`
	NewPassword     string `json:"new_password" validate:"required,min=8"`
}

// VerifyEmailRequest represents an email verification request
type VerifyEmailRequest struct {
	Token string `json:"token" validate:"required"`
}

// ResendVerificationEmailRequest re-issues the email-verification link
// for an unverified account (AUDIT 5.4). Server-side rate-limited; the
// response is always 200 to avoid revealing email existence.
type ResendVerificationEmailRequest struct {
	Email string `json:"email" validate:"required,email"`
	// AppCode identifies the calling app so the verify-email link can
	// point back at that app's frontend (apps.frontend_url). Optional;
	// when empty the email layer falls back to CLIENT_URL.
	AppCode string `json:"app_code,omitempty"`
}

// LogoutRequest represents a logout request
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// ValidateTokenRequest represents a token validation request
type ValidateTokenRequest struct {
	Token string `json:"token" validate:"required"`
}

// ValidateTokenResponse represents a token validation response
type ValidateTokenResponse struct {
	Valid       bool     `json:"valid"`
	UserID      string   `json:"user_id,omitempty"`
	Email       string   `json:"email,omitempty"`
	OrgID       string   `json:"organization_id,omitempty"`
	Roles       []string `json:"roles,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	ExpiresAt   string   `json:"expires_at,omitempty"`
}

// SessionResponse represents a session in the response
type SessionResponse struct {
	ID             string `json:"id"`
	DeviceInfo     string `json:"device_info,omitempty"`
	IPAddress      string `json:"ip_address,omitempty"`
	UserAgent      string `json:"user_agent,omitempty"`
	Location       string `json:"location,omitempty"`
	LastActivityAt string `json:"last_activity_at"`
	CreatedAt      string `json:"created_at"`
	IsCurrent      bool   `json:"is_current,omitempty"`
}

// ToSessionResponse converts a domain session to response
func ToSessionResponse(session *domain.Session, currentSessionID *types.ID) *SessionResponse {
	resp := &SessionResponse{
		ID:             session.ID.String(),
		DeviceInfo:     session.DeviceInfo,
		IPAddress:      session.IPAddress,
		UserAgent:      session.UserAgent,
		Location:       session.Location,
		LastActivityAt: session.LastActivityAt.Format("2006-01-02T15:04:05Z07:00"),
		CreatedAt:      session.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	if currentSessionID != nil && session.ID == *currentSessionID {
		resp.IsCurrent = true
	}

	return resp
}

// SSOProviderResponse represents an SSO provider info
type SSOProviderResponse struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Enabled bool   `json:"enabled"`
}
