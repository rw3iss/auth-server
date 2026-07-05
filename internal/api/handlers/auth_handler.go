// Package handlers provides HTTP request handlers for the API
package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/rw3iss/auth/internal/api/dto"
	"github.com/rw3iss/auth/internal/api/middleware"
	"github.com/rw3iss/auth/internal/logging"
	auth "github.com/rw3iss/auth/internal/service/auth"
	"github.com/rw3iss/auth/pkg/shared/errors"
	"github.com/rw3iss/auth/pkg/shared/types"
)

// AuthHandler handles authentication endpoints
type AuthHandler struct {
	authService *auth.AuthService
}

// NewAuthHandler creates a new auth handler
func NewAuthHandler(authService *auth.AuthService) *AuthHandler {
	return &AuthHandler{
		authService: authService,
	}
}

// Register handles user registration
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	// Read the body once so it can be decoded twice: into the typed
	// request AND into a generic map. The map preserves any EXTRA
	// fields the client sent (campaign tags, referral codes, …) for
	// pass-through to per-app webhooks (migration 019).
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, errors.InvalidInput("body", "Invalid request body"))
		return
	}
	var req dto.RegisterRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		writeError(w, errors.InvalidInput("body", "Invalid request body"))
		return
	}
	var raw map[string]any
	if err := json.Unmarshal(bodyBytes, &raw); err == nil && raw != nil {
		delete(raw, "password") // never forward secrets to webhooks
	}

	// AUDIT 8.1: detect service-auth on the request so the service decides
	// whether to allow ModeRegisterOrReturn. Public clients with no token
	// (or a non-system_admin token) get CallerIsService=false.
	callerIsService := false
	if claims := middleware.GetClaims(r.Context()); claims != nil && claims.HasRole("system_admin") {
		callerIsService = true
	}

	result, err := h.authService.Register(r.Context(), auth.RegisterInput{
		Email:            req.Email,
		Password:         req.Password,
		FirstName:        req.FirstName,
		LastName:         req.LastName,
		Phone:            req.Phone,
		DisplayName:      req.DisplayName,
		OrganizationName: req.OrganizationName,
		InviteCode:       req.InviteCode,
		InviteToken:      req.InviteToken,
		AppCode:          req.AppCode,
		RoleCode:         req.RoleCode,
		LinkedAppCodes:   req.LinkedAppCodes,
		Mode:             auth.RegistrationMode(req.Mode),
		CallerIsService:  callerIsService,
		Raw:              raw,
		ClientIP:         middleware.RealIP(r),
		UserAgent:        r.Header.Get("User-Agent"),
	})
	if err != nil {
		handleServiceError(w, err)
		return
	}

	resp := &dto.RegisterResponse{
		User:                  dto.ToUserResponse(result.User),
		VerificationEmailSent: result.VerificationEmailSent,
		LoggedIn:              result.LoggedIn,
	}
	if result.Organization != nil {
		resp.Organization = dto.ToOrganizationResponse(result.Organization)
	}
	if result.TokenPair != nil {
		resp.Tokens = &dto.TokenResponse{
			AccessToken:  result.TokenPair.AccessToken,
			RefreshToken: result.TokenPair.RefreshToken,
			TokenType:    result.TokenPair.TokenType,
			ExpiresIn:    result.TokenPair.ExpiresIn,
			ExpiresAt:    result.TokenPair.ExpiresAt.Format(time.RFC3339),
		}
	}

	// register_or_login returning an existing user is 200 (logged-in flow),
	// not 201 (created); a plain register stays 201.
	status := http.StatusCreated
	if result.LoggedIn {
		status = http.StatusOK
	}
	writeJSON(w, status, resp)
}

// Login handles user login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req dto.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.InvalidInput("body", "Invalid request body"))
		return
	}

	result, err := h.authService.Login(r.Context(), auth.LoginInput{
		Email:          req.Email,
		Password:       req.Password,
		OrganizationID: req.OrganizationID,
		AppCode:        req.AppCode,
		RememberMe:     req.RememberMe,
		TwoFactorCode:  req.TwoFactorCode,
		RoleCode:       req.RoleCode,
		LinkedAppCodes: req.LinkedAppCodes,
		DeviceInfo:     r.Header.Get("User-Agent"),
		IPAddress:      getClientIP(r),
		UserAgent:      r.Header.Get("User-Agent"),
	})
	if err != nil {
		handleServiceError(w, err)
		return
	}

	// AUDIT C4: 2FA challenge. Password authenticated but the user has 2FA
	// active. Respond 401 with `requires_2fa: true` and an otherwise-empty
	// body — client retries /auth/login with `two_factor_code` populated.
	if result.RequiresTwoFactor {
		writeJSON(w, http.StatusUnauthorized, &dto.LoginResponse{RequiresTwoFactor: true})
		return
	}

	resp := &dto.LoginResponse{
		User: dto.ToUserResponse(result.User),
		Tokens: &dto.TokenResponse{
			AccessToken:  result.TokenPair.AccessToken,
			RefreshToken: result.TokenPair.RefreshToken,
			TokenType:    result.TokenPair.TokenType,
			ExpiresIn:    result.TokenPair.ExpiresIn,
			ExpiresAt:    result.TokenPair.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
		},
		Roles:       result.Roles,
		Permissions: result.Permissions,
	}
	if result.Organization != nil {
		resp.Organization = dto.ToOrganizationResponse(result.Organization)
	}

	writeJSON(w, http.StatusOK, resp)
}

// DeleteMyAccount handles DELETE /me/account. Self-service hard-delete
// of the caller's own account. Requires:
//  1. A valid bearer token (authenticated route).
//  2. The user's current password in the body (service-layer enforced).
//  3. A typed confirmation of the literal string "DELETE" — defends
//     against a malicious bookmark/CSRF firing the endpoint silently.
//
// Soft-delete is intentionally not offered. If we keep the row around
// the user's email is still taken, which they didn't want.
func (h *AuthHandler) DeleteMyAccount(w http.ResponseWriter, r *http.Request) {
	uid := middleware.GetUserID(r.Context())
	if uid == nil {
		writeError(w, errors.Unauthorized("authentication required"))
		return
	}
	var req struct {
		Password     string `json:"password"`
		Confirmation string `json:"confirmation"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.InvalidInput("body", "invalid request body"))
		return
	}
	if req.Confirmation != "DELETE" {
		writeError(w, errors.InvalidInput("confirmation", "type DELETE to confirm"))
		return
	}
	if err := h.authService.DeleteMyAccount(r.Context(), auth.DeleteMyAccountInput{
		UserID:          *uid,
		CurrentPassword: req.Password,
	}); err != nil {
		handleServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// HardDeleteUser physically removes a user from the database (AUDIT C8).
// system_admin-only — routes mount this under systemAdminChain. The
// service layer enforces the self-delete + owned-org pre-flight gates.
func (h *AuthHandler) HardDeleteUser(w http.ResponseWriter, r *http.Request) {
	requesterID := middleware.GetUserID(r.Context())
	if requesterID == nil {
		writeError(w, errors.Unauthorized("Authentication required"))
		return
	}
	targetID, err := types.ParseID(r.PathValue("userId"))
	if err != nil {
		writeError(w, errors.InvalidInput("userId", "invalid user id"))
		return
	}
	var req dto.HardDeleteUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.InvalidInput("body", "invalid request body"))
		return
	}
	if req.Reason == "" {
		writeError(w, errors.InvalidInput("reason", "reason is required for hard-delete"))
		return
	}
	if err := h.authService.HardDeleteUser(r.Context(), auth.HardDeleteUserInput{
		RequesterID: *requesterID,
		TargetID:    targetID,
		Reason:      req.Reason,
	}); err != nil {
		handleServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Impersonate mints a token pair for the target user, stamped with the
// authenticated admin's id + email so subsequent actions are
// audit-traceable to the impersonator (AUDIT C7). Authorization is enforced
// in the service layer: system_admin / super_admin can impersonate anyone;
// org_admin can impersonate within their org. Self-impersonation and
// chained impersonation are refused.
func (h *AuthHandler) Impersonate(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		writeError(w, errors.Unauthorized("Authentication required"))
		return
	}
	targetID, err := types.ParseID(r.PathValue("userId"))
	if err != nil {
		writeError(w, errors.InvalidInput("userId", "invalid user id"))
		return
	}
	var req dto.ImpersonateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.InvalidInput("body", "invalid request body"))
		return
	}
	if req.Reason == "" {
		writeError(w, errors.InvalidInput("reason", "reason is required for impersonation"))
		return
	}

	result, err := h.authService.Impersonate(r.Context(), auth.ImpersonateInput{
		ActorClaims: claims,
		TargetID:    targetID,
		Reason:      req.Reason,
		DeviceInfo:  r.Header.Get("User-Agent"),
		IPAddress:   getClientIP(r),
		UserAgent:   r.Header.Get("User-Agent"),
	})
	if err != nil {
		handleServiceError(w, err)
		return
	}

	resp := &dto.LoginResponse{
		User: dto.ToUserResponse(result.User),
		Tokens: &dto.TokenResponse{
			AccessToken:  result.TokenPair.AccessToken,
			RefreshToken: result.TokenPair.RefreshToken,
			TokenType:    result.TokenPair.TokenType,
			ExpiresIn:    result.TokenPair.ExpiresIn,
			ExpiresAt:    result.TokenPair.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
		},
		Roles:       result.Roles,
		Permissions: result.Permissions,
	}
	if result.Organization != nil {
		resp.Organization = dto.ToOrganizationResponse(result.Organization)
	}
	writeJSON(w, http.StatusOK, resp)
}

// SetupTwoFactor begins TOTP enrollment for the authenticated user
// (AUDIT C4). Returns the provisioning URI + base32 secret; the client
// renders the QR locally so the secret never reaches a third-party
// QR-rendering service.
func (h *AuthHandler) SetupTwoFactor(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == nil {
		writeError(w, errors.Unauthorized("Authentication required"))
		return
	}
	result, err := h.authService.SetupTwoFactor(r.Context(), *userID)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, &dto.TwoFactorSetupResponse{
		Secret:          result.Secret,
		ProvisioningURI: result.ProvisioningURI,
	})
}

// EnableTwoFactor completes enrollment by verifying the first code.
func (h *AuthHandler) EnableTwoFactor(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == nil {
		writeError(w, errors.Unauthorized("Authentication required"))
		return
	}
	var req dto.TwoFactorEnableRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.InvalidInput("body", "Invalid request body"))
		return
	}
	if err := h.authService.VerifyAndEnableTwoFactor(r.Context(), *userID, req.Code); err != nil {
		handleServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// DisableTwoFactor turns 2FA off. Re-prompts password + current code.
func (h *AuthHandler) DisableTwoFactor(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == nil {
		writeError(w, errors.Unauthorized("Authentication required"))
		return
	}
	var req dto.TwoFactorDisableRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.InvalidInput("body", "Invalid request body"))
		return
	}
	if err := h.authService.DisableTwoFactor(r.Context(), *userID, req.Password, req.Code); err != nil {
		handleServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// RefreshToken handles token refresh
func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var req dto.RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.InvalidInput("body", "Invalid request body"))
		return
	}

	var orgID *types.ID
	if req.OrganizationID != "" {
		id, err := types.ParseID(req.OrganizationID)
		if err != nil {
			writeError(w, errors.InvalidInput("organization_id", "Invalid organization ID"))
			return
		}
		orgID = &id
	}

	tokenPair, err := h.authService.RefreshTokens(r.Context(), req.RefreshToken, orgID)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	resp := &dto.TokenResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		TokenType:    tokenPair.TokenType,
		ExpiresIn:    tokenPair.ExpiresIn,
		ExpiresAt:    tokenPair.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	writeJSON(w, http.StatusOK, resp)
}

// Logout revokes the current refresh token (AUDIT 1.22, 1.23).
//
// AUDIT 1.23 — the endpoint now requires authentication. Previously
// anyone with a stolen refresh token could trigger the revoke; combined
// with the silent error swallow this was effectively a CSRF-able
// logout primitive. The auth middleware now ensures the caller holds
// the corresponding access token; service-layer cross-check ensures
// the refresh token's user_id matches the access token's user_id.
//
// AUDIT 1.22 — failures are now logged with the request_id (via the
// context-aware logger) instead of being silently dropped. The endpoint
// still returns 200 success to the client either way: a logout that
// 404s server-side because the token was already revoked is
// semantically equivalent to a successful logout from the client's
// perspective.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	callerID := middleware.GetUserID(r.Context())
	if callerID == nil {
		writeError(w, errors.Unauthorized("Authentication required"))
		return
	}
	var req dto.LogoutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.InvalidInput("body", "Invalid request body"))
		return
	}
	if req.RefreshToken == "" {
		writeError(w, errors.InvalidInput("refresh_token", "refresh_token is required"))
		return
	}

	if err := h.authService.LogoutWithCaller(r.Context(), req.RefreshToken, *callerID); err != nil {
		// Failure modes that aren't user-facing — e.g., the refresh
		// token was already revoked, or the DB transiently errored —
		// are logged with the request_id for ops visibility but don't
		// surface to the caller. A failed logout is functionally a
		// successful logout (the access token is still going to
		// expire; the user's intent is "end this session").
		logging.FromContext(r.Context()).Info("logout request failed; returning success to caller",
			"err", err.Error(),
		)
	}

	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// LogoutAll handles logging out from all sessions
func (h *AuthHandler) LogoutAll(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == nil {
		writeError(w, errors.Unauthorized("Authentication required"))
		return
	}

	if err := h.authService.LogoutAll(r.Context(), *userID); err != nil {
		handleServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// RequestPasswordReset handles password reset request
func (h *AuthHandler) RequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	var req dto.RequestPasswordResetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.InvalidInput("body", "Invalid request body"))
		return
	}

	// App context for the pool-scoped lookup. Unauthenticated flow → the
	// X-App-Code header wins over the body field (doc §1 precedence).
	appCode := req.AppCode
	if hdr := r.Header.Get("X-App-Code"); hdr != "" {
		appCode = hdr
	}

	// Always return success to prevent email enumeration
	_ = h.authService.RequestPasswordReset(r.Context(), req.Email, appCode)

	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// ResetPassword handles password reset
func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req dto.ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.InvalidInput("body", "Invalid request body"))
		return
	}

	if err := h.authService.ResetPassword(r.Context(), req.Token, req.NewPassword); err != nil {
		handleServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// ChangePassword handles password change for authenticated users
func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == nil {
		writeError(w, errors.Unauthorized("Authentication required"))
		return
	}

	var req dto.ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.InvalidInput("body", "Invalid request body"))
		return
	}

	if err := h.authService.ChangePassword(r.Context(), *userID, req.CurrentPassword, req.NewPassword); err != nil {
		handleServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// AdminSetPassword allows a system_admin to set any user's password without knowing the current one.
// CheckEmail reports whether an email is registered. AUDIT 8.2 — gated to
// system_admin (the service-auth stand-in until M2M tokens land in Phase C).
// Never exposed to public clients because it trivially enables user
// enumeration. Public clients should handle existence ambiguity through the
// register-or-login mode (B7a).
//
//	POST /auth/check-email { email }  → 200 { exists: bool }
func (h *AuthHandler) CheckEmail(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil || !claims.HasRole("system_admin") {
		writeError(w, errors.Forbidden("Only service callers may check email existence"))
		return
	}
	var req struct {
		Email   string `json:"email"`
		AppCode string `json:"app_code,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.InvalidInput("body", "Invalid request body"))
		return
	}
	// App context for the pool-scoped lookup. For this authenticated admin
	// route the JWT claim is authoritative; X-App-Code header then body are
	// fallbacks for callers whose service token carries no app scope.
	appCode := claims.AppCode
	if appCode == "" {
		appCode = r.Header.Get("X-App-Code")
	}
	if appCode == "" {
		appCode = req.AppCode
	}
	exists, err := h.authService.CheckEmail(r.Context(), req.Email, appCode)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"exists": exists})
}

// BulkImportUsers imports users with pre-hashed passwords (§4). system_admin
// only — gated by the route chain AND re-checked here. Stores hashes verbatim
// so existing passwords keep working with no reset; returns per-row status +
// uid for foreign-key backfill (e.g. GlobalSKU users.ven_user_id).
func (h *AuthHandler) BulkImportUsers(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil || !claims.HasRole("system_admin") {
		writeError(w, errors.Forbidden("Only system admins can bulk-import users"))
		return
	}
	var req auth.BulkImportInput
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.InvalidInput("body", "Invalid request body"))
		return
	}
	result, err := h.authService.BulkImport(r.Context(), req)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *AuthHandler) AdminSetPassword(w http.ResponseWriter, r *http.Request) {
	callerID := middleware.GetUserID(r.Context())
	if callerID == nil {
		writeError(w, errors.Unauthorized("Authentication required"))
		return
	}

	// Check caller has system_admin role via JWT claims
	claims := middleware.GetClaims(r.Context())
	if claims == nil || !claims.HasRole("system_admin") {
		writeError(w, errors.Forbidden("Only system admins can set user passwords"))
		return
	}

	var req struct {
		UserID      string `json:"user_id"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.InvalidInput("body", "Invalid request body"))
		return
	}
	if req.UserID == "" || req.NewPassword == "" {
		writeError(w, errors.InvalidInput("body", "user_id and new_password are required"))
		return
	}

	targetID, err := types.ParseID(req.UserID)
	if err != nil {
		writeError(w, errors.InvalidInput("user_id", "Invalid user ID"))
		return
	}

	if err := h.authService.AdminSetPassword(r.Context(), targetID, req.NewPassword); err != nil {
		handleServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// ResendVerificationEmail re-issues the email-verification token for an
// unverified account (AUDIT 5.4). The response is always 200 — the
// service silently no-ops on any failure mode (unknown email, already
// verified, suspended, deleted, email-service unconfigured) to avoid
// leaking account-existence to enumeration attempts.
//
// Rate-limited via the global per-IP limiter; an attacker scripting this
// gets throttled the same way any other unauthenticated endpoint would.
func (h *AuthHandler) ResendVerificationEmail(w http.ResponseWriter, r *http.Request) {
	var req dto.ResendVerificationEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.InvalidInput("body", "Invalid request body"))
		return
	}
	if req.Email == "" {
		writeError(w, errors.InvalidInput("email", "email is required"))
		return
	}
	if err := h.authService.ResendVerificationEmail(r.Context(), req.Email, req.AppCode); err != nil {
		// Surface only Internal-class errors; "unknown email" etc. are
		// silently no-op'd inside the service to avoid enumeration.
		handleServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// VerifyEmail handles email verification
func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		var req dto.VerifyEmailRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, errors.InvalidInput("token", "Token is required"))
			return
		}
		token = req.Token
	}

	if err := h.authService.VerifyEmail(r.Context(), token); err != nil {
		handleServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// GetSSOAuthURL returns the SSO authorization URL
func (h *AuthHandler) GetSSOAuthURL(w http.ResponseWriter, r *http.Request) {
	var req dto.SSOAuthURLRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.InvalidInput("body", "Invalid request body"))
		return
	}

	// App context: prefer the X-App-Code header, fall back to the body field.
	appCode := req.AppCode
	if hdr := r.Header.Get("X-App-Code"); hdr != "" {
		appCode = hdr
	}

	provider := types.AuthProvider(req.Provider)
	authURL, state, err := h.authService.GetSSOAuthURL(r.Context(), auth.GetSSOAuthURLInput{
		Provider:            provider,
		RedirectURL:         req.RedirectURL,
		OrganizationID:      req.OrganizationID,
		InviteCode:          req.InviteCode,
		AppCode:             appCode,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
	})
	if err != nil {
		handleServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, &dto.SSOAuthURLResponse{
		AuthURL: authURL,
		State:   state,
	})
}

// SSOCallback handles SSO callback
func (h *AuthHandler) SSOCallback(w http.ResponseWriter, r *http.Request) {
	// Support query params, form_post (Apple), and JSON body.
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	provider := r.URL.Query().Get("provider")
	appCode := r.Header.Get("X-App-Code")
	appleUser := ""

	if code == "" || state == "" {
		// Apple uses response_mode=form_post (application/x-www-form-urlencoded),
		// carrying `user` (name JSON) on the first authorization. Everyone else
		// posts JSON. Branch on content type so we read the body only once.
		if ct := r.Header.Get("Content-Type"); strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
			_ = r.ParseForm()
			code = r.PostFormValue("code")
			state = r.PostFormValue("state")
			appleUser = r.PostFormValue("user")
			if p := r.PostFormValue("provider"); p != "" {
				provider = p
			} else if appleUser != "" {
				provider = "apple"
			}
		} else {
			var req dto.SSOCallbackRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
				code = req.Code
				state = req.State
				provider = req.Provider
				appleUser = req.AppleUser
				if appCode == "" {
					appCode = req.AppCode
				}
			}
		}
	}

	if code == "" || state == "" {
		writeError(w, errors.InvalidInput("code", "Code and state are required"))
		return
	}

	result, err := h.authService.SSOLogin(r.Context(), auth.SSOLoginInput{
		Provider:   types.AuthProvider(provider),
		Code:       code,
		State:      state,
		AppCode:    appCode,
		AppleUser:  appleUser,
		DeviceInfo: r.Header.Get("User-Agent"),
		IPAddress:  getClientIP(r),
		UserAgent:  r.Header.Get("User-Agent"),
	})
	if err != nil {
		handleServiceError(w, err)
		return
	}

	// AUDIT C2: when the original /auth/sso/url request initiated PKCE, the
	// callback returns an auth_code instead of tokens. The public client
	// redeems it at /auth/sso/exchange with its code_verifier.
	if result.AuthCode != "" {
		writeJSON(w, http.StatusOK, &dto.SSOAuthCodeResponse{
			AuthCode:  result.AuthCode,
			ExpiresIn: result.AuthCodeExpiresIn,
		})
		return
	}

	resp := &dto.LoginResponse{
		User: dto.ToUserResponse(result.User),
		Tokens: &dto.TokenResponse{
			AccessToken:  result.TokenPair.AccessToken,
			RefreshToken: result.TokenPair.RefreshToken,
			TokenType:    result.TokenPair.TokenType,
			ExpiresIn:    result.TokenPair.ExpiresIn,
			ExpiresAt:    result.TokenPair.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
		},
		Roles:       result.Roles,
		Permissions: result.Permissions,
	}
	if result.Organization != nil {
		resp.Organization = dto.ToOrganizationResponse(result.Organization)
	}

	writeJSON(w, http.StatusOK, resp)
}

// SSOExchange redeems a PKCE auth_code for a token pair (AUDIT C2). Public
// endpoint — no auth required, since the very purpose is to bootstrap auth
// for a public client. Anti-replay comes from the auth_code being one-shot
// (atomic GETDEL in the store) and the verifier proving possession of the
// original PKCE secret.
func (h *AuthHandler) SSOExchange(w http.ResponseWriter, r *http.Request) {
	var req dto.SSOExchangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.InvalidInput("body", "Invalid request body"))
		return
	}
	if req.AuthCode == "" || req.CodeVerifier == "" {
		writeError(w, errors.InvalidInput("auth_code", "auth_code and code_verifier are required"))
		return
	}

	result, err := h.authService.SSOExchange(r.Context(), auth.SSOExchangeInput{
		AuthCode:     req.AuthCode,
		CodeVerifier: req.CodeVerifier,
		DeviceInfo:   r.Header.Get("User-Agent"),
		IPAddress:    getClientIP(r),
		UserAgent:    r.Header.Get("User-Agent"),
	})
	if err != nil {
		handleServiceError(w, err)
		return
	}

	resp := &dto.LoginResponse{
		User: dto.ToUserResponse(result.User),
		Tokens: &dto.TokenResponse{
			AccessToken:  result.TokenPair.AccessToken,
			RefreshToken: result.TokenPair.RefreshToken,
			TokenType:    result.TokenPair.TokenType,
			ExpiresIn:    result.TokenPair.ExpiresIn,
			ExpiresAt:    result.TokenPair.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
		},
		Roles:       result.Roles,
		Permissions: result.Permissions,
	}
	if result.Organization != nil {
		resp.Organization = dto.ToOrganizationResponse(result.Organization)
	}
	writeJSON(w, http.StatusOK, resp)
}

// ValidateToken validates an access token
func (h *AuthHandler) ValidateToken(w http.ResponseWriter, r *http.Request) {
	var req dto.ValidateTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.InvalidInput("body", "Invalid request body"))
		return
	}

	claims, err := h.authService.ValidateToken(req.Token)
	if err != nil {
		writeJSON(w, http.StatusOK, &dto.ValidateTokenResponse{Valid: false})
		return
	}

	resp := &dto.ValidateTokenResponse{
		Valid:       true,
		UserID:      claims.UserID.String(),
		Email:       claims.Email,
		Roles:       claims.Roles,
		Permissions: claims.Permissions,
		ExpiresAt:   claims.ExpiresAt.Time.Format("2006-01-02T15:04:05Z07:00"),
	}
	if claims.OrganizationID != nil {
		resp.OrgID = claims.OrganizationID.String()
	}

	writeJSON(w, http.StatusOK, resp)
}

// GetSessions returns active sessions for the authenticated user
func (h *AuthHandler) GetSessions(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == nil {
		writeError(w, errors.Unauthorized("Authentication required"))
		return
	}

	sessions, err := h.authService.GetUserSessions(r.Context(), *userID)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	claims := middleware.GetClaims(r.Context())
	var currentSessionID *types.ID
	if claims != nil && claims.SessionID != nil {
		currentSessionID = claims.SessionID
	}

	resp := make([]*dto.SessionResponse, len(sessions))
	for i, session := range sessions {
		resp[i] = dto.ToSessionResponse(session, currentSessionID)
	}

	writeJSON(w, http.StatusOK, resp)
}

// TerminateSession terminates a specific session
func (h *AuthHandler) TerminateSession(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == nil {
		writeError(w, errors.Unauthorized("Authentication required"))
		return
	}

	// AUDIT L1: Go 1.22's ServeMux supports `{name}` patterns directly.
	// r.PathValue is the canonical extractor; the hand-rolled
	// getPathParam helper is the old workaround for routers that didn't
	// support it.
	id, err := types.ParseID(r.PathValue("sessionId"))
	if err != nil {
		writeError(w, errors.InvalidInput("session_id", "Invalid session ID"))
		return
	}

	if err := h.authService.TerminateSession(r.Context(), *userID, id); err != nil {
		handleServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// GetEnabledProviders returns enabled SSO providers
func (h *AuthHandler) GetEnabledProviders(w http.ResponseWriter, r *http.Request) {
	providers := h.authService.GetEnabledSSOProviders()

	resp := make([]*dto.SSOProviderResponse, len(providers))
	for i, p := range providers {
		resp[i] = &dto.SSOProviderResponse{
			Name:    p.Name,
			Type:    string(p.Type),
			Enabled: p.Enabled,
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

// GetMe returns the current authenticated user
func (h *AuthHandler) GetMe(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		writeError(w, errors.Unauthorized("Authentication required"))
		return
	}

	resp := map[string]interface{}{
		"user_id":     claims.UserID.String(),
		"email":       claims.Email,
		"first_name":  claims.FirstName,
		"last_name":   claims.LastName,
		"roles":       claims.Roles,
		"permissions": claims.Permissions,
	}

	if claims.OrganizationID != nil {
		resp["organization_id"] = claims.OrganizationID.String()
		resp["organization_name"] = claims.OrganizationName
		resp["organization_slug"] = claims.OrganizationSlug
	}

	writeJSON(w, http.StatusOK, resp)
}
