// Package errors provides shared error types used across the auction platform
package errors

import (
	"fmt"
	"net/http"
)

// ErrorCode represents a unique error code
type ErrorCode string

const (
	// Authentication errors
	ErrCodeUnauthorized       ErrorCode = "UNAUTHORIZED"
	ErrCodeInvalidCredentials ErrorCode = "INVALID_CREDENTIALS"
	ErrCodeTokenExpired       ErrorCode = "TOKEN_EXPIRED"
	ErrCodeTokenInvalid       ErrorCode = "TOKEN_INVALID"
	ErrCodeTokenRevoked       ErrorCode = "TOKEN_REVOKED"
	ErrCodeSessionExpired     ErrorCode = "SESSION_EXPIRED"

	// Authorization errors
	ErrCodeForbidden         ErrorCode = "FORBIDDEN"
	ErrCodeInsufficientPerms ErrorCode = "INSUFFICIENT_PERMISSIONS"
	ErrCodeRoleNotAssigned   ErrorCode = "ROLE_NOT_ASSIGNED"

	// User errors
	ErrCodeUserNotFound     ErrorCode = "USER_NOT_FOUND"
	ErrCodeUserExists       ErrorCode = "USER_ALREADY_EXISTS"
	ErrCodeUserSuspended    ErrorCode = "USER_SUSPENDED"
	ErrCodeUserDeleted      ErrorCode = "USER_DELETED"
	ErrCodeEmailNotVerified ErrorCode = "EMAIL_NOT_VERIFIED"
	ErrCodeInvalidEmail     ErrorCode = "INVALID_EMAIL"
	ErrCodeWeakPassword     ErrorCode = "WEAK_PASSWORD"

	// Organization errors
	ErrCodeOrgNotFound  ErrorCode = "ORGANIZATION_NOT_FOUND"
	ErrCodeOrgExists    ErrorCode = "ORGANIZATION_ALREADY_EXISTS"
	ErrCodeOrgSuspended ErrorCode = "ORGANIZATION_SUSPENDED"
	ErrCodeOrgDeleted   ErrorCode = "ORGANIZATION_DELETED"
	ErrCodeNotOrgMember ErrorCode = "NOT_ORGANIZATION_MEMBER"

	// Invitation errors
	ErrCodeInviteNotFound    ErrorCode = "INVITE_NOT_FOUND"
	ErrCodeInviteExpired     ErrorCode = "INVITE_EXPIRED"
	ErrCodeInviteUsed        ErrorCode = "INVITE_ALREADY_USED"
	ErrCodeInvalidInviteCode ErrorCode = "INVALID_INVITE_CODE"

	// Role errors
	ErrCodeRoleNotFound ErrorCode = "ROLE_NOT_FOUND"
	ErrCodeRoleExists   ErrorCode = "ROLE_ALREADY_EXISTS"
	ErrCodeSystemRole   ErrorCode = "CANNOT_MODIFY_SYSTEM_ROLE"

	// SSO errors
	ErrCodeSSOProviderError ErrorCode = "SSO_PROVIDER_ERROR"
	ErrCodeSSONotConfigured ErrorCode = "SSO_NOT_CONFIGURED"
	ErrCodeSSOTokenInvalid  ErrorCode = "SSO_TOKEN_INVALID"

	// Validation errors
	ErrCodeValidation   ErrorCode = "VALIDATION_ERROR"
	ErrCodeInvalidInput ErrorCode = "INVALID_INPUT"
	ErrCodeMissingField ErrorCode = "MISSING_REQUIRED_FIELD"

	// Legacy migration (§5). Returned when JIT migration finds an email that
	// already exists in the auth-server with DIFFERENT credentials than the
	// legacy store — migration is halted pending a merge strategy rather than
	// overwriting either side.
	ErrCodeLegacyMigrationConflict ErrorCode = "LEGACY_MIGRATION_CONFLICT"

	// General errors
	ErrCodeNotFound           ErrorCode = "NOT_FOUND"
	ErrCodeConflict           ErrorCode = "CONFLICT"
	ErrCodeInternal           ErrorCode = "INTERNAL_ERROR"
	ErrCodeRateLimited        ErrorCode = "RATE_LIMITED"
	ErrCodeServiceUnavailable ErrorCode = "SERVICE_UNAVAILABLE"
)

// AppError represents a structured application error
type AppError struct {
	Code       ErrorCode              `json:"code"`
	Message    string                 `json:"message"`
	Details    map[string]interface{} `json:"details,omitempty"`
	HTTPStatus int                    `json:"-"`
	Err        error                  `json:"-"`
}

// Error implements the error interface
func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s (%v)", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the underlying error
func (e *AppError) Unwrap() error {
	return e.Err
}

// WithDetails adds details to the error
func (e *AppError) WithDetails(details map[string]interface{}) *AppError {
	e.Details = details
	return e
}

// WithError wraps an underlying error
func (e *AppError) WithError(err error) *AppError {
	e.Err = err
	return e
}

// New creates a new AppError
func New(code ErrorCode, message string, httpStatus int) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		HTTPStatus: httpStatus,
	}
}

// Common error constructors

func Unauthorized(message string) *AppError {
	return New(ErrCodeUnauthorized, message, http.StatusUnauthorized)
}

func InvalidCredentials() *AppError {
	return New(ErrCodeInvalidCredentials, "Invalid email or password", http.StatusUnauthorized)
}

func TokenExpired() *AppError {
	return New(ErrCodeTokenExpired, "Token has expired", http.StatusUnauthorized)
}

func TokenInvalid() *AppError {
	return New(ErrCodeTokenInvalid, "Token is invalid", http.StatusUnauthorized)
}

func TokenRevoked() *AppError {
	return New(ErrCodeTokenRevoked, "Token has been revoked", http.StatusUnauthorized)
}

func Forbidden(message string) *AppError {
	return New(ErrCodeForbidden, message, http.StatusForbidden)
}

func InsufficientPermissions(action string) *AppError {
	return New(ErrCodeInsufficientPerms, fmt.Sprintf("Insufficient permissions to %s", action), http.StatusForbidden)
}

func UserNotFound() *AppError {
	return New(ErrCodeUserNotFound, "User not found", http.StatusNotFound)
}

func UserAlreadyExists(email string) *AppError {
	return New(ErrCodeUserExists, fmt.Sprintf("User with email %s already exists", email), http.StatusConflict)
}

func UserSuspended() *AppError {
	return New(ErrCodeUserSuspended, "User account is suspended", http.StatusForbidden)
}

func OrgNotFound() *AppError {
	return New(ErrCodeOrgNotFound, "Organization not found", http.StatusNotFound)
}

func OrgAlreadyExists(name string) *AppError {
	return New(ErrCodeOrgExists, fmt.Sprintf("Organization with name %s already exists", name), http.StatusConflict)
}

func NotOrgMember() *AppError {
	return New(ErrCodeNotOrgMember, "User is not a member of this organization", http.StatusForbidden)
}

func InviteNotFound() *AppError {
	return New(ErrCodeInviteNotFound, "Invitation not found", http.StatusNotFound)
}

func InviteExpired() *AppError {
	return New(ErrCodeInviteExpired, "Invitation has expired", http.StatusBadRequest)
}

func InviteAlreadyUsed() *AppError {
	return New(ErrCodeInviteUsed, "Invitation has already been used", http.StatusBadRequest)
}

func RoleNotFound() *AppError {
	return New(ErrCodeRoleNotFound, "Role not found", http.StatusNotFound)
}

func CannotModifySystemRole() *AppError {
	return New(ErrCodeSystemRole, "Cannot modify system-defined role", http.StatusForbidden)
}

func ValidationError(message string) *AppError {
	return New(ErrCodeValidation, message, http.StatusBadRequest)
}

func InvalidInput(field, message string) *AppError {
	return New(ErrCodeInvalidInput, message, http.StatusBadRequest).WithDetails(map[string]interface{}{
		"field": field,
	})
}

func MissingField(field string) *AppError {
	return New(ErrCodeMissingField, fmt.Sprintf("Missing required field: %s", field), http.StatusBadRequest)
}

func NotFound(resource string) *AppError {
	return New(ErrCodeNotFound, fmt.Sprintf("%s not found", resource), http.StatusNotFound)
}

func Conflict(message string) *AppError {
	return New(ErrCodeConflict, message, http.StatusConflict)
}

// LegacyMigrationConflict (§5) — an account with this email already exists in
// the central auth system with different credentials; JIT migration was
// halted. The email + app code are carried in WithDetails so a later
// reconciliation tool can find these cases.
func LegacyMigrationConflict(email, appCode string) *AppError {
	return New(ErrCodeLegacyMigrationConflict,
		"An account with this email already exists in the central auth system with different credentials; legacy migration was halted pending a merge strategy.",
		http.StatusConflict).WithDetails(map[string]any{"email": email, "app_code": appCode})
}

func Internal(message string) *AppError {
	return New(ErrCodeInternal, message, http.StatusInternalServerError)
}

func RateLimited() *AppError {
	return New(ErrCodeRateLimited, "Too many requests, please try again later", http.StatusTooManyRequests)
}

func SSOProviderError(provider, message string) *AppError {
	return New(ErrCodeSSOProviderError, fmt.Sprintf("SSO provider %s error: %s", provider, message), http.StatusBadGateway)
}

func SSONotConfigured(provider string) *AppError {
	return New(ErrCodeSSONotConfigured, fmt.Sprintf("SSO provider %s is not configured", provider), http.StatusBadRequest)
}

// IsAppError checks if an error is an AppError
func IsAppError(err error) bool {
	_, ok := err.(*AppError)
	return ok
}

// AsAppError converts an error to AppError if possible
func AsAppError(err error) (*AppError, bool) {
	appErr, ok := err.(*AppError)
	return appErr, ok
}

// GetHTTPStatus returns the HTTP status code for an error
func GetHTTPStatus(err error) int {
	if appErr, ok := AsAppError(err); ok {
		return appErr.HTTPStatus
	}
	return http.StatusInternalServerError
}
