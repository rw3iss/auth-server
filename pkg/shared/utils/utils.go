// Package utils provides shared utility functions used across the auction platform
package utils

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

// Password hashing

// MaxPasswordLength is the hard cap on accepted password input length.
// bcrypt itself truncates at 72 bytes, but accepting multi-MB inputs lets
// an attacker burn CPU on every login/register request — see AUDIT 1.4.
const MaxPasswordLength = 128

// MinBcryptCost is the lowest bcrypt cost the server will accept. Below this
// modern hardware brute-forces hashes too quickly to be useful.
const MinBcryptCost = 10

// MaxBcryptCost is the upper bound. Above this each hash takes seconds on
// commodity hardware, opening a much wider DoS surface than it closes.
const MaxBcryptCost = 14

// HashPassword hashes a password using bcrypt at the given cost.
// Callers must source `cost` from config (Security.BcryptCost); historically
// this function silently used bcrypt.DefaultCost (10) even when operators
// raised BCRYPT_COST in env — see AUDIT 1.3.
func HashPassword(password string, cost int) (string, error) {
	if len(password) > MaxPasswordLength {
		return "", fmt.Errorf("password exceeds maximum length of %d", MaxPasswordLength)
	}
	if cost < MinBcryptCost || cost > MaxBcryptCost {
		return "", fmt.Errorf("bcrypt cost %d outside allowed range [%d,%d]", cost, MinBcryptCost, MaxBcryptCost)
	}
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	return string(bytes), err
}

// CheckPassword compares a password with a hash. Length-capped to bound CPU
// spend per login attempt (see AUDIT 1.4) — bcrypt would otherwise hash the
// full input before truncating at 72 bytes internally.
func CheckPassword(password, hash string) bool {
	if len(password) > MaxPasswordLength {
		return false
	}
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// Random generation

// GenerateRandomBytes generates cryptographically secure random bytes
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// GenerateRandomString generates a random string of specified length
func GenerateRandomString(length int) (string, error) {
	bytes, err := GenerateRandomBytes(length)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}

// GenerateRandomHex generates a random hex string
func GenerateRandomHex(length int) (string, error) {
	bytes, err := GenerateRandomBytes(length / 2)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// GenerateInviteCode generates a user-friendly invite code
func GenerateInviteCode() (string, error) {
	// Generate a 6-character alphanumeric code
	const charset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // Excluding confusing chars like 0, O, 1, I
	bytes, err := GenerateRandomBytes(6)
	if err != nil {
		return "", err
	}
	code := make([]byte, 6)
	for i := range code {
		code[i] = charset[int(bytes[i])%len(charset)]
	}
	return string(code), nil
}

// String utilities

// Slugify creates a URL-friendly slug from a string
func Slugify(s string) string {
	s = strings.ToLower(s)
	s = strings.TrimSpace(s)

	// Replace spaces with hyphens
	s = strings.ReplaceAll(s, " ", "-")

	// Remove all non-alphanumeric characters except hyphens
	reg := regexp.MustCompile(`[^a-z0-9-]`)
	s = reg.ReplaceAllString(s, "")

	// Remove multiple consecutive hyphens
	reg = regexp.MustCompile(`-+`)
	s = reg.ReplaceAllString(s, "-")

	// Trim hyphens from start and end
	s = strings.Trim(s, "-")

	return s
}

// TruncateString truncates a string to a maximum length
func TruncateString(s string, maxLength int) string {
	if len(s) <= maxLength {
		return s
	}
	return s[:maxLength-3] + "..."
}

// Validation utilities

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// IsValidEmail checks if an email is valid
func IsValidEmail(email string) bool {
	return emailRegex.MatchString(email)
}

// PasswordStrength represents the strength of a password
type PasswordStrength int

const (
	PasswordWeak     PasswordStrength = 1
	PasswordFair     PasswordStrength = 2
	PasswordStrong   PasswordStrength = 3
	PasswordVeryStrong PasswordStrength = 4
)

// PasswordValidationResult contains password validation details
type PasswordValidationResult struct {
	IsValid       bool             `json:"is_valid"`
	Strength      PasswordStrength `json:"strength"`
	Errors        []string         `json:"errors,omitempty"`
	Suggestions   []string         `json:"suggestions,omitempty"`
}

// PasswordPolicy parameterises ValidatePassword. Each character-class flag is
// independently configurable so operators can relax requirements without code
// changes (AUDIT 1.5). MinLength defaults to 8, MaxLength to MaxPasswordLength.
type PasswordPolicy struct {
	MinLength      int
	MaxLength      int
	RequireUpper   bool
	RequireLower   bool
	RequireDigit   bool
	RequireSpecial bool
}

// DefaultPasswordPolicy returns the policy used when callers pass MinLength=0
// to ValidatePassword (back-compat shim — prefer building an explicit policy).
func DefaultPasswordPolicy() PasswordPolicy {
	return PasswordPolicy{
		MinLength:      8,
		MaxLength:      MaxPasswordLength,
		RequireUpper:   true,
		RequireLower:   true,
		RequireDigit:   true,
		RequireSpecial: false,
	}
}

// ValidatePassword validates a password against a policy and returns detailed
// results. Two call shapes are supported for back-compat: pass an int
// (treated as MinLength against DefaultPasswordPolicy) or a PasswordPolicy.
func ValidatePassword(password string, policyOrMinLength any) PasswordValidationResult {
	policy := DefaultPasswordPolicy()
	switch v := policyOrMinLength.(type) {
	case PasswordPolicy:
		policy = v
		if policy.MinLength == 0 {
			policy.MinLength = 8
		}
		if policy.MaxLength == 0 {
			policy.MaxLength = MaxPasswordLength
		}
	case int:
		if v > 0 {
			policy.MinLength = v
		}
	}

	result := PasswordValidationResult{
		IsValid:     true,
		Strength:    PasswordWeak,
		Errors:      []string{},
		Suggestions: []string{},
	}

	// Length floor: emit the actual configured minimum, not the result of
	// `string(rune(minLength+'0'))` which silently produced garbage for any
	// MinLength≥10 (AUDIT 1.5).
	if len(password) < policy.MinLength {
		result.IsValid = false
		result.Errors = append(result.Errors, fmt.Sprintf("Password must be at least %d characters", policy.MinLength))
	}
	// Length ceiling: cap CPU per login (AUDIT 1.4).
	if len(password) > policy.MaxLength {
		result.IsValid = false
		result.Errors = append(result.Errors, fmt.Sprintf("Password must be at most %d characters", policy.MaxLength))
	}

	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	// Strength score is advisory (drives `Strength` enum) and independent of
	// the IsValid gate below — operators may demand digits without raising
	// the response's strength rating.
	strengthScore := 0
	if hasUpper {
		strengthScore++
	} else {
		result.Suggestions = append(result.Suggestions, "Add uppercase letters")
	}
	if hasLower {
		strengthScore++
	} else {
		result.Suggestions = append(result.Suggestions, "Add lowercase letters")
	}
	if hasDigit {
		strengthScore++
	} else {
		result.Suggestions = append(result.Suggestions, "Add numbers")
	}
	if hasSpecial {
		strengthScore++
	} else {
		result.Suggestions = append(result.Suggestions, "Add special characters")
	}
	if len(password) >= 12 {
		strengthScore++
	}

	switch {
	case strengthScore >= 5:
		result.Strength = PasswordVeryStrong
	case strengthScore >= 4:
		result.Strength = PasswordStrong
	case strengthScore >= 3:
		result.Strength = PasswordFair
	default:
		result.Strength = PasswordWeak
	}

	// Hard requirements — each driven by an independent policy toggle so
	// operators can relax (e.g. for SSO-only orgs that accept weaker
	// passwords) without code changes.
	if policy.RequireUpper && !hasUpper {
		result.IsValid = false
		result.Errors = append(result.Errors, "Password must contain at least one uppercase letter")
	}
	if policy.RequireLower && !hasLower {
		result.IsValid = false
		result.Errors = append(result.Errors, "Password must contain at least one lowercase letter")
	}
	if policy.RequireDigit && !hasDigit {
		result.IsValid = false
		result.Errors = append(result.Errors, "Password must contain at least one number")
	}
	if policy.RequireSpecial && !hasSpecial {
		result.IsValid = false
		result.Errors = append(result.Errors, "Password must contain at least one special character")
	}

	return result
}

// NormalizeEmail normalizes an email address
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// MaskEmail masks an email address for display
func MaskEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return email
	}

	local := parts[0]
	domain := parts[1]

	if len(local) <= 2 {
		return local + "***@" + domain
	}

	return local[:2] + "***@" + domain
}

// StringPtr returns a pointer to the string
func StringPtr(s string) *string {
	return &s
}

// IntPtr returns a pointer to the int
func IntPtr(i int) *int {
	return &i
}

// BoolPtr returns a pointer to the bool
func BoolPtr(b bool) *bool {
	return &b
}
