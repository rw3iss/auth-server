// Package types provides shared type definitions used across the auction platform
package types

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

// ID represents a unique identifier used across the platform
type ID = uuid.UUID

// NewID generates a new unique identifier
func NewID() ID {
	return uuid.New()
}

// ParseID parses a string into an ID
func ParseID(s string) (ID, error) {
	return uuid.Parse(s)
}

// NullableID represents an optional ID that can be null
type NullableID *uuid.UUID

// Timestamp represents a point in time
type Timestamp = time.Time

// Now returns the current timestamp
func Now() Timestamp {
	return time.Now().UTC()
}

// Duration represents a time duration
type Duration = time.Duration

// Email represents a validated email address
type Email string

// String returns the string representation of an email
func (e Email) String() string {
	return string(e)
}

// PhoneNumber represents a phone number
type PhoneNumber string

// String returns the string representation of a phone number
func (p PhoneNumber) String() string {
	return string(p)
}

// Scan implements sql.Scanner so a NULL `phone` column (nullable in the
// schema) decodes to an empty PhoneNumber instead of erroring with
// "converting NULL to string is unsupported".
func (p *PhoneNumber) Scan(value interface{}) error {
	if value == nil {
		*p = ""
		return nil
	}
	switch v := value.(type) {
	case string:
		*p = PhoneNumber(v)
	case []byte:
		*p = PhoneNumber(v)
	default:
		return errors.New("unsupported Scan type for PhoneNumber")
	}
	return nil
}

// Value implements driver.Valuer — store an empty phone as SQL NULL so
// reads/writes round-trip cleanly against the nullable column.
func (p PhoneNumber) Value() (driver.Value, error) {
	if p == "" {
		return nil, nil
	}
	return string(p), nil
}

// JSON represents arbitrary JSON data
type JSON map[string]interface{}

// Value implements the driver.Valuer interface for database storage
func (j JSON) Value() (driver.Value, error) {
	return json.Marshal(j)
}

// Scan implements the sql.Scanner interface for database retrieval
func (j *JSON) Scan(value interface{}) error {
	if value == nil {
		*j = nil
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}
	return json.Unmarshal(bytes, j)
}

// Pagination represents pagination parameters
type Pagination struct {
	Page     int `json:"page"`
	PageSize int `json:"page_size"`
	Total    int `json:"total"`
}

// DefaultPagination returns default pagination settings
func DefaultPagination() Pagination {
	return Pagination{
		Page:     1,
		PageSize: 20,
	}
}

// Offset calculates the offset for database queries
func (p Pagination) Offset() int {
	return (p.Page - 1) * p.PageSize
}

// SortOrder represents the order for sorting
type SortOrder string

const (
	SortAsc  SortOrder = "ASC"
	SortDesc SortOrder = "DESC"
)

// AuthProvider represents the authentication provider type
type AuthProvider string

const (
	AuthProviderLocal     AuthProvider = "local"
	AuthProviderGoogle    AuthProvider = "google"
	AuthProviderApple     AuthProvider = "apple"
	AuthProviderMicrosoft AuthProvider = "microsoft"
	AuthProviderGitHub    AuthProvider = "github"
	AuthProviderFacebook  AuthProvider = "facebook"
	AuthProviderLinkedIn  AuthProvider = "linkedin"
	AuthProviderCustom    AuthProvider = "custom"
)

// TokenType represents the type of authentication token
type TokenType string

const (
	TokenTypeAccess  TokenType = "access"
	TokenTypeRefresh TokenType = "refresh"
	TokenTypeReset   TokenType = "reset"
	TokenTypeInvite  TokenType = "invite"
	TokenTypeVerify  TokenType = "verify"
	// TokenTypeService is the discriminator for tokens issued via the
	// OAuth2 client_credentials grant (POST /oauth/token). Distinct from
	// TokenTypeAccess so middleware can route service principals through
	// a different authorization path — no user lookup, scope-based
	// authz instead of role-based. See jwt.TokenClaims.IsServicePrincipal
	// and the auth-server-client TokenValidatorService discriminator.
	TokenTypeService TokenType = "service"
)

// UserStatus represents the status of a user account
type UserStatus string

const (
	UserStatusPending   UserStatus = "pending"
	UserStatusActive    UserStatus = "active"
	UserStatusSuspended UserStatus = "suspended"
	UserStatusDeleted   UserStatus = "deleted"
)

// OrganizationStatus represents the status of an organization
type OrganizationStatus string

const (
	OrgStatusPending   OrganizationStatus = "pending"
	OrgStatusActive    OrganizationStatus = "active"
	OrgStatusSuspended OrganizationStatus = "suspended"
	OrgStatusDeleted   OrganizationStatus = "deleted"
)
