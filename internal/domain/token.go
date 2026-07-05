package domain

import (
	"github.com/ven/auth/pkg/shared/models"
	"github.com/ven/auth/pkg/shared/types"
)

// RefreshToken represents a refresh token stored in the database.
//
// FamilyID + ParentID implement OAuth refresh-token rotation with theft
// detection (RFC 6819 §5.2.2.3, AUDIT 1.9):
//
//   - FamilyID is the UUID of the *original* issuance for this chain. Every
//     rotation copies the parent's FamilyID forward, so all descendants of a
//     single login share the same family.
//   - ParentID points to the token this one rotated from (NULL for the
//     family root). Useful for forensics ("walk back to the first issuance
//     after a theft event"); not used in the rotation hot path.
//
// On reuse — i.e. a refresh token presented after it was already rotated and
// revoked — the service revokes the entire family, not just the presented
// row. This kills both the legitimate user and the attacker simultaneously,
// which is the desired behavior: the user re-authenticates and the attacker
// loses the entire stolen chain.
type RefreshToken struct {
	models.BaseModel

	UserID         types.ID         `json:"user_id" db:"user_id"`
	OrganizationID *types.ID        `json:"organization_id,omitempty" db:"organization_id"`
	Token          string           `json:"-" db:"token"`
	TokenHash      string           `json:"-" db:"token_hash"`
	FamilyID       types.ID         `json:"family_id" db:"family_id"`
	ParentID       *types.ID        `json:"parent_id,omitempty" db:"parent_id"`
	DeviceInfo     string           `json:"device_info,omitempty" db:"device_info"`
	IPAddress      string           `json:"ip_address,omitempty" db:"ip_address"`
	UserAgent      string           `json:"user_agent,omitempty" db:"user_agent"`
	ExpiresAt      types.Timestamp  `json:"expires_at" db:"expires_at"`
	LastUsedAt     *types.Timestamp `json:"last_used_at,omitempty" db:"last_used_at"`
	Revoked        bool             `json:"revoked" db:"revoked"`
	RevokedAt      *types.Timestamp `json:"revoked_at,omitempty" db:"revoked_at"`
	RevokedReason  *string          `json:"revoked_reason,omitempty" db:"revoked_reason"`
}

// NewRefreshToken creates a new refresh token record that is its own family
// root (no parent). Used for initial login / SSO upserts. For rotation, use
// NewRotatedRefreshToken so the family is preserved.
func NewRefreshToken(userID types.ID, orgID *types.ID, tokenHash string, expiresAt types.Timestamp) *RefreshToken {
	base := models.NewBaseModel()
	return &RefreshToken{
		BaseModel:      base,
		UserID:         userID,
		OrganizationID: orgID,
		TokenHash:      tokenHash,
		// New family root: family_id == id so the row identifies the
		// origin issuance for every descendant.
		FamilyID:  base.ID,
		ParentID:  nil,
		ExpiresAt: expiresAt,
		Revoked:   false,
	}
}

// NewRotatedRefreshToken creates a refresh token row whose family carries
// over from the parent. Use this on `/auth/refresh`.
func NewRotatedRefreshToken(parent *RefreshToken, tokenHash string, expiresAt types.Timestamp) *RefreshToken {
	parentID := parent.ID
	return &RefreshToken{
		BaseModel:      models.NewBaseModel(),
		UserID:         parent.UserID,
		OrganizationID: parent.OrganizationID,
		TokenHash:      tokenHash,
		FamilyID:       parent.FamilyID,
		ParentID:       &parentID,
		ExpiresAt:      expiresAt,
		Revoked:        false,
	}
}

// IsValid checks if the refresh token is valid
func (t *RefreshToken) IsValid() bool {
	return !t.Revoked && types.Now().Before(t.ExpiresAt)
}

// Revoke revokes the refresh token
func (t *RefreshToken) Revoke(reason string) {
	t.Revoked = true
	now := types.Now()
	t.RevokedAt = &now
	t.RevokedReason = &reason
}

// UpdateLastUsed updates the last used timestamp
func (t *RefreshToken) UpdateLastUsed() {
	now := types.Now()
	t.LastUsedAt = &now
}

// PasswordResetToken represents a password reset token
type PasswordResetToken struct {
	models.BaseModel

	UserID    types.ID        `json:"user_id" db:"user_id"`
	Token     string          `json:"-" db:"token"`
	TokenHash string          `json:"-" db:"token_hash"`
	ExpiresAt types.Timestamp `json:"expires_at" db:"expires_at"`
	Used      bool            `json:"used" db:"used"`
	UsedAt    *types.Timestamp `json:"used_at,omitempty" db:"used_at"`
}

// NewPasswordResetToken creates a new password reset token
func NewPasswordResetToken(userID types.ID, tokenHash string, expiresAt types.Timestamp) *PasswordResetToken {
	return &PasswordResetToken{
		BaseModel: models.NewBaseModel(),
		UserID:    userID,
		TokenHash: tokenHash,
		ExpiresAt: expiresAt,
		Used:      false,
	}
}

// IsValid checks if the reset token is valid
func (t *PasswordResetToken) IsValid() bool {
	return !t.Used && types.Now().Before(t.ExpiresAt)
}

// MarkUsed marks the token as used
func (t *PasswordResetToken) MarkUsed() {
	t.Used = true
	now := types.Now()
	t.UsedAt = &now
}

// EmailVerificationToken represents an email verification token
type EmailVerificationToken struct {
	models.BaseModel

	UserID    types.ID        `json:"user_id" db:"user_id"`
	Email     types.Email     `json:"email" db:"email"`
	Token     string          `json:"-" db:"token"`
	TokenHash string          `json:"-" db:"token_hash"`
	ExpiresAt types.Timestamp `json:"expires_at" db:"expires_at"`
	Used      bool            `json:"used" db:"used"`
	UsedAt    *types.Timestamp `json:"used_at,omitempty" db:"used_at"`
}

// NewEmailVerificationToken creates a new email verification token
func NewEmailVerificationToken(userID types.ID, email types.Email, tokenHash string, expiresAt types.Timestamp) *EmailVerificationToken {
	return &EmailVerificationToken{
		BaseModel: models.NewBaseModel(),
		UserID:    userID,
		Email:     email,
		TokenHash: tokenHash,
		ExpiresAt: expiresAt,
		Used:      false,
	}
}

// IsValid checks if the verification token is valid
func (t *EmailVerificationToken) IsValid() bool {
	return !t.Used && types.Now().Before(t.ExpiresAt)
}

// MarkUsed marks the token as used
func (t *EmailVerificationToken) MarkUsed() {
	t.Used = true
	now := types.Now()
	t.UsedAt = &now
}

// Session represents an active user session
type Session struct {
	models.BaseModel

	UserID         types.ID         `json:"user_id" db:"user_id"`
	OrganizationID *types.ID        `json:"organization_id,omitempty" db:"organization_id"`
	RefreshTokenID types.ID         `json:"refresh_token_id" db:"refresh_token_id"`
	DeviceInfo     string           `json:"device_info,omitempty" db:"device_info"`
	IPAddress      string           `json:"ip_address,omitempty" db:"ip_address"`
	UserAgent      string           `json:"user_agent,omitempty" db:"user_agent"`
	Location       string           `json:"location,omitempty" db:"location"`
	LastActivityAt types.Timestamp  `json:"last_activity_at" db:"last_activity_at"`
	ExpiresAt      types.Timestamp  `json:"expires_at" db:"expires_at"`
	Terminated     bool             `json:"terminated" db:"terminated"`
	TerminatedAt   *types.Timestamp `json:"terminated_at,omitempty" db:"terminated_at"`
}

// NewSession creates a new session
func NewSession(userID types.ID, orgID *types.ID, refreshTokenID types.ID, expiresAt types.Timestamp) *Session {
	now := types.Now()
	return &Session{
		BaseModel:      models.NewBaseModel(),
		UserID:         userID,
		OrganizationID: orgID,
		RefreshTokenID: refreshTokenID,
		LastActivityAt: now,
		ExpiresAt:      expiresAt,
		Terminated:     false,
	}
}

// IsActive checks if the session is active
func (s *Session) IsActive() bool {
	return !s.Terminated && types.Now().Before(s.ExpiresAt)
}

// Terminate terminates the session
func (s *Session) Terminate() {
	s.Terminated = true
	now := types.Now()
	s.TerminatedAt = &now
}

// UpdateActivity updates the last activity timestamp
func (s *Session) UpdateActivity() {
	s.LastActivityAt = types.Now()
}
