package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/rw3iss/auth/internal/domain"
	"github.com/rw3iss/auth/pkg/shared/errors"
	"github.com/rw3iss/auth/pkg/shared/types"
)

// TokenRepository implements repository.TokenRepository
type TokenRepository struct {
	db *DB
}

// NewTokenRepository creates a new token repository
func NewTokenRepository(db *DB) *TokenRepository {
	return &TokenRepository{db: db}
}

// CreateRefreshToken creates a new refresh token. family_id and parent_id
// are part of every INSERT now (AUDIT 1.9 / migration 006).
func (r *TokenRepository) CreateRefreshToken(ctx context.Context, token *domain.RefreshToken) error {
	query := `
		INSERT INTO refresh_tokens (
			id, user_id, organization_id, token_hash, family_id, parent_id,
			device_info, ip_address, user_agent, expires_at, revoked,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`

	q := getQuerier(ctx, r.db)
	_, err := q.ExecContext(ctx, query,
		token.ID, token.UserID, token.OrganizationID, token.TokenHash,
		token.FamilyID, token.ParentID,
		token.DeviceInfo, token.IPAddress, token.UserAgent, token.ExpiresAt,
		token.Revoked, token.CreatedAt, token.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create refresh token: %w", err)
	}
	return nil
}

// refreshTokenSelectCols enumerates every column the domain entity needs.
// Centralised so adding a column (family_id, parent_id, …) is a one-line
// schema-and-string change rather than three duplicated SELECT lists.
const refreshTokenSelectCols = `id, user_id, organization_id, token_hash, family_id, parent_id,
	device_info, ip_address, user_agent, expires_at, last_used_at, revoked,
	revoked_at, revoked_reason, created_at, updated_at`

// GetRefreshToken retrieves a refresh token by hash
func (r *TokenRepository) GetRefreshToken(ctx context.Context, tokenHash string) (*domain.RefreshToken, error) {
	query := `SELECT ` + refreshTokenSelectCols + ` FROM refresh_tokens WHERE token_hash = $1`

	token := &domain.RefreshToken{}
	q := getQuerier(ctx, r.db)
	err := q.GetContext(ctx, token, query, tokenHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.TokenInvalid()
		}
		return nil, fmt.Errorf("failed to get refresh token: %w", err)
	}
	return token, nil
}

// GetRefreshTokenByID retrieves a refresh token by ID
func (r *TokenRepository) GetRefreshTokenByID(ctx context.Context, id types.ID) (*domain.RefreshToken, error) {
	query := `SELECT ` + refreshTokenSelectCols + ` FROM refresh_tokens WHERE id = $1`

	token := &domain.RefreshToken{}
	q := getQuerier(ctx, r.db)
	err := q.GetContext(ctx, token, query, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.TokenInvalid()
		}
		return nil, fmt.Errorf("failed to get refresh token by ID: %w", err)
	}
	return token, nil
}

// RevokeRefreshTokenFamily revokes every live (revoked = false) refresh
// token in the given family. AUDIT 1.9 / RFC 6819 §5.2.2.3: called when a
// revoked refresh token is presented again, indicating theft. Revoking the
// entire chain kills both the legitimate user (who'll have to re-auth) and
// the attacker (who loses access to all descendant rotations).
func (r *TokenRepository) RevokeRefreshTokenFamily(ctx context.Context, familyID types.ID, reason string) (int, error) {
	query := `
		UPDATE refresh_tokens SET
			revoked = true, revoked_at = NOW(), revoked_reason = $2, updated_at = NOW()
		WHERE family_id = $1 AND revoked = false`

	q := getQuerier(ctx, r.db)
	result, err := q.ExecContext(ctx, query, familyID, reason)
	if err != nil {
		return 0, fmt.Errorf("failed to revoke refresh token family: %w", err)
	}
	rows, _ := result.RowsAffected()
	return int(rows), nil
}

// UpdateRefreshToken updates a refresh token's mutable fields
// (last_used_at, revoked, revoked_at, revoked_reason) in a single
// UPDATE. The rotation path on /auth/refresh uses this to fold
// "stamp last_used_at" + "mark revoked" into one round-trip.
//
// The WHERE clause includes `revoked = false` so two concurrent
// refresh attempts presenting the same row can't both succeed at
// rotation — the first writer flips revoked=true; the second sees
// a 0-row UPDATE and bubbles up as TokenInvalid (the caller then
// trips the reuse-detection path on its next attempt).
func (r *TokenRepository) UpdateRefreshToken(ctx context.Context, token *domain.RefreshToken) error {
	query := `
		UPDATE refresh_tokens SET
			last_used_at = $2, revoked = $3, revoked_at = $4, revoked_reason = $5, updated_at = NOW()
		WHERE id = $1 AND revoked = false`

	q := getQuerier(ctx, r.db)
	result, err := q.ExecContext(ctx, query,
		token.ID, NullTime(token.LastUsedAt), token.Revoked,
		NullTime(token.RevokedAt), token.RevokedReason,
	)
	if err != nil {
		return fmt.Errorf("failed to update refresh token: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.TokenInvalid()
	}
	return nil
}

// RevokeRefreshToken revokes a refresh token
func (r *TokenRepository) RevokeRefreshToken(ctx context.Context, id types.ID, reason string) error {
	query := `
		UPDATE refresh_tokens SET
			revoked = true, revoked_at = NOW(), revoked_reason = $2, updated_at = NOW()
		WHERE id = $1 AND revoked = false`

	q := getQuerier(ctx, r.db)
	result, err := q.ExecContext(ctx, query, id, reason)
	if err != nil {
		return fmt.Errorf("failed to revoke refresh token: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.TokenInvalid()
	}
	return nil
}

// RevokeAllUserTokens revokes all refresh tokens for a user
func (r *TokenRepository) RevokeAllUserTokens(ctx context.Context, userID types.ID, reason string) error {
	query := `
		UPDATE refresh_tokens SET
			revoked = true, revoked_at = NOW(), revoked_reason = $2, updated_at = NOW()
		WHERE user_id = $1 AND revoked = false`

	q := getQuerier(ctx, r.db)
	_, err := q.ExecContext(ctx, query, userID, reason)
	if err != nil {
		return fmt.Errorf("failed to revoke all user tokens: %w", err)
	}
	return nil
}

// RevokeUserOrgTokens revokes refresh tokens for a user in a specific organization
func (r *TokenRepository) RevokeUserOrgTokens(ctx context.Context, userID, orgID types.ID, reason string) error {
	query := `
		UPDATE refresh_tokens SET
			revoked = true, revoked_at = NOW(), revoked_reason = $3, updated_at = NOW()
		WHERE user_id = $1 AND organization_id = $2 AND revoked = false`

	q := getQuerier(ctx, r.db)
	_, err := q.ExecContext(ctx, query, userID, orgID, reason)
	if err != nil {
		return fmt.Errorf("failed to revoke user org tokens: %w", err)
	}
	return nil
}

// ListUserRefreshTokens lists all refresh tokens for a user
func (r *TokenRepository) ListUserRefreshTokens(ctx context.Context, userID types.ID) ([]*domain.RefreshToken, error) {
	query := `SELECT ` + refreshTokenSelectCols + `
		FROM refresh_tokens
		WHERE user_id = $1 AND revoked = false AND expires_at > NOW()
		ORDER BY created_at DESC`

	var tokens []*domain.RefreshToken
	q := getQuerier(ctx, r.db)
	if err := q.SelectContext(ctx, &tokens, query, userID); err != nil {
		return nil, fmt.Errorf("failed to list user refresh tokens: %w", err)
	}
	return tokens, nil
}

// CleanupExpiredTokens removes expired tokens
func (r *TokenRepository) CleanupExpiredTokens(ctx context.Context) (int, error) {
	query := `DELETE FROM refresh_tokens WHERE expires_at < NOW() OR (revoked = true AND revoked_at < NOW() - INTERVAL '30 days')`

	q := getQuerier(ctx, r.db)
	result, err := q.ExecContext(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired tokens: %w", err)
	}

	rows, _ := result.RowsAffected()
	return int(rows), nil
}

// CreatePasswordResetToken creates a password reset token
func (r *TokenRepository) CreatePasswordResetToken(ctx context.Context, token *domain.PasswordResetToken) error {
	query := `
		INSERT INTO password_reset_tokens (
			id, user_id, token_hash, expires_at, used, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)`

	q := getQuerier(ctx, r.db)
	_, err := q.ExecContext(ctx, query,
		token.ID, token.UserID, token.TokenHash, token.ExpiresAt,
		token.Used, token.CreatedAt, token.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create password reset token: %w", err)
	}
	return nil
}

// GetPasswordResetToken retrieves a password reset token by hash
func (r *TokenRepository) GetPasswordResetToken(ctx context.Context, tokenHash string) (*domain.PasswordResetToken, error) {
	query := `
		SELECT id, user_id, token_hash, expires_at, used, used_at, created_at, updated_at
		FROM password_reset_tokens WHERE token_hash = $1`

	token := &domain.PasswordResetToken{}
	q := getQuerier(ctx, r.db)
	err := q.GetContext(ctx, token, query, tokenHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.TokenInvalid()
		}
		return nil, fmt.Errorf("failed to get password reset token: %w", err)
	}
	return token, nil
}

// GetPasswordResetTokenByID looks up a stored password-reset row by its UUID,
// which is the JWT `jti`. Used by AuthService.ResetPassword to enforce
// single-use semantics — the previous flow validated the JWT but never
// consulted the row, so a leaked reset link was replayable until expiry
// (AUDIT 1.1).
func (r *TokenRepository) GetPasswordResetTokenByID(ctx context.Context, id types.ID) (*domain.PasswordResetToken, error) {
	query := `
		SELECT id, user_id, token_hash, expires_at, used, used_at, created_at, updated_at
		FROM password_reset_tokens WHERE id = $1`

	token := &domain.PasswordResetToken{}
	q := getQuerier(ctx, r.db)
	err := q.GetContext(ctx, token, query, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.TokenInvalid()
		}
		return nil, fmt.Errorf("failed to get password reset token by id: %w", err)
	}
	return token, nil
}

// MarkPasswordResetTokenUsed marks a password reset token as used
func (r *TokenRepository) MarkPasswordResetTokenUsed(ctx context.Context, id types.ID) error {
	query := `UPDATE password_reset_tokens SET used = true, used_at = NOW(), updated_at = NOW() WHERE id = $1`

	q := getQuerier(ctx, r.db)
	_, err := q.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to mark password reset token used: %w", err)
	}
	return nil
}

// InvalidateUserPasswordResetTokens invalidates all password reset tokens for a user
func (r *TokenRepository) InvalidateUserPasswordResetTokens(ctx context.Context, userID types.ID) error {
	query := `UPDATE password_reset_tokens SET used = true, updated_at = NOW() WHERE user_id = $1 AND used = false`

	q := getQuerier(ctx, r.db)
	_, err := q.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to invalidate password reset tokens: %w", err)
	}
	return nil
}

// CreateEmailVerificationToken creates an email verification token
func (r *TokenRepository) CreateEmailVerificationToken(ctx context.Context, token *domain.EmailVerificationToken) error {
	query := `
		INSERT INTO email_verification_tokens (
			id, user_id, email, token_hash, expires_at, used, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	q := getQuerier(ctx, r.db)
	_, err := q.ExecContext(ctx, query,
		token.ID, token.UserID, token.Email, token.TokenHash,
		token.ExpiresAt, token.Used, token.CreatedAt, token.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create email verification token: %w", err)
	}
	return nil
}

// GetEmailVerificationToken retrieves an email verification token by hash
func (r *TokenRepository) GetEmailVerificationToken(ctx context.Context, tokenHash string) (*domain.EmailVerificationToken, error) {
	query := `
		SELECT id, user_id, email, token_hash, expires_at, used, used_at, created_at, updated_at
		FROM email_verification_tokens WHERE token_hash = $1`

	token := &domain.EmailVerificationToken{}
	q := getQuerier(ctx, r.db)
	err := q.GetContext(ctx, token, query, tokenHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.TokenInvalid()
		}
		return nil, fmt.Errorf("failed to get email verification token: %w", err)
	}
	return token, nil
}

// GetEmailVerificationTokenByID looks up a stored verification row by its
// UUID (the JWT `jti`). Counterpart to GetPasswordResetTokenByID — see
// AUDIT 1.2.
func (r *TokenRepository) GetEmailVerificationTokenByID(ctx context.Context, id types.ID) (*domain.EmailVerificationToken, error) {
	query := `
		SELECT id, user_id, email, token_hash, expires_at, used, used_at, created_at, updated_at
		FROM email_verification_tokens WHERE id = $1`

	token := &domain.EmailVerificationToken{}
	q := getQuerier(ctx, r.db)
	err := q.GetContext(ctx, token, query, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.TokenInvalid()
		}
		return nil, fmt.Errorf("failed to get email verification token by id: %w", err)
	}
	return token, nil
}

// MarkEmailVerificationTokenUsed marks an email verification token as used
func (r *TokenRepository) MarkEmailVerificationTokenUsed(ctx context.Context, id types.ID) error {
	query := `UPDATE email_verification_tokens SET used = true, used_at = NOW(), updated_at = NOW() WHERE id = $1`

	q := getQuerier(ctx, r.db)
	_, err := q.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to mark email verification token used: %w", err)
	}
	return nil
}

// InvalidateUserEmailVerificationTokens invalidates all email verification tokens for a user
func (r *TokenRepository) InvalidateUserEmailVerificationTokens(ctx context.Context, userID types.ID) error {
	query := `UPDATE email_verification_tokens SET used = true, updated_at = NOW() WHERE user_id = $1 AND used = false`

	q := getQuerier(ctx, r.db)
	_, err := q.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to invalidate email verification tokens: %w", err)
	}
	return nil
}

// CreateSession creates a new session
func (r *TokenRepository) CreateSession(ctx context.Context, session *domain.Session) error {
	query := `
		INSERT INTO sessions (
			id, user_id, organization_id, refresh_token_id, device_info,
			ip_address, user_agent, location, last_activity_at, expires_at,
			terminated, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`

	q := getQuerier(ctx, r.db)
	_, err := q.ExecContext(ctx, query,
		session.ID, session.UserID, session.OrganizationID, session.RefreshTokenID,
		session.DeviceInfo, session.IPAddress, session.UserAgent, session.Location,
		session.LastActivityAt, session.ExpiresAt, session.Terminated,
		session.CreatedAt, session.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	return nil
}

// GetSession retrieves a session by ID
func (r *TokenRepository) GetSession(ctx context.Context, id types.ID) (*domain.Session, error) {
	query := `
		SELECT id, user_id, organization_id, refresh_token_id, device_info,
			ip_address, user_agent, location, last_activity_at, expires_at,
			terminated, terminated_at, created_at, updated_at
		FROM sessions WHERE id = $1`

	session := &domain.Session{}
	q := getQuerier(ctx, r.db)
	err := q.GetContext(ctx, session, query, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.NotFound("Session")
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}
	return session, nil
}

// UpdateSession updates a session
func (r *TokenRepository) UpdateSession(ctx context.Context, session *domain.Session) error {
	query := `
		UPDATE sessions SET
			last_activity_at = $2, terminated = $3, terminated_at = $4, updated_at = NOW()
		WHERE id = $1`

	q := getQuerier(ctx, r.db)
	_, err := q.ExecContext(ctx, query,
		session.ID, session.LastActivityAt, session.Terminated, NullTime(session.TerminatedAt),
	)
	if err != nil {
		return fmt.Errorf("failed to update session: %w", err)
	}
	return nil
}

// TerminateSession terminates a session
func (r *TokenRepository) TerminateSession(ctx context.Context, id types.ID) error {
	query := `UPDATE sessions SET terminated = true, terminated_at = NOW(), updated_at = NOW() WHERE id = $1`

	q := getQuerier(ctx, r.db)
	_, err := q.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to terminate session: %w", err)
	}
	return nil
}

// TerminateAllUserSessions terminates all sessions for a user
func (r *TokenRepository) TerminateAllUserSessions(ctx context.Context, userID types.ID) error {
	query := `UPDATE sessions SET terminated = true, terminated_at = NOW(), updated_at = NOW() WHERE user_id = $1 AND terminated = false`

	q := getQuerier(ctx, r.db)
	_, err := q.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to terminate all user sessions: %w", err)
	}
	return nil
}

// ListUserSessions lists active sessions for a user
func (r *TokenRepository) ListUserSessions(ctx context.Context, userID types.ID) ([]*domain.Session, error) {
	query := `
		SELECT id, user_id, organization_id, refresh_token_id, device_info,
			ip_address, user_agent, location, last_activity_at, expires_at,
			terminated, terminated_at, created_at, updated_at
		FROM sessions
		WHERE user_id = $1 AND terminated = false AND expires_at > NOW()
		ORDER BY last_activity_at DESC`

	var sessions []*domain.Session
	q := getQuerier(ctx, r.db)
	if err := q.SelectContext(ctx, &sessions, query, userID); err != nil {
		return nil, fmt.Errorf("failed to list user sessions: %w", err)
	}
	return sessions, nil
}
