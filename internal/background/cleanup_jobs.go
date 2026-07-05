package background

import (
	"context"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
)

// cleanup_jobs.go: concrete Job implementations for the housekeeping tasks
// that previously had no scheduler attached.
//
// Each job is a thin wrapper around a single DELETE / UPDATE statement;
// schemas already have the necessary timestamp columns. The Scheduler
// handles timing, status, manual triggers, and pause/resume — these
// implementations only know "how to do the work."

// RefreshTokenCleanup deletes expired refresh tokens and revoked tokens
// older than 30 days. Mirrors the existing TokenRepository.CleanupExpiredTokens
// query but exposes it as a managed Job.
type RefreshTokenCleanup struct {
	DB       *sqlx.DB
	Every    time.Duration // typically hourly; configurable
}

func (j *RefreshTokenCleanup) Name() string             { return "cleanup.refresh_tokens" }
func (j *RefreshTokenCleanup) Interval() time.Duration  { return j.Every }
func (j *RefreshTokenCleanup) Run(ctx context.Context) error {
	const q = `DELETE FROM refresh_tokens
		WHERE expires_at < NOW()
		   OR (revoked = true AND revoked_at < NOW() - INTERVAL '30 days')`
	_, err := j.DB.ExecContext(ctx, q)
	if err != nil {
		return fmt.Errorf("refresh-token cleanup: %w", err)
	}
	return nil
}

// SessionCleanup terminates sessions whose expires_at is in the past, and
// hard-deletes terminated sessions older than 30 days.
type SessionCleanup struct {
	DB    *sqlx.DB
	Every time.Duration
}

func (j *SessionCleanup) Name() string             { return "cleanup.sessions" }
func (j *SessionCleanup) Interval() time.Duration  { return j.Every }
func (j *SessionCleanup) Run(ctx context.Context) error {
	// Two-phase: mark expired sessions terminated, then prune old terminated rows.
	if _, err := j.DB.ExecContext(ctx, `
		UPDATE sessions SET terminated = true, terminated_at = NOW()
		WHERE terminated = false AND expires_at < NOW()`,
	); err != nil {
		return fmt.Errorf("session expire-update: %w", err)
	}
	if _, err := j.DB.ExecContext(ctx, `
		DELETE FROM sessions
		WHERE terminated = true AND terminated_at < NOW() - INTERVAL '30 days'`,
	); err != nil {
		return fmt.Errorf("session prune: %w", err)
	}
	return nil
}

// PasswordResetTokenCleanup removes expired and used-and-old password reset
// tokens. The `password_reset_tokens` table can otherwise grow indefinitely
// since the JWT and the stored row are 1:1.
type PasswordResetTokenCleanup struct {
	DB    *sqlx.DB
	Every time.Duration
}

func (j *PasswordResetTokenCleanup) Name() string             { return "cleanup.password_reset_tokens" }
func (j *PasswordResetTokenCleanup) Interval() time.Duration  { return j.Every }
func (j *PasswordResetTokenCleanup) Run(ctx context.Context) error {
	const q = `DELETE FROM password_reset_tokens
		WHERE expires_at < NOW()
		   OR (used = true AND used_at < NOW() - INTERVAL '7 days')`
	_, err := j.DB.ExecContext(ctx, q)
	return err
}

// EmailVerificationTokenCleanup mirrors the reset-token cleanup for the
// verification table. Same lifecycle pattern.
type EmailVerificationTokenCleanup struct {
	DB    *sqlx.DB
	Every time.Duration
}

func (j *EmailVerificationTokenCleanup) Name() string             { return "cleanup.email_verification_tokens" }
func (j *EmailVerificationTokenCleanup) Interval() time.Duration  { return j.Every }
func (j *EmailVerificationTokenCleanup) Run(ctx context.Context) error {
	const q = `DELETE FROM email_verification_tokens
		WHERE expires_at < NOW()
		   OR (used = true AND used_at < NOW() - INTERVAL '7 days')`
	_, err := j.DB.ExecContext(ctx, q)
	return err
}
