// Password lifecycle — reset request/completion and authenticated
// change. Split from auth_service.go (2026-06-11); shared
// state/helpers live there.
// Package service provides business logic services for the auth application
package auth

import (
	"context"

	"github.com/ven/auth/internal/audit"
	"github.com/ven/auth/pkg/shared/errors"
	"github.com/ven/auth/pkg/shared/types"
	"github.com/ven/auth/pkg/shared/utils"
)

// AuthService handles authentication business logic

func (s *AuthService) RequestPasswordReset(ctx context.Context, email, appCode string) error {
	normalizedEmail := types.Email(utils.NormalizeEmail(email))

	// Resolve within the app's read pools (migration 017) instead of a bare
	// default lookup, so a namespaced user (e.g. globalsku) can reset.
	user, err := s.userRepo.GetByEmailInNamespaces(ctx, normalizedEmail, s.resolveReadNamespaces(ctx, appCode))
	if err != nil {
		// Don't reveal if email exists
		return nil
	}

	token, err := s.jwtService.GeneratePasswordResetToken(ctx, user, s.cfg.Auth.PasswordResetExpiry)
	if err != nil {
		return errors.Internal("Failed to generate reset token")
	}

	if s.emailService != nil {
		return s.emailService.SendPasswordResetEmail(ctx, s.resolveAppBaseURL(ctx, appCode), string(user.Email), user.FirstName, token)
	}

	return nil
}

// resolveAppBaseURL looks up the app by code and returns its
// FrontendURL. Returns empty string when:
//   - appCode is empty
//   - AppService isn't wired
//   - lookup fails / app inactive / frontend_url unset
//
// Empty result is fine — the email layer falls back to CLIENT_URL.
// Intentionally swallows all errors: this is a UX hint for the email
// link, not a security boundary, and a bad app code shouldn't block
// the email from going out.

func (s *AuthService) ResetPassword(ctx context.Context, token string, newPassword string) error {
	claims, err := s.jwtService.ValidatePasswordResetToken(ctx, token)
	if err != nil {
		return err
	}

	// Validate new password
	pwResult := utils.ValidatePassword(newPassword, s.passwordPolicy())
	if !pwResult.IsValid {
		return errors.ValidationError("Password does not meet requirements")
	}

	// Parse the JWT id (stored row's UUID).
	tokenID, err := types.ParseID(claims.ID)
	if err != nil {
		return errors.TokenInvalid()
	}

	user, err := s.userRepo.GetByID(ctx, claims.UserID)
	if err != nil {
		return err
	}

	// Hash new password before opening the tx so we don't hold a connection
	// through bcrypt (~250ms at cost=12).
	passwordHash, err := s.hashPassword(newPassword)
	if err != nil {
		return errors.Internal("Failed to hash password")
	}

	err = s.txManager.WithTransaction(ctx, func(ctx context.Context) error {
		// AUDIT 1.1: single-use check. Look up the row and reject if
		// already used. The UserID match is defense-in-depth — the JWT was
		// already signature-verified against the user.
		stored, err := s.tokenRepo.GetPasswordResetTokenByID(ctx, tokenID)
		if err != nil {
			return errors.TokenInvalid()
		}
		if stored.Used {
			return errors.TokenInvalid()
		}
		if stored.UserID != claims.UserID {
			return errors.TokenInvalid()
		}

		user.SetPassword(passwordHash)
		now := types.Now()
		user.PasswordResetAt = &now

		if err := s.userRepo.Update(ctx, user); err != nil {
			return err
		}
		return s.tokenRepo.MarkPasswordResetTokenUsed(ctx, tokenID)
	})
	if err != nil {
		return err
	}

	// Revoke outstanding refresh tokens (best-effort — failure here does
	// not undo the password change, the user just retains an old session).
	_ = s.jwtService.RevokeAllUserTokens(ctx, user.ID, "password_reset")

	audit.Record(ctx, audit.Event{
		Action:      "password.reset",
		ActorUserID: &user.ID,
	})
	return nil
}

// VerifyEmail verifies a user's email.
//
// AUDIT 1.2: same single-use shape as ResetPassword. Lower stakes (worst
// case is re-verifying an already-verified email) but still wrong — a
// reused verify link after the user changed emails could re-verify an
// attacker-controlled address.

func (s *AuthService) ChangePassword(ctx context.Context, userID types.ID, currentPassword, newPassword string) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	// Verify current password
	if !utils.CheckPassword(currentPassword, user.PasswordHash) {
		return errors.InvalidCredentials()
	}

	// Validate new password
	pwResult := utils.ValidatePassword(newPassword, s.passwordPolicy())
	if !pwResult.IsValid {
		return errors.ValidationError("Password does not meet requirements")
	}

	// Hash new password
	passwordHash, err := s.hashPassword(newPassword)
	if err != nil {
		return errors.Internal("Failed to hash password")
	}

	user.SetPassword(passwordHash)
	if err := s.userRepo.Update(ctx, user); err != nil {
		return err
	}
	audit.Record(ctx, audit.Event{
		Action:      "password.change",
		ActorUserID: &user.ID,
	})
	return nil
}

// registerOrLogin is invoked from Register() when the email already exists
// and Mode == register_or_login. We attempt a login with the submitted
// password; on success we return the existing user + tokens (and clear the
// per-account attempts counter), on failure we surface an InvalidCredentials
// error so the response shape matches a plain failed login attempt.
//
// We do NOT touch the per-account rate limiter on this path because the
// AuthService.Login flow already does, and double-incrementing would unfairly
// penalize legit register-or-login flows.
