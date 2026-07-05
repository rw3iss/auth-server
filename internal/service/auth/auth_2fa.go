// Two-factor authentication (TOTP) — setup, confirm-enable, disable.
// AUDIT C4. Split from auth_service.go (2026-06-11); shared
// state/helpers live there.
// Package service provides business logic services for the auth application
package auth

import (
	"context"

	"github.com/ven/auth/internal/audit"
	"github.com/ven/auth/internal/auth/totp"
	"github.com/ven/auth/pkg/shared/errors"
	"github.com/ven/auth/pkg/shared/types"
	"github.com/ven/auth/pkg/shared/utils"
)

// AuthService handles authentication business logic

type TwoFactorSetupResult struct {
	Secret          string `json:"secret"`
	ProvisioningURI string `json:"provisioning_uri"`
}

// SetupTwoFactor generates a fresh TOTP secret for the user and stashes it
// in users.two_factor_secret with TwoFactorEnabled=true but
// TwoFactorConfirmedAt=nil. The flow then waits for VerifyAndEnableTwoFactor
// to flip the confirmed-at timestamp; until that happens, login does NOT
// require a code (IsTwoFactorActive returns false). Re-running Setup on a
// half-enrolled user replaces the secret — useful when the user lost their
// QR scan before confirming.
//
// Refuses to run when 2FA is already fully active. To rotate, call Disable
// first.
func (s *AuthService) SetupTwoFactor(ctx context.Context, userID types.ID) (*TwoFactorSetupResult, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user.IsTwoFactorActive() {
		return nil, errors.New(errors.ErrCodeValidation, "2FA is already enabled; disable it first to re-enroll", 400)
	}
	setup, err := totp.Setup(string(user.Email))
	if err != nil {
		return nil, errors.Internal("Failed to generate TOTP secret")
	}
	user.TwoFactorSecret = setup.Secret
	user.TwoFactorEnabled = true    // provisionally; confirmation flips ConfirmedAt
	user.TwoFactorConfirmedAt = nil // explicit — not confirmed until Enable
	if err := s.userRepo.Update(ctx, user); err != nil {
		return nil, err
	}
	audit.Record(ctx, audit.Event{
		Action:      "2fa.setup_started",
		ActorUserID: &user.ID,
	})
	return &TwoFactorSetupResult{
		Secret:          setup.Secret,
		ProvisioningURI: setup.ProvisioningURI,
	}, nil
}

// VerifyAndEnableTwoFactor completes enrollment. The user submits a code
// from their authenticator; the server validates against the stashed
// secret and — on success — stamps TwoFactorConfirmedAt so subsequent
// logins require a code (AUDIT C4).
//
// Wrong code = no state change + 400. We deliberately don't burn a
// FailedLoginAttempt here because (a) the user is already authenticated
// (this is a protected endpoint) and (b) the secret is fresh, so a wrong
// code is almost always a transcription typo, not an attack.
func (s *AuthService) VerifyAndEnableTwoFactor(ctx context.Context, userID types.ID, code string) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	if user.TwoFactorSecret == "" {
		return errors.New(errors.ErrCodeValidation, "no pending 2FA enrollment; call Setup first", 400)
	}
	if !totp.Validate(code, user.TwoFactorSecret) {
		return errors.InvalidInput("code", "invalid TOTP code")
	}
	now := types.Now()
	user.TwoFactorEnabled = true
	user.TwoFactorConfirmedAt = &now
	if err := s.userRepo.Update(ctx, user); err != nil {
		return err
	}
	audit.Record(ctx, audit.Event{
		Action:      "2fa.enabled",
		ActorUserID: &user.ID,
	})
	return nil
}

// DisableTwoFactor turns 2FA off. Requires both the current password AND a
// fresh TOTP code (AUDIT C4) — without the password gate, a stolen access
// token would be enough to remove the second factor and pivot to a
// password-only takeover. We bump the user's token-version so any other
// outstanding session sees the 2FA-off state immediately (defensive: even
// if a session was already valid, it shouldn't keep operating in a
// "thought 2FA was still on" world).
func (s *AuthService) DisableTwoFactor(ctx context.Context, userID types.ID, password, code string) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	if !user.IsTwoFactorActive() {
		return errors.New(errors.ErrCodeValidation, "2FA is not active for this user", 400)
	}
	if !utils.CheckPassword(password, user.PasswordHash) {
		return errors.InvalidCredentials()
	}
	if !totp.Validate(code, user.TwoFactorSecret) {
		return errors.InvalidInput("code", "invalid TOTP code")
	}
	user.TwoFactorEnabled = false
	user.TwoFactorSecret = ""
	user.TwoFactorConfirmedAt = nil
	if err := s.userRepo.Update(ctx, user); err != nil {
		return err
	}
	// Bump token version: any other outstanding access token immediately
	// stops validating. The current session's token will also bounce on
	// next use, requiring re-login — that's fine for a security-sensitive
	// transition.
	_, _ = s.tokenCache.BumpUserTokenVersion(ctx, user.ID.String())
	audit.Record(ctx, audit.Event{
		Action:      "2fa.disabled",
		ActorUserID: &user.ID,
	})
	return nil
}
