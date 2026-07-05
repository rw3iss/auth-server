// Package totp wraps pquerna/otp with the small surface area the auth-server
// needs for TOTP 2FA (AUDIT C4): generate a secret + provisioning URI for
// enrollment, verify a 6-digit code at login, and refuse codes outside the
// configured window so old SMS-style replays don't slip through.
//
// We don't store backup codes or HOTP counters in this first cut. Recovery
// (lost-device) goes through the password-reset flow + a support escalation;
// adding hashed backup codes is a follow-up that fits cleanly here when the
// product calls for it.
package totp

import (
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// Issuer is the value placed in the otpauth:// URI so the user's
// authenticator app labels the entry. Keeping it stable across rotations
// matters — changing it would create "ghost" entries in users' apps.
const Issuer = "rw3iss"

// Window controls clock-skew tolerance for code validation. We allow one
// 30-second step before and after the current step (total 90s drift), which
// is the pquerna/otp default and matches RFC 6238 §5.2 guidance.
const Window = 1

// SetupResult holds everything a client needs to display the enrollment UI.
// The provisioning URI is QR-renderable; the base32 secret is shown as a
// fallback when the user can't scan (manual entry into their authenticator).
type SetupResult struct {
	// Secret is the base32-encoded shared key. Caller stores this in
	// users.two_factor_secret. It MUST NOT leave the server outside the
	// initial setup response, and even then is sent over HTTPS only.
	Secret string
	// ProvisioningURI is the otpauth://totp/... URI for QR-code rendering.
	// The URI embeds issuer + account label + secret; clients should render
	// it to a QR image client-side rather than passing it to a remote QR
	// generator (which would leak the secret).
	ProvisioningURI string
}

// Setup generates a fresh TOTP secret for `accountLabel` (typically the
// user's email). The returned secret is base32-encoded so it can be embedded
// in the provisioning URI and stored verbatim in two_factor_secret.
//
// `accountLabel` becomes part of the provisioning URI's user-visible label —
// it's what the user will see in their authenticator app. Use the email
// (lowercased, no whitespace).
func Setup(accountLabel string) (*SetupResult, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      Issuer,
		AccountName: accountLabel,
		Algorithm:   otp.AlgorithmSHA1, // Google Authenticator / 1Password / Authy all default to SHA1
		Digits:      otp.DigitsSix,
		Period:      30,
	})
	if err != nil {
		return nil, err
	}
	return &SetupResult{
		Secret:          key.Secret(),
		ProvisioningURI: key.URL(),
	}, nil
}

// Validate returns true when `code` is the current TOTP for `secret`, within
// the configured drift Window. Used both at enrollment confirmation and at
// every subsequent login. Constant-time comparison is handled internally by
// pquerna/otp.
func Validate(code, secret string) bool {
	if code == "" || secret == "" {
		return false
	}
	valid, _ := totp.ValidateCustom(code, secret, timeNow(), totp.ValidateOpts{
		Period:    30,
		Skew:      Window,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	return valid
}
