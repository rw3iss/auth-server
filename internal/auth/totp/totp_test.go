package totp

import (
	"testing"
	"time"

	otp_pkg "github.com/pquerna/otp"
	totp_pkg "github.com/pquerna/otp/totp"
)

// AUDIT C4: Setup produces a non-empty base32 secret + a parseable
// otpauth://totp/... provisioning URI. The URI must carry our Issuer.
func TestSetupProducesUsableSecret(t *testing.T) {
	r, err := Setup("user@example.com")
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if r.Secret == "" {
		t.Fatal("setup secret should not be empty")
	}
	if r.ProvisioningURI == "" {
		t.Fatal("provisioning URI should not be empty")
	}
	if !contains(r.ProvisioningURI, Issuer) {
		t.Fatalf("provisioning URI should embed issuer %q: %s", Issuer, r.ProvisioningURI)
	}
}

// AUDIT C4: a freshly-issued code (computed against the same secret) must
// validate. This is the core enrollment property — without it, no user could
// complete VerifyAndEnableTwoFactor.
func TestValidateAcceptsCurrentCode(t *testing.T) {
	r, err := Setup("user@example.com")
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	code, err := totp_pkg.GenerateCode(r.Secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	if !Validate(code, r.Secret) {
		t.Fatal("freshly generated code must validate")
	}
}

// AUDIT C4: a stale code (well outside the drift window) must NOT validate.
// This catches the "we accidentally set window=0xFFFF" misconfiguration.
func TestValidateRejectsExpiredCode(t *testing.T) {
	r, err := Setup("user@example.com")
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	// Generate a code 10 minutes in the past — 20 steps before now, well
	// beyond the ±1-step Window.
	pastCode, err := totp_pkg.GenerateCode(r.Secret, time.Now().Add(-10*time.Minute))
	if err != nil {
		t.Fatalf("generate stale code: %v", err)
	}
	if Validate(pastCode, r.Secret) {
		t.Fatal("stale code must not validate")
	}
}

// AUDIT C4: a six-digit code computed from a DIFFERENT secret must fail.
// This is the "code from someone else's authenticator" check.
func TestValidateRejectsForeignCode(t *testing.T) {
	r1, _ := Setup("user@example.com")
	r2, _ := Setup("attacker@example.com")
	code, err := totp_pkg.GenerateCode(r2.Secret, time.Now())
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if Validate(code, r1.Secret) {
		t.Fatal("code from a different secret must not validate")
	}
}

// AUDIT C4: empty inputs short-circuit to false without panicking. Defends
// against a future call site that passes "" for the secret (e.g., a user row
// where 2FA was never set up).
func TestValidateEmptyInputs(t *testing.T) {
	if Validate("", "secret") {
		t.Fatal("empty code must fail")
	}
	if Validate("123456", "") {
		t.Fatal("empty secret must fail")
	}
}

// AUDIT C4: validate the algorithm choice — SHA1 is what every major
// authenticator app defaults to. A future change here would silently break
// every existing user's enrolled secret, so we pin it via a test.
func TestDefaultAlgorithm(t *testing.T) {
	r, err := Setup("user@example.com")
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	// Re-parse the URI and confirm algorithm/digits/period.
	key, err := otp_pkg.NewKeyFromURL(r.ProvisioningURI)
	if err != nil {
		t.Fatalf("parse URI: %v", err)
	}
	if key.Algorithm() != otp_pkg.AlgorithmSHA1 {
		t.Errorf("expected SHA1 algorithm, got %v", key.Algorithm())
	}
	if key.Digits() != otp_pkg.DigitsSix {
		t.Errorf("expected 6 digits, got %v", key.Digits())
	}
	if key.Period() != 30 {
		t.Errorf("expected 30s period, got %d", key.Period())
	}
}

func contains(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
