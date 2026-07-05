package utils

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// AUDIT 1.3: HashPassword must honor the cost parameter — historically it
// silently used bcrypt.DefaultCost (10) regardless of config.
func TestHashPasswordHonorsCost(t *testing.T) {
	hash, err := HashPassword("correct-horse-battery-staple", 12)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		t.Fatalf("bcrypt.Cost: %v", err)
	}
	if cost != 12 {
		t.Fatalf("expected cost=12, got %d", cost)
	}
}

func TestHashPasswordRejectsOutOfRangeCost(t *testing.T) {
	for _, c := range []int{0, 4, 9, 15, 32} {
		if _, err := HashPassword("anything", c); err == nil {
			t.Fatalf("expected error for cost=%d", c)
		}
	}
}

// AUDIT 1.4: cap the input length so a multi-MB password can't burn CPU
// on every login attempt.
func TestHashPasswordRejectsOverlongInput(t *testing.T) {
	long := strings.Repeat("a", MaxPasswordLength+1)
	if _, err := HashPassword(long, 10); err == nil {
		t.Fatal("expected length error for password > MaxPasswordLength")
	}
}

func TestCheckPasswordRejectsOverlongInput(t *testing.T) {
	hash, err := HashPassword("password123!", 10)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	long := strings.Repeat("a", MaxPasswordLength+1)
	if CheckPassword(long, hash) {
		t.Fatal("CheckPassword should reject overlong input without computing bcrypt")
	}
}

// AUDIT 1.5: the length-floor error message used `string(rune(minLength+'0'))`,
// producing garbage characters for any minLength ≥ 10. Verify the actual
// number renders for a non-trivial floor.
func TestValidatePasswordErrorMessageRendersNumber(t *testing.T) {
	res := ValidatePassword("Aa1", PasswordPolicy{MinLength: 12, RequireUpper: true, RequireLower: true, RequireDigit: true})
	if res.IsValid {
		t.Fatal("expected invalid for 3-char password against MinLength=12")
	}
	found := false
	for _, e := range res.Errors {
		if strings.Contains(e, "at least 12 characters") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected '...at least 12 characters' error, got: %v", res.Errors)
	}
}

func TestValidatePasswordRespectsMaxLength(t *testing.T) {
	long := strings.Repeat("Aa1!", 40) // 160 chars
	res := ValidatePassword(long, PasswordPolicy{MinLength: 8, MaxLength: 128, RequireUpper: true, RequireLower: true, RequireDigit: true})
	if res.IsValid {
		t.Fatal("expected invalid for password > MaxLength")
	}
	found := false
	for _, e := range res.Errors {
		if strings.Contains(e, "at most 128 characters") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected length-ceiling error, got: %v", res.Errors)
	}
}

func TestValidatePasswordCharClassToggles(t *testing.T) {
	// Operator who turned off the uppercase requirement should not get an
	// uppercase-required error.
	res := ValidatePassword("longenoughpw123", PasswordPolicy{
		MinLength: 8, RequireUpper: false, RequireLower: true, RequireDigit: true,
	})
	if !res.IsValid {
		t.Fatalf("expected valid with uppercase requirement off, got errors: %v", res.Errors)
	}

	// Same input with uppercase ON should fail with an uppercase-specific error.
	res = ValidatePassword("longenoughpw123", PasswordPolicy{
		MinLength: 8, RequireUpper: true, RequireLower: true, RequireDigit: true,
	})
	if res.IsValid {
		t.Fatal("expected invalid when missing required uppercase")
	}
	found := false
	for _, e := range res.Errors {
		if strings.Contains(strings.ToLower(e), "uppercase") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected uppercase-specific error, got: %v", res.Errors)
	}
}

// Back-compat: the legacy int-shape (`ValidatePassword(pw, 8)`) must still
// route to the default policy.
func TestValidatePasswordLegacyIntShape(t *testing.T) {
	res := ValidatePassword("ValidPass1", 8)
	if !res.IsValid {
		t.Fatalf("legacy shape rejected a valid password: %v", res.Errors)
	}
}
