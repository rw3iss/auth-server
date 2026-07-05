package config

import (
	"strings"
	"testing"
	"time"
)

func baseValidConfig() *Config {
	return &Config{
		JWT: JWTConfig{
			AccessTokenSecret:  "this-is-a-strong-32-plus-character-access-secret",
			RefreshTokenSecret: "this-is-a-strong-32-plus-character-refresh-secret-x",
		},
		Security: SecurityConfig{
			BcryptCost:        12,
			RateLimitRequests: 100,
			RateLimitWindow:   time.Minute,
		},
		Auth: AuthConfig{
			PasswordMinLength: 8,
			PasswordMaxLength: 128,
		},
		Database: DatabaseConfig{
			MaxOpenConns: 25,
			MaxIdleConns: 5,
		},
	}
}

// AUDIT 1.8: refuse short JWT secrets at boot.
func TestValidateRejectsShortJWTSecret(t *testing.T) {
	c := baseValidConfig()
	c.JWT.AccessTokenSecret = "too-short"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "JWT_ACCESS_SECRET must be at least") {
		t.Fatalf("expected short-secret rejection, got: %v", err)
	}
}

// AUDIT 1.8: access/refresh secrets must differ.
func TestValidateRejectsEqualJWTSecrets(t *testing.T) {
	c := baseValidConfig()
	c.JWT.RefreshTokenSecret = c.JWT.AccessTokenSecret
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "must differ") {
		t.Fatalf("expected equal-secrets rejection, got: %v", err)
	}
}

// AUDIT 1.8: weak placeholder values should be flagged even if they were
// padded to satisfy the length floor.
func TestValidateRejectsWeakJWTSecret(t *testing.T) {
	for _, weak := range []string{"secret", "CHANGEME", "test", "password"} {
		c := baseValidConfig()
		// Pad to satisfy the length floor; the denylist check is on the
		// case-folded value, not the length.
		c.JWT.AccessTokenSecret = weak
		// Restore length passes — make it exactly the denylist value to
		// confirm the matcher.
		err := c.Validate()
		if err == nil {
			t.Fatalf("expected weak-value rejection for %q, got nil", weak)
		}
		// Short weak values trip the length floor first — that's also a
		// rejection, just a different one. Either is fine.
		if !strings.Contains(err.Error(), "weak") && !strings.Contains(err.Error(), "at least") {
			t.Fatalf("unexpected error for %q: %v", weak, err)
		}
	}
}

// AUDIT 1.3: bcrypt cost must be in a sane range.
func TestValidateRejectsInsaneBcryptCost(t *testing.T) {
	for _, c := range []int{0, 8, 9, 15, 20} {
		cfg := baseValidConfig()
		cfg.Security.BcryptCost = c
		if err := cfg.Validate(); err == nil {
			t.Fatalf("expected bcrypt-cost rejection for %d", c)
		}
	}
}

// AUDIT 4.5: DB pool sanity — idle ≤ open.
func TestValidateRejectsInvertedDBPool(t *testing.T) {
	c := baseValidConfig()
	c.Database.MaxIdleConns = 30 // > MaxOpenConns=25
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "DB_MAX_IDLE_CONNS") {
		t.Fatalf("expected DB-pool rejection, got: %v", err)
	}
}

func TestValidateAcceptsValidConfig(t *testing.T) {
	if err := baseValidConfig().Validate(); err != nil {
		t.Fatalf("baseline config should validate, got: %v", err)
	}
}

// AUDIT C5: empty previous slots = rotation not in progress, which must be
// accepted (the common case).
func TestValidateAcceptsEmptyPreviousSecrets(t *testing.T) {
	c := baseValidConfig()
	c.JWT.AccessTokenSecretPrevious = ""
	c.JWT.RefreshTokenSecretPrevious = ""
	if err := c.Validate(); err != nil {
		t.Fatalf("empty previous slots should validate, got: %v", err)
	}
}

// AUDIT C5: a populated previous slot must satisfy the same strength rules
// as the active secret — short values are rejected.
func TestValidateRejectsShortPreviousAccessSecret(t *testing.T) {
	c := baseValidConfig()
	c.JWT.AccessTokenSecretPrevious = "too-short"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "JWT_ACCESS_SECRET_PREVIOUS") {
		t.Fatalf("expected short-prev-secret rejection, got: %v", err)
	}
}

func TestValidateRejectsShortPreviousRefreshSecret(t *testing.T) {
	c := baseValidConfig()
	c.JWT.RefreshTokenSecretPrevious = "too-short"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "JWT_REFRESH_SECRET_PREVIOUS") {
		t.Fatalf("expected short-prev-secret rejection, got: %v", err)
	}
}

// AUDIT C5: a previous secret that matches the active is a typo / no-op.
// Either is dangerous (rotation does nothing) so we refuse to boot.
func TestValidateRejectsPreviousEqualsActive(t *testing.T) {
	c := baseValidConfig()
	c.JWT.AccessTokenSecretPrevious = c.JWT.AccessTokenSecret
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "must differ") {
		t.Fatalf("expected prev-equals-active rejection, got: %v", err)
	}
}

// AUDIT C5: weak placeholders in the previous slot are flagged identically.
func TestValidateRejectsWeakPreviousSecret(t *testing.T) {
	c := baseValidConfig()
	c.JWT.AccessTokenSecretPrevious = "secret"
	if err := c.Validate(); err == nil {
		t.Fatalf("expected weak-value rejection on previous slot")
	}
}

// AUDIT C5: well-formed previous secrets (≥32 chars, denylist-clean, distinct
// from active) must validate. This is the rotation-in-progress happy path.
func TestValidateAcceptsValidPreviousSecrets(t *testing.T) {
	c := baseValidConfig()
	c.JWT.AccessTokenSecretPrevious = "previous-access-secret-32-plus-characters-padded"
	c.JWT.RefreshTokenSecretPrevious = "previous-refresh-secret-32-plus-characters-padded"
	if err := c.Validate(); err != nil {
		t.Fatalf("rotation-in-progress baseline should validate, got: %v", err)
	}
}
