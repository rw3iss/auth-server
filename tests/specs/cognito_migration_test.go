//go:build integration_cognito

// Cognito migration integration tests.
//
// These exercise the real pkg/migration/cognito.Adapter against an actual
// AWS Cognito user pool. They're behind their own build tag —
// `integration_cognito` — so:
//
//   - The regular `go test` runs (no build tags) ignore them; PRs and
//     dev builds aren't slowed by network calls.
//   - `make test-integration` (which uses the `integration` tag) also
//     ignores them; the standard integration suite stays hermetic
//     against Postgres + Redis without external dependencies.
//   - Running `go test -tags integration_cognito` opts in. Tests skip
//     silently when the required env vars are absent, so you can
//     activate the tag in CI without breaking anything.
//
// Local setup:
//
//   1. Copy tests/.env.test.cognito.example → tests/.env.test.cognito
//   2. Fill in COGNITO_USER_POOL_ID / COGNITO_CLIENT_ID / etc.
//   3. AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY are picked up from the
//      standard AWS credential chain — set them in .env.test.cognito or
//      use ~/.aws/credentials.
//   4. Run: go test -tags integration_cognito ./tests/specs/...
//
// The .env.test.cognito file is gitignored. Credentials shared via
// chat are dev-only; rotate if exposed in a public PR.

package tests

import (
	"bufio"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rw3iss/auth/pkg/migration"
	"github.com/rw3iss/auth/pkg/migration/cognito"
)

// loadCognitoEnv loads tests/.env.test.cognito into the process env if it
// exists. Returns true when the file was found and parsed. Tests use this
// to set env at startup; missing file → tests skip.
func loadCognitoEnv(t *testing.T) bool {
	t.Helper()
	// Find the repo root by walking up from $PWD until we hit go.mod.
	dir, _ := os.Getwd()
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			break
		}
		dir = filepath.Dir(dir)
	}
	envFile := filepath.Join(dir, "tests", ".env.test.cognito")
	f, err := os.Open(envFile)
	if err != nil {
		return false
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx < 1 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
			val = val[1 : len(val)-1]
		}
		// Explicit env wins over the file.
		if _, present := os.LookupEnv(key); !present {
			_ = os.Setenv(key, val)
		}
	}
	return true
}

// cognitoTestConfig returns the adapter config or skips the test when
// any required field is missing. Centralised so every test in this file
// has the same skip-or-run decision.
func cognitoTestConfig(t *testing.T) cognito.Config {
	t.Helper()
	loadCognitoEnv(t)
	cfg := cognito.Config{
		Region:       os.Getenv("COGNITO_REGION"),
		UserPoolID:   os.Getenv("COGNITO_USER_POOL_ID"),
		ClientID:     os.Getenv("COGNITO_CLIENT_ID"),
		ClientSecret: os.Getenv("COGNITO_CLIENT_SECRET"),
	}
	if cfg.Region == "" || cfg.UserPoolID == "" || cfg.ClientID == "" {
		t.Skip("Cognito test env not configured (see tests/.env.test.cognito.example)")
	}
	return cfg
}

// TestCognitoAdapter_UnknownEmail exercises an email that doesn't exist
// in the pool. The expected error depends on Cognito's
// PreventUserExistenceErrors setting on the app client:
//
//   - When PreventUserExistenceErrors=Enabled (default for new pools, and
//     the security best practice), Cognito intentionally collapses
//     "user not found" into "wrong password" via NotAuthorizedException
//     so attackers can't enumerate users. Our adapter maps that to
//     ErrLegacyLoginFailed.
//
//   - When the pool predates this setting (or it's explicitly disabled),
//     UserNotFoundException reaches us and we return ErrLegacyUserNotFound.
//
// Either is a valid migration-fail outcome — AuthService surfaces both
// as InvalidCredentials on the wire so the response shape is uniform.
// What the adapter MUST NOT do is leak a generic error or panic.
func TestCognitoAdapter_UnknownEmail(t *testing.T) {
	cfg := cognitoTestConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	adapter, err := cognito.New(ctx, cfg)
	if err != nil {
		t.Fatalf("cognito.New: %v", err)
	}
	_, err = adapter.TryLogin(ctx, "definitely-not-a-real-user-12345@example.com", "any-password")
	if !errors.Is(err, migration.ErrLegacyUserNotFound) && !errors.Is(err, migration.ErrLegacyLoginFailed) {
		t.Fatalf("expected ErrLegacyUserNotFound or ErrLegacyLoginFailed, got %v", err)
	}
}

// TestCognitoAdapter_WrongPassword: an existing user with a wrong password
// must surface ErrLegacyLoginFailed (NotAuthorized), distinct from
// not-found. AuthService maps both to InvalidCredentials on the wire so
// the response shape stays identical — but the adapter should still draw
// the line internally for audit visibility.
func TestCognitoAdapter_WrongPassword(t *testing.T) {
	cfg := cognitoTestConfig(t)
	email := os.Getenv("COGNITO_TEST_SELLER_EMAIL")
	if email == "" {
		t.Skip("COGNITO_TEST_SELLER_EMAIL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	adapter, err := cognito.New(ctx, cfg)
	if err != nil {
		t.Fatalf("cognito.New: %v", err)
	}
	_, err = adapter.TryLogin(ctx, email, "definitely-not-the-real-password-abc123")
	if !errors.Is(err, migration.ErrLegacyLoginFailed) {
		t.Fatalf("expected ErrLegacyLoginFailed for wrong password, got %v", err)
	}
}

// TestCognitoAdapter_SuccessfulLogin: when the demo seller user logs in
// with the correct password, the adapter returns a LegacyUser populated
// with email + name + roles. This test only runs when
// COGNITO_TEST_PASSWORD is set — without a real password we can't verify
// the success path, so we skip rather than fail. Set the password in
// tests/.env.test.cognito when you're running this locally.
func TestCognitoAdapter_SuccessfulLogin_Seller(t *testing.T) {
	cfg := cognitoTestConfig(t)
	password := os.Getenv("COGNITO_TEST_PASSWORD")
	email := os.Getenv("COGNITO_TEST_SELLER_EMAIL")
	if password == "" || email == "" {
		t.Skip("COGNITO_TEST_PASSWORD or COGNITO_TEST_SELLER_EMAIL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	adapter, err := cognito.New(ctx, cfg)
	if err != nil {
		t.Fatalf("cognito.New: %v", err)
	}
	user, err := adapter.TryLogin(ctx, email, password)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if user == nil {
		t.Fatal("nil user returned from successful login")
	}
	if !strings.EqualFold(user.Email, email) {
		t.Fatalf("email mismatch: got %q want %q", user.Email, email)
	}
	// The demo seller account should carry a SELLER group at minimum.
	// Use a soft assertion — we don't want this to fail if the seed
	// drifts; we just log it.
	hasSeller := false
	for _, r := range user.Roles {
		if strings.EqualFold(r, "seller") || strings.EqualFold(r, "SELLER") {
			hasSeller = true
			break
		}
	}
	if !hasSeller {
		t.Logf("warning: seller demo account has no SELLER group; got %v", user.Roles)
	}
}

// TestCognitoAdapter_DefaultRoleMapper_AppliesToRoles: end-to-end check
// that the role mapper correctly translates Cognito group names into
// internal role codes. Doesn't need credentials — runs against a
// fabricated LegacyUser.
func TestCognitoAdapter_DefaultRoleMapper_AppliesToRoles(t *testing.T) {
	mapper := migration.DefaultRoleMapper{}
	got := mapper.Map([]string{"SELLER", "SUPER_ADMIN", "SELLERADMIN"})

	expectedAny := map[string]bool{
		"seller":      true,
		"super_admin": true,
		"org_admin":   true, // SELLERADMIN expands to seller + org_admin
	}
	for _, code := range got {
		delete(expectedAny, code)
	}
	if len(expectedAny) > 0 {
		t.Fatalf("missing expected role mappings: %v (got %v)", expectedAny, got)
	}
	// And system_admin must never appear — defense check.
	for _, code := range got {
		if code == "system_admin" {
			t.Fatalf("DefaultRoleMapper produced system_admin from %v — must never happen", got)
		}
	}
}
