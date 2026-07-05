//go:build integration

package tests

import (
	"net/http"
	"testing"

	"github.com/rw3iss/auth/tests/specs/helpers"
)

func TestPasswordResetRequest_Success(t *testing.T) {
	env := helpers.NewTestEnvironment(t)
	user := helpers.NewTestUser()

	// Register
	resp := env.Client.Register(t, user.RegisterInput())
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Registration failed: %d", resp.StatusCode)
	}

	// Request password reset
	resp = env.Client.RequestPasswordReset(t, user.Email)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d: %s", resp.StatusCode, string(resp.Body))
	}
}

func TestPasswordResetRequest_NonexistentEmail(t *testing.T) {
	env := helpers.NewTestEnvironment(t)

	// Should still return 200 to prevent email enumeration
	resp := env.Client.RequestPasswordReset(t, "nonexistent@test.ven.com")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 even for nonexistent email, got %d", resp.StatusCode)
	}
}

func TestResetPassword_InvalidToken(t *testing.T) {
	env := helpers.NewTestEnvironment(t)

	resp := env.Client.ResetPassword(t, "invalid-reset-token", "NewP@ssword123!")
	if resp.StatusCode == http.StatusOK {
		t.Error("Expected reset to fail with invalid token")
	}
}

func TestChangePassword_Success(t *testing.T) {
	env := helpers.NewTestEnvironment(t)
	user := helpers.RegisterAndLogin(t, env.Client)

	env.Client.SetToken(user.AccessToken)
	defer env.Client.ClearToken()

	newPassword := "NewP@ssword456!"
	resp := env.Client.ChangePassword(t, user.Password, newPassword)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d: %s", resp.StatusCode, string(resp.Body))
	}

	// Verify old password no longer works
	env.Client.ClearToken()
	resp = env.Client.Login(t, map[string]interface{}{
		"email":    user.Email,
		"password": user.Password,
	})
	if resp.StatusCode == http.StatusOK {
		t.Error("Expected old password to fail after change")
	}

	// Verify new password works
	resp = env.Client.Login(t, map[string]interface{}{
		"email":    user.Email,
		"password": newPassword,
	})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected new password to work, got %d: %s", resp.StatusCode, string(resp.Body))
	}
}

func TestChangePassword_WrongCurrentPassword(t *testing.T) {
	env := helpers.NewTestEnvironment(t)
	user := helpers.RegisterAndLogin(t, env.Client)

	env.Client.SetToken(user.AccessToken)
	defer env.Client.ClearToken()

	resp := env.Client.ChangePassword(t, "WrongCurrent123!", "NewP@ssword456!")
	if resp.StatusCode == http.StatusOK {
		t.Error("Expected change to fail with wrong current password")
	}
}
