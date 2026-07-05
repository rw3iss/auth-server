//go:build integration

package tests

import (
	"net/http"
	"testing"

	"github.com/ven/auth/tests/specs/helpers"
)

func TestLogin_Success(t *testing.T) {
	env := helpers.NewTestEnvironment(t)
	user := helpers.NewTestUser()

	// Register
	resp := env.Client.Register(t, user.RegisterInput())
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Registration failed: %d", resp.StatusCode)
	}

	// Login
	resp = env.Client.Login(t, user.LoginInput())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d: %s", resp.StatusCode, string(resp.Body))
	}

	var result struct {
		User struct {
			Email string `json:"email"`
		} `json:"user"`
		Tokens struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			TokenType    string `json:"token_type"`
			ExpiresIn    int64  `json:"expires_in"`
		} `json:"tokens"`
		Roles []string `json:"roles"`
	}
	if err := resp.JSON(&result); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if result.User.Email != user.Email {
		t.Errorf("Expected email %s, got %s", user.Email, result.User.Email)
	}
	if result.Tokens.AccessToken == "" {
		t.Error("Expected non-empty access token")
	}
	if result.Tokens.RefreshToken == "" {
		t.Error("Expected non-empty refresh token")
	}
	if result.Tokens.TokenType != "Bearer" {
		t.Errorf("Expected token type Bearer, got %s", result.Tokens.TokenType)
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	env := helpers.NewTestEnvironment(t)
	user := helpers.NewTestUser()

	// Register
	resp := env.Client.Register(t, user.RegisterInput())
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Registration failed: %d", resp.StatusCode)
	}

	// Login with wrong password
	resp = env.Client.Login(t, map[string]interface{}{
		"email":    user.Email,
		"password": "WrongPassword123!",
	})

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d: %s", resp.StatusCode, string(resp.Body))
	}
}

func TestLogin_AccountLockout(t *testing.T) {
	env := helpers.NewTestEnvironment(t)
	user := helpers.NewTestUser()

	// Register
	resp := env.Client.Register(t, user.RegisterInput())
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Registration failed: %d", resp.StatusCode)
	}

	maxAttempts := env.Config.Auth.MaxLoginAttempts

	// Attempt login with wrong password multiple times
	for i := 0; i < maxAttempts; i++ {
		env.Client.Login(t, map[string]interface{}{
			"email":    user.Email,
			"password": "WrongPassword123!",
		})
	}

	// Next attempt should show locked
	resp = env.Client.Login(t, map[string]interface{}{
		"email":    user.Email,
		"password": "WrongPassword123!",
	})

	if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status 403 or 401 after lockout, got %d: %s", resp.StatusCode, string(resp.Body))
	}
}

func TestLogin_RememberMe(t *testing.T) {
	env := helpers.NewTestEnvironment(t)
	user := helpers.NewTestUser()

	// Register
	resp := env.Client.Register(t, user.RegisterInput())
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Registration failed: %d", resp.StatusCode)
	}

	// Login with remember me
	input := user.LoginInput()
	input["remember_me"] = true
	resp = env.Client.Login(t, input)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d: %s", resp.StatusCode, string(resp.Body))
	}

	var result struct {
		Tokens struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		} `json:"tokens"`
	}
	if err := resp.JSON(&result); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if result.Tokens.RefreshToken == "" {
		t.Error("Expected non-empty refresh token with remember_me")
	}
}
