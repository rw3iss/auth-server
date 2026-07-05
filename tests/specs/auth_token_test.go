//go:build integration

package tests

import (
	"net/http"
	"testing"

	"github.com/rw3iss/auth/tests/specs/helpers"
)

func TestRefreshToken_Success(t *testing.T) {
	env := helpers.NewTestEnvironment(t)
	user := helpers.RegisterAndLogin(t, env.Client)

	resp := env.Client.RefreshToken(t, user.RefreshToken, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d: %s", resp.StatusCode, string(resp.Body))
	}

	var result struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if err := resp.JSON(&result); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if result.AccessToken == "" {
		t.Error("Expected non-empty new access token")
	}
	if result.RefreshToken == "" {
		t.Error("Expected non-empty new refresh token")
	}
	if result.AccessToken == user.AccessToken {
		t.Error("Expected new access token to differ from original")
	}
}

func TestRefreshToken_RevokedToken(t *testing.T) {
	env := helpers.NewTestEnvironment(t)
	user := helpers.RegisterAndLogin(t, env.Client)

	// Logout to revoke the refresh token
	env.Client.Logout(t, user.RefreshToken)

	// Try to refresh with revoked token
	resp := env.Client.RefreshToken(t, user.RefreshToken, "")
	if resp.StatusCode == http.StatusOK {
		t.Error("Expected refresh to fail with revoked token")
	}
}

func TestRefreshToken_InvalidToken(t *testing.T) {
	env := helpers.NewTestEnvironment(t)

	resp := env.Client.RefreshToken(t, "invalid-token-value", "")
	if resp.StatusCode == http.StatusOK {
		t.Error("Expected refresh to fail with invalid token")
	}
}

func TestValidateToken_Success(t *testing.T) {
	env := helpers.NewTestEnvironment(t)
	user := helpers.RegisterAndLogin(t, env.Client)

	resp := env.Client.ValidateToken(t, user.AccessToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d: %s", resp.StatusCode, string(resp.Body))
	}

	var result struct {
		Valid       bool     `json:"valid"`
		UserID     string   `json:"user_id"`
		Email      string   `json:"email"`
		Roles      []string `json:"roles"`
		Permissions []string `json:"permissions"`
	}
	if err := resp.JSON(&result); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if !result.Valid {
		t.Error("Expected token to be valid")
	}
	if result.Email != user.Email {
		t.Errorf("Expected email %s, got %s", user.Email, result.Email)
	}
}

func TestValidateToken_InvalidToken(t *testing.T) {
	env := helpers.NewTestEnvironment(t)

	resp := env.Client.ValidateToken(t, "invalid-token")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	var result struct {
		Valid bool `json:"valid"`
	}
	if err := resp.JSON(&result); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if result.Valid {
		t.Error("Expected invalid token to return valid=false")
	}
}
