//go:build integration

package tests

import (
	"net/http"
	"testing"

	"github.com/ven/auth/tests/specs/helpers"
)

func TestGetSessions_Success(t *testing.T) {
	env := helpers.NewTestEnvironment(t)
	user := helpers.RegisterAndLogin(t, env.Client)

	env.Client.SetToken(user.AccessToken)
	defer env.Client.ClearToken()

	resp := env.Client.GetSessions(t)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d: %s", resp.StatusCode, string(resp.Body))
	}

	var sessions []map[string]interface{}
	if err := resp.JSON(&sessions); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if len(sessions) == 0 {
		t.Error("Expected at least one session")
	}
}

func TestTerminateSession_Success(t *testing.T) {
	env := helpers.NewTestEnvironment(t)
	user := helpers.RegisterAndLogin(t, env.Client)

	env.Client.SetToken(user.AccessToken)
	defer env.Client.ClearToken()

	// Get sessions
	resp := env.Client.GetSessions(t)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Failed to get sessions: %d", resp.StatusCode)
	}

	var sessions []struct {
		ID        string `json:"id"`
		IsCurrent bool   `json:"is_current"`
	}
	if err := resp.JSON(&sessions); err != nil {
		t.Fatalf("Failed to parse sessions: %v", err)
	}

	if len(sessions) == 0 {
		t.Fatal("No sessions found")
	}

	// Terminate the session
	sessionID := sessions[0].ID
	resp = env.Client.TerminateSession(t, sessionID)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d: %s", resp.StatusCode, string(resp.Body))
	}
}

func TestLogoutAll_Success(t *testing.T) {
	env := helpers.NewTestEnvironment(t)
	user := helpers.RegisterAndLogin(t, env.Client)

	env.Client.SetToken(user.AccessToken)

	// Logout all
	resp := env.Client.LogoutAll(t)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d: %s", resp.StatusCode, string(resp.Body))
	}

	env.Client.ClearToken()

	// Refresh token should no longer work
	resp = env.Client.RefreshToken(t, user.RefreshToken, "")
	if resp.StatusCode == http.StatusOK {
		t.Error("Expected refresh to fail after logout all")
	}
}

func TestGetSessions_Unauthenticated(t *testing.T) {
	env := helpers.NewTestEnvironment(t)

	resp := env.Client.GetSessions(t)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", resp.StatusCode)
	}
}
