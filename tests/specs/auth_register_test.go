//go:build integration

package tests

import (
	"net/http"
	"testing"

	"github.com/ven/auth/tests/specs/helpers"
)

func TestRegister_Success(t *testing.T) {
	env := helpers.NewTestEnvironment(t)
	user := helpers.NewTestUser()

	resp := env.Client.Register(t, user.RegisterInput())

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Expected status 201, got %d: %s", resp.StatusCode, string(resp.Body))
	}

	var result map[string]interface{}
	if err := resp.JSON(&result); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	userResp, ok := result["user"].(map[string]interface{})
	if !ok {
		t.Fatal("Response missing user object")
	}

	if userResp["email"] != user.Email {
		t.Errorf("Expected email %s, got %s", user.Email, userResp["email"])
	}
}

func TestRegister_DuplicateEmail(t *testing.T) {
	env := helpers.NewTestEnvironment(t)
	user := helpers.NewTestUser()

	// Register first time
	resp := env.Client.Register(t, user.RegisterInput())
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("First registration failed: %d", resp.StatusCode)
	}

	// Register same email again
	resp = env.Client.Register(t, user.RegisterInput())
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("Expected status 409 for duplicate email, got %d: %s", resp.StatusCode, string(resp.Body))
	}
}

func TestRegister_WeakPassword(t *testing.T) {
	env := helpers.NewTestEnvironment(t)
	user := helpers.NewTestUser()
	user.Password = "short"

	resp := env.Client.Register(t, user.RegisterInput())

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400 for weak password, got %d: %s", resp.StatusCode, string(resp.Body))
	}
}

func TestRegister_MissingFields(t *testing.T) {
	env := helpers.NewTestEnvironment(t)

	testCases := []struct {
		name  string
		input map[string]interface{}
	}{
		{
			name:  "missing email",
			input: map[string]interface{}{"password": "TestP@ss123!", "first_name": "Test", "last_name": "User"},
		},
		{
			name:  "missing password",
			input: map[string]interface{}{"email": helpers.UniqueEmail(), "first_name": "Test", "last_name": "User"},
		},
		{
			name:  "missing first_name",
			input: map[string]interface{}{"email": helpers.UniqueEmail(), "password": "TestP@ss123!", "last_name": "User"},
		},
		{
			name:  "missing last_name",
			input: map[string]interface{}{"email": helpers.UniqueEmail(), "password": "TestP@ss123!", "first_name": "Test"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp := env.Client.Register(t, tc.input)
			if resp.StatusCode == http.StatusCreated {
				t.Errorf("Expected registration to fail for %s, but got 201", tc.name)
			}
		})
	}
}
