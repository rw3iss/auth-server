//go:build integration

package helpers

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

var emailCounter uint64

// UniqueEmail generates a unique email address for testing
func UniqueEmail() string {
	n := atomic.AddUint64(&emailCounter, 1)
	b := make([]byte, 4)
	rand.Read(b)
	return fmt.Sprintf("test-%d-%s-%s@test.ven.com", n, hex.EncodeToString(b), fmt.Sprintf("%d", time.Now().UnixNano()%100000))
}

// TestUser represents test user data
type TestUser struct {
	Email     string
	Password  string
	FirstName string
	LastName  string
}

// NewTestUser creates a new test user with unique email
func NewTestUser() *TestUser {
	return &TestUser{
		Email:     UniqueEmail(),
		Password:  "TestP@ss123!",
		FirstName: "Test",
		LastName:  "User",
	}
}

// RegisterInput returns the user as a registration input map
func (u *TestUser) RegisterInput() map[string]interface{} {
	return map[string]interface{}{
		"email":      u.Email,
		"password":   u.Password,
		"first_name": u.FirstName,
		"last_name":  u.LastName,
	}
}

// LoginInput returns the user as a login input map
func (u *TestUser) LoginInput() map[string]interface{} {
	return map[string]interface{}{
		"email":    u.Email,
		"password": u.Password,
	}
}

// RegisteredUser represents a user that has been registered and logged in
type RegisteredUser struct {
	TestUser
	AccessToken  string
	RefreshToken string
	UserID       string
}

// RegisterAndLogin creates a user, registers, and logs in
func RegisterAndLogin(t *testing.T, client *TestClient) *RegisteredUser {
	t.Helper()

	user := NewTestUser()

	// Register
	resp := client.Register(t, user.RegisterInput())
	if resp.StatusCode != 201 {
		t.Fatalf("Failed to register user: status=%d body=%s", resp.StatusCode, string(resp.Body))
	}

	// Login
	loginResp := client.Login(t, user.LoginInput())
	if loginResp.StatusCode != 200 {
		t.Fatalf("Failed to login user: status=%d body=%s", loginResp.StatusCode, string(loginResp.Body))
	}

	var loginResult struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		Tokens struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		} `json:"tokens"`
	}
	if err := loginResp.JSON(&loginResult); err != nil {
		t.Fatalf("Failed to parse login response: %v", err)
	}

	return &RegisteredUser{
		TestUser:     *user,
		AccessToken:  loginResult.Tokens.AccessToken,
		RefreshToken: loginResult.Tokens.RefreshToken,
		UserID:       loginResult.User.ID,
	}
}
