//go:build integration

package helpers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
)

// TestClient provides typed HTTP methods for integration tests
type TestClient struct {
	baseURL    string
	apiPrefix  string // e.g. "/api/v1" — driven by API_PREFIX in .env.test
	httpClient *http.Client
	token      string
}

// NewTestClient creates a new test client. apiPrefix is the route prefix configured
// on the server (cfg.Server.APIPrefix), e.g. "/api/v1" or "".
func NewTestClient(baseURL, apiPrefix string) *TestClient {
	return &TestClient{
		baseURL:    baseURL,
		apiPrefix:  apiPrefix,
		httpClient: &http.Client{},
	}
}

// SetToken sets the authorization token for subsequent requests
func (c *TestClient) SetToken(token string) {
	c.token = token
}

// ClearToken clears the authorization token
func (c *TestClient) ClearToken() {
	c.token = ""
}

// Response wraps an HTTP response with helper methods
type Response struct {
	StatusCode int
	Body       []byte
	Headers    http.Header
}

// JSON unmarshals the response body into the given target
func (r *Response) JSON(target interface{}) error {
	return json.Unmarshal(r.Body, target)
}

// Register registers a new user
func (c *TestClient) Register(t *testing.T, input map[string]interface{}) *Response {
	t.Helper()
	return c.post(t, c.apiPrefix+"/auth/register", input)
}

// Login logs in a user
func (c *TestClient) Login(t *testing.T, input map[string]interface{}) *Response {
	t.Helper()
	return c.post(t, c.apiPrefix+"/auth/login", input)
}

// RefreshToken refreshes an access token
func (c *TestClient) RefreshToken(t *testing.T, refreshToken string, orgID string) *Response {
	t.Helper()
	body := map[string]interface{}{
		"refresh_token": refreshToken,
	}
	if orgID != "" {
		body["organization_id"] = orgID
	}
	return c.post(t, c.apiPrefix+"/auth/refresh", body)
}

// Logout logs out a user
func (c *TestClient) Logout(t *testing.T, refreshToken string) *Response {
	t.Helper()
	return c.post(t, c.apiPrefix+"/auth/logout", map[string]interface{}{
		"refresh_token": refreshToken,
	})
}

// LogoutAll logs out from all sessions
func (c *TestClient) LogoutAll(t *testing.T) *Response {
	t.Helper()
	return c.post(t, c.apiPrefix+"/auth/logout/all", nil)
}

// ValidateToken validates an access token
func (c *TestClient) ValidateToken(t *testing.T, token string) *Response {
	t.Helper()
	return c.post(t, c.apiPrefix+"/auth/validate", map[string]interface{}{
		"token": token,
	})
}

// GetMe gets the current user info
func (c *TestClient) GetMe(t *testing.T) *Response {
	t.Helper()
	return c.get(t, c.apiPrefix+"/auth/me")
}

// RequestPasswordReset requests a password reset
func (c *TestClient) RequestPasswordReset(t *testing.T, email string) *Response {
	t.Helper()
	return c.post(t, c.apiPrefix+"/auth/password/reset-request", map[string]interface{}{
		"email": email,
	})
}

// ResetPassword resets a password with a token
func (c *TestClient) ResetPassword(t *testing.T, token, newPassword string) *Response {
	t.Helper()
	return c.post(t, c.apiPrefix+"/auth/password/reset", map[string]interface{}{
		"token":        token,
		"new_password": newPassword,
	})
}

// ChangePassword changes the user's password
func (c *TestClient) ChangePassword(t *testing.T, currentPassword, newPassword string) *Response {
	t.Helper()
	return c.post(t, c.apiPrefix+"/auth/password/change", map[string]interface{}{
		"current_password": currentPassword,
		"new_password":     newPassword,
	})
}

// GetSessions gets the user's active sessions
func (c *TestClient) GetSessions(t *testing.T) *Response {
	t.Helper()
	return c.get(t, c.apiPrefix+"/auth/sessions")
}

// TerminateSession terminates a specific session
func (c *TestClient) TerminateSession(t *testing.T, sessionID string) *Response {
	t.Helper()
	return c.delete(t, fmt.Sprintf("%s/auth/sessions/%s", c.apiPrefix, sessionID))
}

// Health checks the health endpoint
func (c *TestClient) Health(t *testing.T) *Response {
	t.Helper()
	return c.get(t, "/health")
}

func (c *TestClient) get(t *testing.T, path string) *Response {
	t.Helper()
	req, err := http.NewRequest("GET", c.baseURL+path, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	return c.doRequest(t, req)
}

func (c *TestClient) post(t *testing.T, path string, body interface{}) *Response {
	t.Helper()
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("Failed to marshal body: %v", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest("POST", c.baseURL+path, bodyReader)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return c.doRequest(t, req)
}

func (c *TestClient) delete(t *testing.T, path string) *Response {
	t.Helper()
	req, err := http.NewRequest("DELETE", c.baseURL+path, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	return c.doRequest(t, req)
}

func (c *TestClient) doRequest(t *testing.T, req *http.Request) *Response {
	t.Helper()
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Body:       body,
		Headers:    resp.Header,
	}
}
