// Package globalsku provides a LegacyAuthProvider that verifies a live
// password attempt against GlobalSKU's signed internal endpoint (§5.1 of
// docs/GLOBALSKU_INTEGRATION_AUTH_SERVER_TASKS.md).
//
// GlobalSKU's passwords are bcrypt hashes — not reversible — so JIT migration
// can't "import and decrypt". Instead the auth-server verifies the password
// the user just typed against GlobalSKU's store via:
//
//	POST {BaseURL}/api/internal/verify-legacy-password
//	{"email","password"} → 200 {"valid":true,"user":{"email","name"}} | {"valid":false}
//
// The endpoint is a password oracle, so it's HMAC-gated. Every request carries
// X-Auth-Timestamp + X-Auth-Signature; VerifySecret is the shared random
// secret proving the caller is the real auth-server (NOT a hashing key).
//
// Drop-in, SOLID: the auth-server core depends only on
// migration.LegacyAuthProvider. main.go instantiates this only when
// GLOBALSKU_LEGACY_MIGRATION_ENABLED is true, and registers it under
// app_code "globalsku" so the JIT path fires only for that app.
package globalsku

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rw3iss/auth/pkg/migration"
)

const verifyPath = "/api/internal/verify-legacy-password"

// defaultTimeout bounds the verify round-trip. GlobalSKU rejects timestamps
// with >300s skew; we send a fresh timestamp per request so we never approach it.
const defaultTimeout = 10 * time.Second

// Config holds the GlobalSKU verify-channel details.
type Config struct {
	BaseURL      string
	VerifySecret string
	HTTPTimeout  time.Duration // optional; defaults to 10s
}

// Adapter is the GlobalSKU-backed LegacyAuthProvider.
type Adapter struct {
	baseURL string
	secret  string
	client  *http.Client
	now     func() time.Time // injectable for tests
}

// New constructs an Adapter, validating that BaseURL + VerifySecret are set.
func New(cfg Config) (*Adapter, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if base == "" || strings.TrimSpace(cfg.VerifySecret) == "" {
		return nil, fmt.Errorf("globalsku: base_url and verify_secret are required")
	}
	timeout := cfg.HTTPTimeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &Adapter{
		baseURL: base,
		secret:  cfg.VerifySecret,
		client:  &http.Client{Timeout: timeout},
		now:     time.Now,
	}, nil
}

// Name implements migration.LegacyAuthProvider.
func (a *Adapter) Name() string { return "globalsku" }

type verifyResponse struct {
	Valid bool `json:"valid"`
	User  struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	} `json:"user"`
}

// TryLogin verifies the credential against GlobalSKU's signed endpoint.
//
// Error mapping (per §5.1):
//   - 200 {"valid":true}  → *migration.LegacyUser (roles empty → base_user).
//   - 200 {"valid":false} → migration.ErrLegacyLoginFailed (GlobalSKU can't
//     distinguish unknown-email from wrong-password by design).
//   - 401 / 5xx / transport / timeout → wrapped TRANSIENT error (never
//     ErrLegacyUserNotFound), so a GlobalSKU outage fails the login closed
//     rather than silently skipping migration.
func (a *Adapter) TryLogin(ctx context.Context, email, password string) (*migration.LegacyUser, error) {
	// 1. Marshal the body and capture the EXACT bytes for signing.
	rawBody, err := json.Marshal(map[string]string{"email": email, "password": password})
	if err != nil {
		return nil, fmt.Errorf("globalsku: marshal body: %w", err)
	}

	// 2. ts + signature over "{ts}.{rawBody}".
	ts := strconv.FormatInt(a.now().Unix(), 10)
	mac := hmac.New(sha256.New, []byte(a.secret))
	mac.Write([]byte(ts + "." + string(rawBody)))
	sig := "SHA256:" + base64.StdEncoding.EncodeToString(mac.Sum(nil))

	// 3. POST with the signing headers.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.baseURL+verifyPath, bytes.NewReader(rawBody))
	if err != nil {
		return nil, fmt.Errorf("globalsku: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Auth-Timestamp", ts)
	req.Header.Set("X-Auth-Signature", sig)

	resp, err := a.client.Do(req)
	if err != nil {
		// Transport/timeout — transient. Fail closed.
		return nil, fmt.Errorf("globalsku: verify request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	// 4. Map the response.
	if resp.StatusCode != http.StatusOK {
		// 401 (bad signature) / 5xx (GlobalSKU misconfigured or down) →
		// transient, never "not found".
		return nil, fmt.Errorf("globalsku: verify returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var vr verifyResponse
	if err := json.Unmarshal(body, &vr); err != nil {
		return nil, fmt.Errorf("globalsku: parse verify response: %w", err)
	}
	if !vr.Valid {
		// Wrong password OR unknown email — uniform by design.
		return nil, migration.ErrLegacyLoginFailed
	}

	first, last := splitName(vr.User.Name)
	resolvedEmail := vr.User.Email
	if strings.TrimSpace(resolvedEmail) == "" {
		resolvedEmail = email
	}
	return &migration.LegacyUser{
		Email:         strings.ToLower(strings.TrimSpace(resolvedEmail)),
		FirstName:     first,
		LastName:      last,
		EmailVerified: true, // verified against the source of truth
		// Roles intentionally empty: GlobalSKU keeps roles in local Spatie,
		// so the migrated user gets the default base_user (correct for Phase 1).
	}, nil
}

// splitName splits a single display name into (first, last) on the first
// space. "Jane" → ("Jane",""); "Jane Q Doe" → ("Jane","Q Doe").
func splitName(name string) (string, string) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", ""
	}
	if i := strings.IndexByte(name, ' '); i >= 0 {
		return name[:i], strings.TrimSpace(name[i+1:])
	}
	return name, ""
}
