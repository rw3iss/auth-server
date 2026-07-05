package globalsku

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/ven/auth/pkg/migration"
)

const testSecret = "shared-secret-xyz"

func TestNew_Validation(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("expected error for empty config")
	}
	if _, err := New(Config{BaseURL: "https://x", VerifySecret: ""}); err == nil {
		t.Error("expected error for missing secret")
	}
	a, err := New(Config{BaseURL: "https://x/", VerifySecret: testSecret})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if a.baseURL != "https://x" { // trailing slash trimmed
		t.Errorf("baseURL not trimmed: %q", a.baseURL)
	}
}

// newServer asserts the signing headers and returns the configured response.
func newServer(t *testing.T, status int, respBody string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != verifyPath {
			t.Errorf("wrong path: %s", r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		ts := r.Header.Get("X-Auth-Timestamp")
		if _, err := strconv.ParseInt(ts, 10, 64); err != nil {
			t.Errorf("bad timestamp header: %q", ts)
		}
		// Recompute the expected signature over "{ts}.{rawBody}".
		mac := hmac.New(sha256.New, []byte(testSecret))
		mac.Write([]byte(ts + "." + string(body)))
		want := "SHA256:" + base64.StdEncoding.EncodeToString(mac.Sum(nil))
		if got := r.Header.Get("X-Auth-Signature"); got != want {
			t.Errorf("signature mismatch\n got=%s\nwant=%s", got, want)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(respBody))
	}))
}

func TestTryLogin_Valid(t *testing.T) {
	srv := newServer(t, 200, `{"valid":true,"user":{"email":"jane@x.com","name":"Jane Q Doe"}}`)
	defer srv.Close()
	a, _ := New(Config{BaseURL: srv.URL, VerifySecret: testSecret})

	u, err := a.TryLogin(t.Context(), "jane@x.com", "pw")
	if err != nil {
		t.Fatalf("TryLogin: %v", err)
	}
	if u.Email != "jane@x.com" || u.FirstName != "Jane" || u.LastName != "Q Doe" {
		t.Fatalf("unexpected user: %+v", u)
	}
	if !u.EmailVerified || len(u.Roles) != 0 {
		t.Errorf("expected verified + no roles, got verified=%v roles=%v", u.EmailVerified, u.Roles)
	}
}

func TestTryLogin_Invalid(t *testing.T) {
	srv := newServer(t, 200, `{"valid":false}`)
	defer srv.Close()
	a, _ := New(Config{BaseURL: srv.URL, VerifySecret: testSecret})

	_, err := a.TryLogin(t.Context(), "x@x.com", "wrong")
	if !errors.Is(err, migration.ErrLegacyLoginFailed) {
		t.Fatalf("expected ErrLegacyLoginFailed, got %v", err)
	}
}

func TestTryLogin_TransientOn401And5xx(t *testing.T) {
	for _, status := range []int{401, 500, 503} {
		srv := newServer(t, status, `{"error":"nope"}`)
		a, _ := New(Config{BaseURL: srv.URL, VerifySecret: testSecret})
		_, err := a.TryLogin(t.Context(), "x@x.com", "pw")
		srv.Close()
		if err == nil {
			t.Fatalf("status %d: expected error", status)
		}
		// Must NOT be a "not found" (that would silently skip migration).
		if errors.Is(err, migration.ErrLegacyUserNotFound) {
			t.Errorf("status %d: must not map to ErrLegacyUserNotFound", status)
		}
		if errors.Is(err, migration.ErrLegacyLoginFailed) {
			t.Errorf("status %d: transient must not map to login-failed", status)
		}
	}
}

func TestSplitName(t *testing.T) {
	cases := map[string][2]string{
		"":           {"", ""},
		"Jane":       {"Jane", ""},
		"Jane Doe":   {"Jane", "Doe"},
		"Jane Q Doe": {"Jane", "Q Doe"},
	}
	for in, want := range cases {
		f, l := splitName(in)
		if f != want[0] || l != want[1] {
			t.Errorf("%q → (%q,%q), want (%q,%q)", in, f, l, want[0], want[1])
		}
	}
}

func TestName(t *testing.T) {
	a, _ := New(Config{BaseURL: "https://x", VerifySecret: testSecret})
	if a.Name() != "globalsku" {
		t.Errorf("name = %q", a.Name())
	}
}
