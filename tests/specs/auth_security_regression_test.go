//go:build integration

// Phase-A security regressions — one test per AUDIT finding that landed in
// the security-fix commit series. If any of these flips green-to-red, a
// regression has slipped past unit-level coverage.

package tests

import (
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/rw3iss/auth/tests/specs/helpers"
)

// AUDIT 1.1: a password-reset token must be single-use even when the JWT is
// still within its expiry window. Reset succeeds once; the second
// presentation of the same token must fail.
func TestPasswordResetTokenSingleUse(t *testing.T) {
	env := helpers.NewTestEnvironment(t)
	user := helpers.RegisterAndLogin(t, env.Client)

	// We don't have the raw reset token surfaced via API (it normally goes
	// out via email). The test harness needs to peek at the
	// password_reset_tokens row to grab the JWT. Skip this test if the
	// harness doesn't expose that — it's documented as missing coverage
	// in AUDIT 6.1 and tracked separately. The single-use *enforcement*
	// has unit-level coverage in internal/auth/jwt/service_test.go.
	t.Skip("requires email-capture harness to grab reset token; unit coverage in jwt/service_test.go")
	_ = user
}

// AUDIT 1.9: presenting a refresh token after it's been rotated must (a)
// fail, and (b) revoke every descendant token in the family, including the
// one the legitimate user is currently using.
func TestRefreshTokenReuseRevokesFamily(t *testing.T) {
	env := helpers.NewTestEnvironment(t)
	user := helpers.RegisterAndLogin(t, env.Client)

	// Rotate: T0 -> T1. T0 is now revoked.
	resp := env.Client.RefreshToken(t, user.RefreshToken, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rotate failed: %d %s", resp.StatusCode, resp.Body)
	}
	var rotated struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := resp.JSON(&rotated); err != nil {
		t.Fatalf("parse rotated: %v", err)
	}

	// Rotate again: T1 -> T2. T1 is now revoked.
	resp2 := env.Client.RefreshToken(t, rotated.RefreshToken, "")
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("second rotate failed: %d %s", resp2.StatusCode, resp2.Body)
	}
	var rotated2 struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := resp2.JSON(&rotated2); err != nil {
		t.Fatalf("parse rotated2: %v", err)
	}

	// Reuse T0 (the original) — must fail AND must revoke T2 by family
	// association.
	resp3 := env.Client.RefreshToken(t, user.RefreshToken, "")
	if resp3.StatusCode == http.StatusOK {
		t.Fatal("expected reuse of revoked T0 to fail")
	}

	// T2 must now also fail. The legitimate user has been logged out by
	// the family-revoke triggered from the attacker's presentation of T0.
	resp4 := env.Client.RefreshToken(t, rotated2.RefreshToken, "")
	if resp4.StatusCode == http.StatusOK {
		t.Fatal("expected current refresh T2 to fail after family revoke")
	}
}

// AUDIT 1.9 bonus: simultaneous rotation of the same refresh token. One
// wins, the other must lose — and ideally trigger the family-revoke path.
// At minimum the losing call must not get a valid pair back without
// triggering an error.
func TestConcurrentRefreshSameTokenOneWins(t *testing.T) {
	env := helpers.NewTestEnvironment(t)
	user := helpers.RegisterAndLogin(t, env.Client)

	var wg sync.WaitGroup
	results := make([]int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			r := env.Client.RefreshToken(t, user.RefreshToken, "")
			results[idx] = r.StatusCode
		}(i)
	}
	wg.Wait()

	wins := 0
	for _, code := range results {
		if code == http.StatusOK {
			wins++
		}
	}
	// At least one must lose. Two simultaneous 200s would mean both got
	// fresh pairs from a token that should only be consumable once.
	if wins == 2 {
		t.Fatalf("both concurrent refreshes succeeded — race condition in rotation: %v", results)
	}
}

// AUDIT 1.10: logout-all must invalidate the user's currently-valid access
// token, not just refresh tokens. Before this fix, /auth/me would continue
// to succeed for up to 15 minutes after logout-all.
func TestLogoutAllInvalidatesAccessTokens(t *testing.T) {
	env := helpers.NewTestEnvironment(t)
	user := helpers.RegisterAndLogin(t, env.Client)

	// Sanity: the just-issued access token works on /auth/me.
	resp := env.Client.GetMe(t)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pre-revoke /me failed: %d %s", resp.StatusCode, resp.Body)
	}

	// Logout-all.
	rev := env.Client.LogoutAll(t)
	if rev.StatusCode != http.StatusOK {
		t.Fatalf("logout-all failed: %d %s", rev.StatusCode, rev.Body)
	}

	// The same access token must no longer work. Without AUDIT 1.10, the
	// token would still be cryptographically valid AND not blacklisted →
	// 200. With the token-version gate, the bumped counter rejects it.
	resp2 := env.Client.GetMe(t)
	if resp2.StatusCode == http.StatusOK {
		t.Fatal("access token still works after logout-all — token-version gate broken")
	}
	_ = user
}

// AUDIT 1.4: oversized password input must be rejected at registration
// without triggering bcrypt. This is a DoS bound — not a correctness one —
// so a fast 4xx is the expected behavior.
func TestRegisterRejectsOversizedPassword(t *testing.T) {
	env := helpers.NewTestEnvironment(t)
	huge := strings.Repeat("Aa1!", 100) // 400 chars, > 128
	resp := env.Client.Register(t, map[string]any{
		"email":      helpers.UniqueEmail(),
		"password":   huge,
		"first_name": "T",
		"last_name":  "T",
	})
	if resp.StatusCode/100 != 4 {
		t.Fatalf("expected 4xx for oversized password, got %d", resp.StatusCode)
	}
}
