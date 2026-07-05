package sso

import (
	"context"
	"testing"
	"time"

	"github.com/ven/auth/internal/config"
)

// AUDIT 1.13: redirect URLs must be validated against the allowlist before
// any state is minted. An attacker shouldn't be able to request an OAuth
// flow that points back at their own origin.
func TestRedirectAllowlist(t *testing.T) {
	// Allowlist supports exact match plus tail-only wildcards via trailing
	// '*'. Hostname-component wildcards are NOT supported (would require
	// URL parsing); operators express the same intent with explicit
	// per-host entries or a host-prefix wildcard like
	// "https://app.example.com/*".
	ctx := context.Background()
	m, _ := NewManager(ctx, config.SSOConfig{}, NewInMemoryStateStore(ctx), []string{
		"https://app.example.com/auth/callback",
		"https://staging.example.com/cb*",
	})

	cases := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"exact match", "https://app.example.com/auth/callback", false},
		{"tail wildcard match", "https://staging.example.com/cb-mobile", false},
		{"tail wildcard no overlap", "https://attacker.example.com/cb", true},
		{"unrelated origin", "https://evil.com/", true},
		{"empty url", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := m.validateRedirectURL(tc.url)
			if (err != nil) != tc.wantErr {
				t.Fatalf("got err=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

// Empty allowlist (development default) accepts anything non-empty.
func TestRedirectAllowlistEmpty(t *testing.T) {
	ctx := context.Background()
	m, _ := NewManager(ctx, config.SSOConfig{}, NewInMemoryStateStore(ctx), nil)
	if err := m.validateRedirectURL("https://anywhere.example.com/cb"); err != nil {
		t.Fatalf("expected accept with empty allowlist, got %v", err)
	}
	if err := m.validateRedirectURL(""); err == nil {
		t.Fatal("empty URL must always be rejected")
	}
}

// AUDIT 1.14: state validation must be atomic. The in-memory store's
// GetAndDelete uses a single write lock; two concurrent reads can't both
// see the entry as present.
func TestInMemoryStateGetAndDeleteOneShot(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryStateStore(ctx)
	if err := store.Set(ctx, "abc", &StateData{Provider: "google"}, time.Minute); err != nil {
		t.Fatalf("set: %v", err)
	}
	first, err := store.GetAndDelete(ctx, "abc")
	if err != nil {
		t.Fatalf("first get: %v", err)
	}
	if first == nil {
		t.Fatal("first get returned nil")
	}
	if _, err := store.GetAndDelete(ctx, "abc"); err == nil {
		t.Fatal("second get must fail (state is one-shot)")
	}
}
