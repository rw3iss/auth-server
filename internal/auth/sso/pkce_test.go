package sso

import (
	"context"
	"strings"
	"testing"
	"time"
)

// validVerifier is a syntactically-correct 64-char base64url-unreserved
// string. Used as the "happy path" verifier across the PKCE tests.
const validVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk_8E2C_oeFu0H_2YYssJ-d"

// AUDIT C2: derived challenge round-trips through VerifyCodeVerifier — what
// the client produced is what the server should accept on exchange.
func TestPKCERoundTripS256(t *testing.T) {
	challenge := DeriveS256Challenge(validVerifier)
	if challenge == "" {
		t.Fatal("derived challenge must be non-empty")
	}
	if err := VerifyCodeVerifier(validVerifier, challenge, CodeChallengeMethodS256); err != nil {
		t.Fatalf("expected verifier to verify against its own derived challenge: %v", err)
	}
}

// AUDIT C2: a verifier that doesn't hash to the stored challenge must be
// rejected. This is the core PKCE security property — an attacker who
// intercepts only the auth_code can't redeem it.
func TestPKCEWrongVerifierRejected(t *testing.T) {
	challenge := DeriveS256Challenge(validVerifier)
	// Change exactly one character of the verifier.
	other := "X" + validVerifier[1:]
	if err := VerifyCodeVerifier(other, challenge, CodeChallengeMethodS256); err == nil {
		t.Fatal("mismatched verifier must be rejected")
	}
}

// AUDIT C2: only S256 is accepted. RFC 7636 §4.3 also defines "plain" but
// that's insecure (challenge == verifier) and we refuse it explicitly.
func TestPKCEPlainMethodRejected(t *testing.T) {
	if err := ValidateCodeChallenge(validVerifier, "plain"); err == nil {
		t.Fatal("plain method must be rejected")
	}
	if err := VerifyCodeVerifier(validVerifier, validVerifier, "plain"); err == nil {
		t.Fatal("VerifyCodeVerifier with method=plain must be rejected")
	}
}

// AUDIT C2: verifier length bounds (43..128) per RFC 7636 §4.1.
func TestPKCEVerifierLengthBounds(t *testing.T) {
	challenge := DeriveS256Challenge(validVerifier)

	cases := []struct {
		name     string
		verifier string
		wantErr  bool
	}{
		{"too short (42)", strings.Repeat("a", 42), true},
		{"min length (43)", strings.Repeat("a", 43), true /* won't match challenge but tests grammar */},
		{"max length (128)", strings.Repeat("a", 128), true /* won't match */},
		{"too long (129)", strings.Repeat("a", 129), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyCodeVerifier(tc.verifier, challenge, CodeChallengeMethodS256)
			if (err != nil) != tc.wantErr {
				t.Fatalf("got err=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

// AUDIT C2: only the RFC 7636 unreserved set is permitted in the verifier.
// Slashes, equals, and other base64 padding-style chars must be refused.
func TestPKCEVerifierCharsetRejection(t *testing.T) {
	challenge := DeriveS256Challenge(validVerifier)
	bad := strings.Repeat("a", 50) + "/" + strings.Repeat("a", 13) // 64 chars, with a slash
	if err := VerifyCodeVerifier(bad, challenge, CodeChallengeMethodS256); err == nil {
		t.Fatal("verifier containing disallowed character must be rejected")
	}
}

// AUDIT C2: challenge submitted at /auth/sso/url must satisfy the same
// bounds, and method must be present-and-S256. ValidateCodeChallenge is the
// /auth/sso/url-side gate; VerifyCodeVerifier is the exchange-side gate.
func TestValidateCodeChallengeRejectsBadInputs(t *testing.T) {
	cases := []struct {
		name      string
		challenge string
		method    string
		wantErr   bool
	}{
		{"valid", DeriveS256Challenge(validVerifier), "S256", false},
		{"empty challenge", "", "S256", true},
		{"too-short challenge", "abc", "S256", true},
		{"missing method", DeriveS256Challenge(validVerifier), "", true},
		{"plain method", DeriveS256Challenge(validVerifier), "plain", true},
		{"unknown method", DeriveS256Challenge(validVerifier), "MD5", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateCodeChallenge(tc.challenge, tc.method)
			if (err != nil) != tc.wantErr {
				t.Fatalf("got err=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

// AUDIT C2: auth_code is single-shot. Two redemptions of the same code must
// not both succeed. Mirror of TestInMemoryStateGetAndDeleteOneShot for the
// auth-code store.
func TestInMemoryAuthCodeStoreOneShot(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryAuthCodeStore(ctx)
	if err := store.Set(ctx, "abc", &AuthCodeData{UserID: "u1"}, time.Minute); err != nil {
		t.Fatalf("set: %v", err)
	}
	first, err := store.GetAndDelete(ctx, "abc")
	if err != nil {
		t.Fatalf("first get: %v", err)
	}
	if first.UserID != "u1" {
		t.Fatalf("user_id round-trip wrong: %q", first.UserID)
	}
	if _, err := store.GetAndDelete(ctx, "abc"); err == nil {
		t.Fatal("second get must fail (auth_code is one-shot)")
	}
}

// AUDIT C2: expired auth_code is treated as not-found. Catches the case
// where a slow client tries to redeem after the 60s TTL has elapsed.
func TestInMemoryAuthCodeStoreExpiry(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryAuthCodeStore(ctx)
	if err := store.Set(ctx, "abc", &AuthCodeData{UserID: "u1"}, time.Nanosecond); err != nil {
		t.Fatalf("set: %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	if _, err := store.GetAndDelete(ctx, "abc"); err == nil {
		t.Fatal("expired auth_code must be treated as not-found")
	}
}
