package sso

// PKCE (RFC 7636) — Proof Key for Code Exchange.
//
// Public clients (the browser SDK, native apps) can't safely hold a client
// secret. PKCE binds the authorization request to the eventual token
// exchange via a one-time secret known only to the client. Even if an
// attacker captures the redirect-flow `auth_code`, they can't exchange it
// without the `code_verifier`.
//
// Wire shape:
//
//  1. Client generates `code_verifier` — 43-128 chars from the unreserved
//     base64url alphabet (RFC 7636 §4.1).
//  2. Client derives `code_challenge` = BASE64URL(SHA256(verifier)) and sets
//     `code_challenge_method` = "S256" (the only method we accept).
//  3. Client POSTs both to /auth/sso/url; the server stashes them with the
//     opaque state record (10-minute TTL).
//  4. Provider redirects user-agent back to OUR callback; the callback
//     finalizes the upstream OAuth dance and — because PKCE is in flight —
//     issues a short-lived `auth_code` instead of an access/refresh pair.
//  5. Client POSTs {auth_code, code_verifier} to /auth/sso/exchange. Server
//     atomically consumes the auth_code, verifies SHA256(verifier) matches
//     the stashed challenge, and mints the token pair.
//
// Why server-issued auth_code instead of using the upstream provider's code?
// The upstream code is already consumed by the time PKCE finalizes (we do
// the exchange-with-provider step server-side in the callback). The
// auth_code is OUR boundary token — it lets us defer minting OUR tokens
// until the public client proves possession of the original verifier.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"

	"github.com/rw3iss/auth/pkg/shared/errors"
)

// GenerateCodeVerifier returns a fresh RFC 7636 §4.1 code_verifier — 32 random
// bytes base64url-encoded (unpadded) = 43 chars, inside the mandated 43..128
// range and drawn from the unreserved alphabet. Used by the manager to mint a
// provider-leg verifier for providers that require PKCE on the server↔provider
// exchange (X/Twitter mandates it even for confidential clients).
func GenerateCodeVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Code challenge method constants. RFC 7636 §4.3 names two methods: "plain"
// (verifier == challenge — provides no defense against challenge capture) and
// "S256" (SHA256). Only S256 is accepted here. Operators wanting to support
// `plain` for legacy clients should explicitly opt in via a separate flag.
const (
	CodeChallengeMethodS256 = "S256"
)

// PKCE verifier length bounds. RFC 7636 §4.1 mandates 43..128 chars from the
// unreserved set [A-Z][a-z][0-9]-._~. We enforce both.
const (
	pkceVerifierMinLen = 43
	pkceVerifierMaxLen = 128
)

// ValidateCodeChallenge inspects a challenge value submitted on the SSO-URL
// endpoint. Returns nil if it's structurally acceptable.
//
// We don't try to decode the challenge — it's an opaque string we'll just
// store and compare against on exchange. The bounds check guards against
// pathological inputs (empty / megabyte payloads) while leaving the
// cryptographic verification to ValidateVerifier on exchange.
func ValidateCodeChallenge(challenge, method string) error {
	if challenge == "" {
		return errors.InvalidInput("code_challenge", "code_challenge is required when PKCE is initiated")
	}
	// S256 challenge is BASE64URL(SHA256(verifier)) = 43 chars unpadded.
	// Allow some slack for clients that include padding (which we strip on
	// compare) but reject anything wildly off.
	if len(challenge) < 43 || len(challenge) > 128 {
		return errors.InvalidInput("code_challenge", "code_challenge must be 43-128 chars")
	}
	if method == "" {
		return errors.InvalidInput("code_challenge_method", "code_challenge_method is required when code_challenge is set")
	}
	if method != CodeChallengeMethodS256 {
		return errors.InvalidInput("code_challenge_method", "only S256 is supported; plain is rejected")
	}
	return nil
}

// VerifyCodeVerifier returns nil if SHA256(verifier) base64url-encodes to the
// supplied challenge. Constant-time secret comparison isn't necessary here
// because the challenge is public (it travels in the auth URL) — what we
// actually protect is the verifier, which never leaves the public client
// until exchange.
//
// We only support S256 (the safe method). If a future change wants to permit
// `plain` for migration, branch on method here.
func VerifyCodeVerifier(verifier, challenge, method string) error {
	if method != CodeChallengeMethodS256 {
		return errors.InvalidInput("code_challenge_method", "unsupported method")
	}
	if err := validateVerifierFormat(verifier); err != nil {
		return err
	}
	derived := DeriveS256Challenge(verifier)
	// base64url no-padding canonical form. Accept padded inputs by trimming;
	// challenge stored at /auth/sso/url is whatever the client sent.
	if trimPadding(derived) != trimPadding(challenge) {
		return errors.InvalidInput("code_verifier", "verifier does not match the stored challenge")
	}
	return nil
}

// DeriveS256Challenge returns BASE64URL(SHA256(verifier)) without padding.
// Exposed so tests can round-trip the construction and the future browser
// SDK can share the same derivation logic via a parallel TS port.
func DeriveS256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// validateVerifierFormat enforces the RFC 7636 §4.1 character set + bounds.
// The grammar is [A-Za-z0-9-._~]{43,128}. We reject everything else without
// trying to be helpful about what character offended us — a misformatted
// verifier from a public client is a bug in the client, not a user action
// worth diagnosing.
func validateVerifierFormat(verifier string) error {
	n := len(verifier)
	if n < pkceVerifierMinLen || n > pkceVerifierMaxLen {
		return errors.InvalidInput("code_verifier", "code_verifier must be 43-128 chars")
	}
	for i := range n {
		c := verifier[i]
		isAlpha := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
		isDigit := c >= '0' && c <= '9'
		isMark := c == '-' || c == '.' || c == '_' || c == '~'
		if !(isAlpha || isDigit || isMark) {
			return errors.InvalidInput("code_verifier", "code_verifier contains disallowed characters")
		}
	}
	return nil
}

// trimPadding strips trailing '=' from a base64url string. Lets clients send
// padded or unpadded challenges; either compares equal.
func trimPadding(s string) string {
	end := len(s)
	for end > 0 && s[end-1] == '=' {
		end--
	}
	return s[:end]
}
