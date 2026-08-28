//go:build integration

// Magic-link sign-in. Previously ZERO coverage: the service, the handler and the
// routes all existed and nothing exercised any of them, because the token only
// ever reaches the user by email and the harness threw emails away.

package tests

import (
	"net/http"
	"testing"

	"github.com/rw3iss/auth/tests/specs/helpers"
)

// The happy path, end to end: request a link, read the token out of the email
// exactly as a user reads it out of their inbox, present it, receive a session.
func TestMagicLink_RequestAndVerify(t *testing.T) {
	env := helpers.NewTestEnvironment(t)
	user := helpers.RegisterAndLogin(t, env.Client)

	env.Emails.Reset()
	resp := env.Client.RequestMagicLink(t, user.Email)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("magic-link request: %d %s", resp.StatusCode, resp.Body)
	}

	mail, ok := env.Emails.LastTo("magic_link", user.Email)
	if !ok {
		t.Fatal("no magic-link email captured")
	}
	if mail.Token == "" {
		t.Fatal("magic-link email carried no token")
	}

	verify := env.Client.VerifyMagicLink(t, mail.Token)
	if verify.StatusCode != http.StatusOK {
		t.Fatalf("verify should establish a session: %d %s", verify.StatusCode, verify.Body)
	}
	var out struct {
		Tokens struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		} `json:"tokens"`
	}
	if err := verify.JSON(&out); err != nil {
		t.Fatalf("parse verify response: %v", err)
	}
	if out.Tokens.AccessToken == "" || out.Tokens.RefreshToken == "" {
		t.Fatalf("verify returned no token pair: %s", verify.Body)
	}

	// The session is REAL, not just well-shaped. A token pair that does not
	// authenticate is the failure this assertion exists to catch.
	env.Client.SetToken(out.Tokens.AccessToken)
	defer env.Client.ClearToken()
	if me := env.Client.GetMe(t); me.StatusCode != http.StatusOK {
		t.Fatalf("magic-link session should authenticate: %d %s", me.StatusCode, me.Body)
	}
}

// SINGLE USE. A sign-in link that works twice is a sign-in link that works for
// whoever finds the email later — forwarded, backed up, or in a shared inbox.
func TestMagicLink_TokenIsSingleUse(t *testing.T) {
	env := helpers.NewTestEnvironment(t)
	user := helpers.RegisterAndLogin(t, env.Client)

	env.Emails.Reset()
	if resp := env.Client.RequestMagicLink(t, user.Email); resp.StatusCode != http.StatusOK {
		t.Fatalf("magic-link request: %d %s", resp.StatusCode, resp.Body)
	}
	mail, ok := env.Emails.LastTo("magic_link", user.Email)
	if !ok {
		t.Fatal("no magic-link email captured")
	}

	if first := env.Client.VerifyMagicLink(t, mail.Token); first.StatusCode != http.StatusOK {
		t.Fatalf("first verify should succeed: %d %s", first.StatusCode, first.Body)
	}
	if second := env.Client.VerifyMagicLink(t, mail.Token); second.StatusCode == http.StatusOK {
		t.Fatal("SECURITY: a magic-link token was accepted twice")
	}
}

// A forged or corrupted token must be refused, not merely fail to find a user.
func TestMagicLink_InvalidToken(t *testing.T) {
	env := helpers.NewTestEnvironment(t)
	resp := env.Client.VerifyMagicLink(t, "not-a-real-token")
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("SECURITY: an invalid magic-link token was accepted: %s", resp.Body)
	}
}

// ANTI-ENUMERATION. Requesting a link for an address that has no account must
// look identical from outside — same status — or the endpoint becomes a way to
// ask "does this person have an account here". The email must NOT be sent.
func TestMagicLink_UnknownEmailIsIndistinguishable(t *testing.T) {
	env := helpers.NewTestEnvironment(t)
	user := helpers.RegisterAndLogin(t, env.Client)

	env.Emails.Reset()
	known := env.Client.RequestMagicLink(t, user.Email)

	env.Emails.Reset()
	unknown := env.Client.RequestMagicLink(t, "definitely-not-registered@example.invalid")

	if known.StatusCode != unknown.StatusCode {
		t.Fatalf("ENUMERATION: known=%d unknown=%d — the two must be indistinguishable",
			known.StatusCode, unknown.StatusCode)
	}
	if n := env.Emails.Count("magic_link"); n != 0 {
		t.Fatalf("a magic-link email was sent for an unregistered address (%d sent)", n)
	}
}
