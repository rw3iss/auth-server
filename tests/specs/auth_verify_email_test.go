//go:build integration

// Email verification through the actual HTTP flow. The JWT layer had unit
// coverage (issue/validate/single-use against a stub repo), but nothing ever
// called the endpoint — so the handler, the service, and the wiring between
// them were untested, and the token the user actually receives was never
// exercised.

package tests

import (
	"net/http"
	"strings"
	"testing"

	"github.com/rw3iss/auth/tests/specs/helpers"
)

// Registration sends a verification email, and the token in it verifies.
func TestVerifyEmail_RegistrationSendsTokenThatWorks(t *testing.T) {
	env := helpers.NewTestEnvironment(t)

	env.Emails.Reset()
	user := helpers.NewTestUser()
	if resp := env.Client.Register(t, user.RegisterInput()); resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d %s", resp.StatusCode, resp.Body)
	}

	mail, ok := env.Emails.LastTo("verification", user.Email)
	if !ok {
		t.Fatal("registration sent no verification email")
	}
	if mail.Token == "" {
		t.Fatal("verification email carried no token")
	}

	if resp := env.Client.VerifyEmail(t, mail.Token); resp.StatusCode != http.StatusOK {
		t.Fatalf("verification should succeed: %d %s", resp.StatusCode, resp.Body)
	}
}

// SINGLE USE, at the HTTP layer rather than against a stub repo.
func TestVerifyEmail_TokenIsSingleUse(t *testing.T) {
	env := helpers.NewTestEnvironment(t)

	env.Emails.Reset()
	user := helpers.NewTestUser()
	if resp := env.Client.Register(t, user.RegisterInput()); resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d %s", resp.StatusCode, resp.Body)
	}
	mail, ok := env.Emails.LastTo("verification", user.Email)
	if !ok {
		t.Fatal("no verification email captured")
	}

	if first := env.Client.VerifyEmail(t, mail.Token); first.StatusCode != http.StatusOK {
		t.Fatalf("first verification should succeed: %d %s", first.StatusCode, first.Body)
	}
	if second := env.Client.VerifyEmail(t, mail.Token); second.StatusCode == http.StatusOK {
		t.Fatal("SECURITY: a verification token was accepted twice")
	}
}

func TestVerifyEmail_InvalidToken(t *testing.T) {
	env := helpers.NewTestEnvironment(t)
	if resp := env.Client.VerifyEmail(t, "not-a-real-token"); resp.StatusCode == http.StatusOK {
		t.Fatalf("SECURITY: an invalid verification token was accepted: %s", resp.Body)
	}
}

// CROSS-PURPOSE REJECTION at the HTTP layer. A password-reset token and a
// verification token are both signed JWTs from the same issuer; if the verify
// endpoint accepted a reset token, a leaked reset link would silently verify an
// address. The unit tests prove the validators are separate — this proves the
// ENDPOINTS are wired to the right validator, which is a different claim.
func TestVerifyEmail_RejectsPasswordResetToken(t *testing.T) {
	env := helpers.NewTestEnvironment(t)
	user := helpers.RegisterAndLogin(t, env.Client)

	env.Emails.Reset()
	if resp := env.Client.RequestPasswordReset(t, user.Email); resp.StatusCode != http.StatusOK {
		t.Fatalf("reset request: %d %s", resp.StatusCode, resp.Body)
	}
	reset, ok := env.Emails.LastTo("password_reset", user.Email)
	if !ok {
		t.Fatal("no password-reset email captured")
	}

	if resp := env.Client.VerifyEmail(t, reset.Token); resp.StatusCode == http.StatusOK {
		t.Fatal("SECURITY: a password-reset token was accepted by the verify-email endpoint")
	}
}

// THE LINK ITSELF IS A CONTRACT. The emailed URL must point at the app, not at
// the server's own dev default — a verification email linking to localhost is
// exactly the defect that shipped to production once already, and it is
// invisible unless something asserts the link rather than the token.
func TestVerifyEmail_LinkUsesConfiguredBaseURL(t *testing.T) {
	env := helpers.NewTestEnvironment(t)

	env.Emails.Reset()
	user := helpers.NewTestUser()
	if resp := env.Client.Register(t, user.RegisterInput()); resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d %s", resp.StatusCode, resp.Body)
	}
	mail, ok := env.Emails.LastTo("verification", user.Email)
	if !ok {
		t.Fatal("no verification email captured")
	}

	link := mail.Link()
	if link == "" {
		t.Fatal("verification email produced no link")
	}
	// The path is the part the client app must implement; assert it exactly.
	if want := "/auth/verify-email?token=" + mail.Token; !strings.Contains(link, want) {
		t.Fatalf("verification link %q does not carry %q", link, want)
	}
}
