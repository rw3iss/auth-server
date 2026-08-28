package email

import (
	"context"
	"strings"
	"sync"
)

// CapturingEmailService is a TEST DOUBLE: it records what would have been sent
// instead of sending it.
//
// WHY THIS HAS TO EXIST FOR THE TESTS TO BE POSSIBLE AT ALL. Four of this
// server's flows hand the user a token that ONLY ever reaches them by email —
// email verification, password reset, organization invitation, and magic-link
// sign-in. With the no-op email service the integration harness used, that
// token is written to a log and dropped, so a test could call the request
// endpoint and then had nothing to present to the confirm endpoint. That is
// exactly why TestPasswordResetTokenSingleUse was skipped with the note
// "requires email-capture harness to grab reset token", and why invitations,
// magic links and the verify-email HTTP flow had no tests whatsoever.
//
// It deliberately captures the LINK as well as the token: the emailed URL is
// itself a contract with the client app (six landing paths, built from
// resolveBaseURL), and a link that silently points at localhost in production
// is a real defect this makes assertable.
//
// NOT WIRED INTO THE PROVIDER FACTORY, on purpose. Nothing selects this by
// config value; a caller must construct it explicitly. An email service that
// captures every message and delivers nothing would be a quiet catastrophe if
// a deployment could reach it by setting EMAIL_PROVIDER.
type CapturingEmailService struct {
	mu   sync.Mutex
	sent []CapturedEmail
}

// CapturedEmail is one message that would have been sent.
type CapturedEmail struct {
	// Kind is the flow: "verification" | "password_reset" | "invitation" |
	// "magic_link" | "welcome" | "password_changed" | "security_alert".
	Kind string
	// AppBaseURL is the value the caller passed — "" means it accepted the
	// CLIENT_URL / localhost fallback, which is itself worth asserting.
	AppBaseURL string
	To         string
	FirstName  string
	// Token is the single-use credential, where the flow has one.
	Token string
	// Code is the invitation code (invitations carry both a code and a token).
	Code string
	// OrgName / InviterName are set for invitations.
	OrgName     string
	InviterName string
	// AlertType / Details are set for security alerts.
	AlertType string
	Details   string
	// ColorMode is the branded shell variant requested.
	ColorMode string
}

// NewCapturingEmailService returns an empty capture buffer.
func NewCapturingEmailService() *CapturingEmailService { return &CapturingEmailService{} }

func (s *CapturingEmailService) record(e CapturedEmail) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, e)
	return nil
}

// All returns a copy of everything captured so far.
func (s *CapturingEmailService) All() []CapturedEmail {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]CapturedEmail, len(s.sent))
	copy(out, s.sent)
	return out
}

// Reset drops everything captured. Call between tests sharing one harness so a
// previous test's token can never satisfy this one's assertion.
func (s *CapturingEmailService) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = nil
}

// Last returns the most recent email of a kind, and whether one was found.
// Most tests want "the reset email that was just triggered", not a search.
func (s *CapturingEmailService) Last(kind string) (CapturedEmail, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.sent) - 1; i >= 0; i-- {
		if s.sent[i].Kind == kind {
			return s.sent[i], true
		}
	}
	return CapturedEmail{}, false
}

// LastTo returns the most recent email of a kind sent to a specific address.
// Necessary whenever a test has more than one user in flight: "the last
// invitation" is ambiguous the moment two are outstanding.
func (s *CapturingEmailService) LastTo(kind, email string) (CapturedEmail, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.sent) - 1; i >= 0; i-- {
		if s.sent[i].Kind == kind && strings.EqualFold(s.sent[i].To, email) {
			return s.sent[i], true
		}
	}
	return CapturedEmail{}, false
}

// Count returns how many emails of a kind were captured. Asserting a count of
// zero is how a test proves an email was NOT sent — the anti-enumeration
// behaviour of password reset, for instance, depends on it.
func (s *CapturingEmailService) Count(kind string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, e := range s.sent {
		if e.Kind == kind {
			n++
		}
	}
	return n
}

// Link rebuilds the URL this email would have contained, using the SAME
// resolveBaseURL the real providers use — so a test asserts the actual link a
// recipient would click, including the base-URL fallback chain.
func (e CapturedEmail) Link() string {
	base := resolveBaseURL(e.AppBaseURL)
	switch e.Kind {
	case "verification":
		return base + "/auth/verify-email?token=" + e.Token
	case "password_reset":
		return base + "/auth/reset?token=" + e.Token
	case "magic_link":
		return base + "/auth/magic-link/verify?token=" + e.Token
	case "invitation":
		return base + "/auth/accept-invite?code=" + e.Code + "&token=" + e.Token
	case "password_changed", "security_alert":
		return base + "/profile"
	default: // welcome
		return base
	}
}

// ── service.EmailService ─────────────────────────────────────────────────────

func (s *CapturingEmailService) SendVerificationEmail(_ context.Context, appBaseURL, to, firstName, token, colorMode string) error {
	return s.record(CapturedEmail{Kind: "verification", AppBaseURL: appBaseURL, To: to, FirstName: firstName, Token: token, ColorMode: colorMode})
}

func (s *CapturingEmailService) SendPasswordResetEmail(_ context.Context, appBaseURL, to, firstName, token, colorMode string) error {
	return s.record(CapturedEmail{Kind: "password_reset", AppBaseURL: appBaseURL, To: to, FirstName: firstName, Token: token, ColorMode: colorMode})
}

func (s *CapturingEmailService) SendInvitationEmail(_ context.Context, appBaseURL, to, orgName, inviterName, code, token string) error {
	return s.record(CapturedEmail{Kind: "invitation", AppBaseURL: appBaseURL, To: to, OrgName: orgName, InviterName: inviterName, Code: code, Token: token})
}

func (s *CapturingEmailService) SendWelcomeEmail(_ context.Context, appBaseURL, to, firstName string) error {
	return s.record(CapturedEmail{Kind: "welcome", AppBaseURL: appBaseURL, To: to, FirstName: firstName})
}

func (s *CapturingEmailService) SendPasswordChangedEmail(_ context.Context, appBaseURL, to, firstName string) error {
	return s.record(CapturedEmail{Kind: "password_changed", AppBaseURL: appBaseURL, To: to, FirstName: firstName})
}

func (s *CapturingEmailService) SendSecurityAlertEmail(_ context.Context, appBaseURL, to, firstName, alertType, details string) error {
	return s.record(CapturedEmail{Kind: "security_alert", AppBaseURL: appBaseURL, To: to, FirstName: firstName, AlertType: alertType, Details: details})
}

func (s *CapturingEmailService) SendMagicLinkEmail(_ context.Context, appBaseURL, to, firstName, token string) error {
	return s.record(CapturedEmail{Kind: "magic_link", AppBaseURL: appBaseURL, To: to, FirstName: firstName, Token: token})
}
