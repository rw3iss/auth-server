package service

import "context"

// EmailService defines the interface for email operations.
//
// Every method that produces an action link (verify-email,
// password-reset, magic-link, invitation) takes an `appBaseURL`
// parameter as its first argument after the context. This is the
// originating app's canonical frontend origin — e.g.
// "https://demo.auth.ryanweiss.net". The email layer appends the
// conventional path for each flow (e.g. "/auth/verify-email"),
// producing a link that lands inside the app that initiated the
// send rather than a global default.
//
// Empty appBaseURL is honored: the implementation falls back to the
// CLIENT_URL env var (single-tenant deployments) and ultimately to
// http://localhost:3000 (dev). Callers that don't know which app
// initiated the send (e.g. system-emitted security alerts) may pass
// "" and accept the fallback.
type EmailService interface {
	// SendVerificationEmail sends an email verification link. colorMode
	// selects the branded shell variant ("dark"|"light") to match the
	// recipient's preference; pass domain.User.ColorMode() (empty/unknown
	// falls back to dark).
	SendVerificationEmail(ctx context.Context, appBaseURL, email, firstName, token, colorMode string) error

	// SendPasswordResetEmail sends a password reset link. colorMode selects
	// the branded shell variant — see SendVerificationEmail.
	SendPasswordResetEmail(ctx context.Context, appBaseURL, email, firstName, token, colorMode string) error

	// SendInvitationEmail sends an organization invitation.
	SendInvitationEmail(ctx context.Context, appBaseURL, email, orgName, inviterName, code, token string) error

	// SendWelcomeEmail sends a welcome email after registration. The
	// dashboard link is built from appBaseURL (or fallback).
	SendWelcomeEmail(ctx context.Context, appBaseURL, email, firstName string) error

	// SendPasswordChangedEmail notifies user of password change. The
	// "review your security settings" link is built from appBaseURL.
	SendPasswordChangedEmail(ctx context.Context, appBaseURL, email, firstName string) error

	// SendSecurityAlertEmail sends a security alert. Link built from
	// appBaseURL.
	SendSecurityAlertEmail(ctx context.Context, appBaseURL, email, firstName, alertType, details string) error

	// SendMagicLinkEmail delivers a single-use sign-in link. Migration 014.
	SendMagicLinkEmail(ctx context.Context, appBaseURL, email, firstName, token string) error
}
