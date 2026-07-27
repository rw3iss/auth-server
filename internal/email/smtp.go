// Package email provides email sending functionality
package email

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/smtp"
	"os"
	"time"

	"github.com/rw3iss/auth/internal/config"
)

// SMTPService implements EmailService using SMTP.
//
// HTML is rendered through the shared Renderer (the same one SendGrid
// uses) so the branded CivicGate templates + light/dark shell selection
// are identical across transports. Messages are sent as
// multipart/alternative (text/plain + text/html) for deliverability.
type SMTPService struct {
	cfg      config.EmailConfig
	renderer *Renderer
	log      *slog.Logger
}

// NewSMTPService creates a new SMTP email service. The renderer is
// required for HTML rendering; when nil the service degrades to
// plain-text-only sends (the PlainTextFallback body).
func NewSMTPService(cfg config.EmailConfig, renderer *Renderer, log *slog.Logger) (*SMTPService, error) {
	if log == nil {
		log = slog.Default()
	}
	return &SMTPService{
		cfg:      cfg,
		renderer: renderer,
		log:      log,
	}, nil
}

// smtpSendArgs mirrors sendgrid.sendArgs — the common shape each send
// method assembles before renderAndSend renders + transmits it.
type smtpSendArgs struct {
	template  string
	to        string
	subject   string
	preview   string
	colorMode string // "dark"|"light"; "" ⇒ dark
	data      map[string]any
	ctaURL    string // surfaced to the text/plain fallback
}

// renderAndSend renders the template through the shared Renderer and
// dispatches a multipart/alternative message. Falls back to a
// plain-text-only send when no renderer is wired.
func (s *SMTPService) renderAndSend(args smtpSendArgs) error {
	brand := s.cfg.FromName
	var html string
	if s.renderer != nil {
		brand = s.renderer.brandName
		rendered, err := s.renderer.Render(RenderInput{
			Name:        args.template,
			Subject:     args.subject,
			PreviewText: args.preview,
			ColorMode:   args.colorMode,
			Data:        args.data,
		})
		if err != nil {
			return fmt.Errorf("render %s: %w", args.template, err)
		}
		html = rendered.HTML
	}
	plain := PlainTextFallback(brand, args.subject, args.ctaURL)
	return s.send(args.to, args.subject, plain, html)
}

// SendVerificationEmail sends an email verification link.
func (s *SMTPService) SendVerificationEmail(ctx context.Context, appBaseURL, email, firstName, token, colorMode string) error {
	url := fmt.Sprintf("%s/auth/verify-email?token=%s", resolveBaseURL(appBaseURL), token)
	return s.renderAndSend(smtpSendArgs{
		template:  "verification",
		to:        email,
		subject:   "Verify your email address",
		preview:   "Confirm your email so we know we can reach you.",
		colorMode: colorMode,
		data: map[string]any{
			"FirstName":       firstName,
			"VerificationURL": url,
			"ExpiryHours":     24,
		},
		ctaURL: url,
	})
}

// SendPasswordResetEmail sends a password reset link.
func (s *SMTPService) SendPasswordResetEmail(ctx context.Context, appBaseURL, email, firstName, token, colorMode string) error {
	url := fmt.Sprintf("%s/auth/reset?token=%s", resolveBaseURL(appBaseURL), token)
	return s.renderAndSend(smtpSendArgs{
		template:  "password_reset",
		to:        email,
		subject:   "Reset your password",
		preview:   "Click the button to choose a new password.",
		colorMode: colorMode,
		data: map[string]any{
			"FirstName":     firstName,
			"ResetURL":      url,
			"ExpiryMinutes": 60,
		},
		ctaURL: url,
	})
}

// SendMagicLinkEmail delivers a one-tap sign-in link.
func (s *SMTPService) SendMagicLinkEmail(ctx context.Context, appBaseURL, email, firstName, token string) error {
	url := fmt.Sprintf("%s/auth/magic-link/verify?token=%s", resolveBaseURL(appBaseURL), token)
	return s.renderAndSend(smtpSendArgs{
		template: "magic_link",
		to:       email,
		subject:  "Your sign-in link",
		preview:  "One-tap sign-in — no password needed.",
		data: map[string]any{
			"FirstName":     firstName,
			"URL":           url,
			"ExpiryMinutes": 15,
		},
		ctaURL: url,
	})
}

// SendInvitationEmail sends an organization invitation.
func (s *SMTPService) SendInvitationEmail(ctx context.Context, appBaseURL, email, orgName, inviterName, code, token string) error {
	url := fmt.Sprintf("%s/auth/accept-invite?code=%s&token=%s", resolveBaseURL(appBaseURL), code, token)
	return s.renderAndSend(smtpSendArgs{
		template: "invitation",
		to:       email,
		subject:  fmt.Sprintf("You've been invited to join %s", orgName),
		preview:  fmt.Sprintf("%s invited you to %s.", inviterName, orgName),
		data: map[string]any{
			"OrgName":     orgName,
			"InviterName": inviterName,
			"AcceptURL":   url,
			"Code":        code,
			"ExpiryDays":  7,
		},
		ctaURL: url,
	})
}

// SendWelcomeEmail sends a welcome email after registration.
func (s *SMTPService) SendWelcomeEmail(ctx context.Context, appBaseURL, email, firstName string) error {
	base := resolveBaseURL(appBaseURL)
	return s.renderAndSend(smtpSendArgs{
		template: "welcome",
		to:       email,
		subject:  "Welcome to CivicGate",
		preview:  "Your account is ready.",
		data: map[string]any{
			"FirstName":    firstName,
			"DashboardURL": base,
		},
	})
}

// SendPasswordChangedEmail notifies user of password change.
func (s *SMTPService) SendPasswordChangedEmail(ctx context.Context, appBaseURL, email, firstName string) error {
	base := resolveBaseURL(appBaseURL)
	return s.renderAndSend(smtpSendArgs{
		template: "password_changed",
		to:       email,
		subject:  "Your password was changed",
		preview:  "Heads-up — your password just changed.",
		data: map[string]any{
			"FirstName":   firstName,
			"SecurityURL": base + "/profile",
		},
	})
}

// SendSecurityAlertEmail sends a security alert.
func (s *SMTPService) SendSecurityAlertEmail(ctx context.Context, appBaseURL, email, firstName, alertType, details string) error {
	base := resolveBaseURL(appBaseURL)
	return s.renderAndSend(smtpSendArgs{
		template: "security_alert",
		to:       email,
		subject:  fmt.Sprintf("Security alert: %s", alertType),
		preview:  "We noticed something on your account.",
		data: map[string]any{
			"FirstName":   firstName,
			"AlertType":   alertType,
			"Details":     details,
			"SecurityURL": base + "/profile",
		},
	})
}

// send transmits a message over SMTP. When html is non-empty the body is
// multipart/alternative (text/plain + text/html); otherwise it's a bare
// text/plain message.
func (s *SMTPService) send(to, subject, plain, html string) error {
	from := s.cfg.FromAddress
	if s.cfg.FromName != "" {
		from = fmt.Sprintf("%s <%s>", s.cfg.FromName, s.cfg.FromAddress)
	}

	var msg bytes.Buffer
	fmt.Fprintf(&msg, "From: %s\r\n", from)
	fmt.Fprintf(&msg, "To: %s\r\n", to)
	fmt.Fprintf(&msg, "Subject: %s\r\n", subject)
	msg.WriteString("MIME-Version: 1.0\r\n")

	if html == "" {
		msg.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
		msg.WriteString(plain)
	} else {
		boundary := fmt.Sprintf("cg-boundary-%d", time.Now().UnixNano())
		fmt.Fprintf(&msg, "Content-Type: multipart/alternative; boundary=%q\r\n\r\n", boundary)
		fmt.Fprintf(&msg, "--%s\r\n", boundary)
		msg.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
		msg.WriteString(plain + "\r\n\r\n")
		fmt.Fprintf(&msg, "--%s\r\n", boundary)
		msg.WriteString("Content-Type: text/html; charset=UTF-8\r\n\r\n")
		msg.WriteString(html + "\r\n\r\n")
		fmt.Fprintf(&msg, "--%s--\r\n", boundary)
	}
	message := msg.Bytes()

	addr := fmt.Sprintf("%s:%d", s.cfg.SMTPHost, s.cfg.SMTPPort)

	var auth smtp.Auth
	if s.cfg.SMTPUser != "" {
		auth = smtp.PlainAuth("", s.cfg.SMTPUser, s.cfg.SMTPPassword, s.cfg.SMTPHost)
	}

	if s.cfg.SMTPSecure {
		return s.sendTLS(addr, auth, s.cfg.FromAddress, to, message)
	}

	return smtp.SendMail(addr, auth, s.cfg.FromAddress, []string{to}, message)
}

func (s *SMTPService) sendTLS(addr string, auth smtp.Auth, from, to string, msg []byte) error {
	tlsConfig := &tls.Config{
		ServerName: s.cfg.SMTPHost,
	}

	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to dial TLS: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, s.cfg.SMTPHost)
	if err != nil {
		return fmt.Errorf("failed to create SMTP client: %w", err)
	}
	defer client.Close()

	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("failed to authenticate: %w", err)
		}
	}

	if err := client.Mail(from); err != nil {
		return fmt.Errorf("failed to set sender: %w", err)
	}

	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("failed to set recipient: %w", err)
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("failed to get data writer: %w", err)
	}

	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("failed to close writer: %w", err)
	}

	return client.Quit()
}

// resolveBaseURL picks the frontend origin for an email link. Order:
//
//  1. The per-app URL passed in (loaded from apps.frontend_url on the
//     row matching the app_code that initiated the flow).
//  2. The CLIENT_URL env var — single-tenant fallback for deployments
//     that haven't onboarded per-app URLs yet.
//  3. localhost:3000 — last-resort dev default.
//
// Callers pass "" when they don't know which app initiated the send
// (system-emitted security alerts, etc.) and accept the fallback.
func resolveBaseURL(appBaseURL string) string {
	if appBaseURL != "" {
		return appBaseURL
	}
	if url := os.Getenv("CLIENT_URL"); url != "" {
		return url
	}
	return "http://localhost:3000"
}

// NoOpEmailService is the fallback implementation when no real provider
// is configured. Historically it silently returned nil, which hid every
// password-reset / verify-email / invitation token because they were
// only sent through email and never logged anywhere.
//
// The new behavior: log every call at INFO level with the full token /
// URL so developers can grab a reset link from journalctl in
// development. Production should always wire a real provider (SMTP or
// Postmark) and treat the appearance of these log lines as a config bug.
type NoOpEmailService struct {
	log *slog.Logger
}

// NewNoOpEmailService wires the dev-friendly logging fallback. Pass nil
// to use slog.Default().
func NewNoOpEmailService(log *slog.Logger) *NoOpEmailService {
	if log == nil {
		log = slog.Default()
	}
	return &NoOpEmailService{log: log}
}

func (s *NoOpEmailService) SendVerificationEmail(_ context.Context, appBaseURL, email, firstName, token, colorMode string) error {
	url := fmt.Sprintf("%s/auth/verify-email?token=%s", resolveBaseURL(appBaseURL), token)
	s.log.Info("email (suppressed: no provider configured) — verify-email",
		"to", email, "first_name", firstName, "color_mode", colorMode, "verify_url", url)
	return nil
}

func (s *NoOpEmailService) SendPasswordResetEmail(_ context.Context, appBaseURL, email, firstName, token, colorMode string) error {
	url := fmt.Sprintf("%s/auth/reset?token=%s", resolveBaseURL(appBaseURL), token)
	s.log.Info("email (suppressed: no provider configured) — password-reset",
		"to", email, "first_name", firstName, "color_mode", colorMode, "reset_url", url)
	return nil
}

func (s *NoOpEmailService) SendInvitationEmail(_ context.Context, appBaseURL, email, orgName, inviterName, code, token string) error {
	url := fmt.Sprintf("%s/auth/accept-invite?code=%s&token=%s", resolveBaseURL(appBaseURL), code, token)
	s.log.Info("email (suppressed: no provider configured) — invitation",
		"to", email, "org", orgName, "inviter", inviterName, "code", code, "accept_url", url)
	return nil
}

func (s *NoOpEmailService) SendWelcomeEmail(_ context.Context, appBaseURL, email, firstName string) error {
	s.log.Info("email (suppressed) — welcome",
		"to", email, "first_name", firstName, "dashboard_url", resolveBaseURL(appBaseURL))
	return nil
}

func (s *NoOpEmailService) SendPasswordChangedEmail(_ context.Context, appBaseURL, email, firstName string) error {
	s.log.Info("email (suppressed) — password-changed",
		"to", email, "first_name", firstName, "security_url", resolveBaseURL(appBaseURL)+"/profile")
	return nil
}

func (s *NoOpEmailService) SendSecurityAlertEmail(_ context.Context, appBaseURL, email, firstName, alertType, details string) error {
	s.log.Info("email (suppressed) — security-alert",
		"to", email, "first_name", firstName, "alert_type", alertType, "details", details,
		"security_url", resolveBaseURL(appBaseURL)+"/profile")
	return nil
}

func (s *NoOpEmailService) SendMagicLinkEmail(_ context.Context, appBaseURL, email, firstName, token string) error {
	url := fmt.Sprintf("%s/auth/magic-link/verify?token=%s", resolveBaseURL(appBaseURL), token)
	s.log.Info("email (suppressed: no provider configured) — magic-link",
		"to", email, "first_name", firstName, "verify_url", url)
	return nil
}
