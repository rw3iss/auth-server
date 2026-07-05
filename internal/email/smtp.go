// Package email provides email sending functionality
package email

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"html/template"
	"log/slog"
	"net/smtp"
	"os"
	"path/filepath"

	"github.com/rw3iss/auth/internal/config"
)

// SMTPService implements EmailService using SMTP
type SMTPService struct {
	cfg       config.EmailConfig
	templates map[string]*template.Template
}

// NewSMTPService creates a new SMTP email service
func NewSMTPService(cfg config.EmailConfig) (*SMTPService, error) {
	service := &SMTPService{
		cfg:       cfg,
		templates: make(map[string]*template.Template),
	}

	// Load templates if path is specified
	if cfg.TemplatesPath != "" {
		if err := service.loadTemplates(); err != nil {
			// Don't fail, just log - templates might not exist yet
			fmt.Printf("Warning: Failed to load email templates: %v\n", err)
		}
	}

	return service, nil
}

func (s *SMTPService) loadTemplates() error {
	templateFiles := []string{
		"verification.html",
		"password_reset.html",
		"invitation.html",
		"welcome.html",
		"password_changed.html",
		"security_alert.html",
	}

	for _, file := range templateFiles {
		path := filepath.Join(s.cfg.TemplatesPath, file)
		tmpl, err := template.ParseFiles(path)
		if err != nil {
			continue // Skip missing templates
		}
		name := file[:len(file)-5] // Remove .html extension
		s.templates[name] = tmpl
	}

	return nil
}

// SendVerificationEmail sends an email verification link
func (s *SMTPService) SendVerificationEmail(ctx context.Context, appBaseURL, email, firstName, token string) error {
	subject := "Verify your email address"
	data := map[string]string{
		"FirstName":       firstName,
		"VerificationURL": fmt.Sprintf("%s/auth/verify-email?token=%s", resolveBaseURL(appBaseURL), token),
	}

	body, err := s.renderTemplate("verification", data)
	if err != nil {
		// Fallback to plain text
		body = fmt.Sprintf(`Hello %s,

Please verify your email address by clicking the link below:

%s

This link will expire in 24 hours.

Best regards,
The rw3iss Team`, firstName, data["VerificationURL"])
	}

	return s.send(email, subject, body)
}

// SendPasswordResetEmail sends a password reset link
func (s *SMTPService) SendPasswordResetEmail(ctx context.Context, appBaseURL, email, firstName, token string) error {
	subject := "Reset your password"
	resetURL := fmt.Sprintf("%s/auth/reset?token=%s", resolveBaseURL(appBaseURL), token)
	data := map[string]string{
		"FirstName": firstName,
		"ResetURL":  resetURL,
	}

	// Log the reset link to console for development
	fmt.Printf("\n========================================\n")
	fmt.Printf("PASSWORD RESET LINK for %s:\n%s\n", email, resetURL)
	fmt.Printf("========================================\n\n")

	body, err := s.renderTemplate("password_reset", data)
	if err != nil {
		body = fmt.Sprintf(`Hello %s,

You requested to reset your password. Click the link below to proceed:

%s

This link will expire in 1 hour. If you didn't request this, please ignore this email.

Best regards,
The rw3iss Team`, firstName, data["ResetURL"])
	}

	return s.send(email, subject, body)
}

// SendMagicLinkEmail delivers a one-tap sign-in link.
func (s *SMTPService) SendMagicLinkEmail(ctx context.Context, appBaseURL, email, firstName, token string) error {
	subject := "Your sign-in link"
	url := fmt.Sprintf("%s/auth/magic-link/verify?token=%s", resolveBaseURL(appBaseURL), token)
	data := map[string]string{"FirstName": firstName, "URL": url}
	body, err := s.renderTemplate("magic_link", data)
	if err != nil {
		// Fall through to inline copy when the template file is absent —
		// magic-link is a new flow (migration 014) and operators haven't
		// shipped a template for it in many existing deployments.
		body = fmt.Sprintf(`Hello %s,

Click the link below to sign in:

%s

This link expires in 15 minutes. If you didn't request it, ignore this email.

— The rw3iss Team`, firstName, url)
	}
	return s.send(email, subject, body)
}

// SendInvitationEmail sends an organization invitation
func (s *SMTPService) SendInvitationEmail(ctx context.Context, appBaseURL, email, orgName, inviterName, code, token string) error {
	subject := fmt.Sprintf("You've been invited to join %s", orgName)
	data := map[string]string{
		"OrgName":     orgName,
		"InviterName": inviterName,
		"Code":        code,
		"InviteURL":   fmt.Sprintf("%s/auth/accept-invite?code=%s&token=%s", resolveBaseURL(appBaseURL), code, token),
	}

	body, err := s.renderTemplate("invitation", data)
	if err != nil {
		body = fmt.Sprintf(`Hello,

%s has invited you to join %s on the rw3iss auction platform.

You can accept this invitation by:

1. Using this invite code: %s
2. Or clicking this link: %s

This invitation will expire in 7 days.

Best regards,
The rw3iss Team`, inviterName, orgName, code, data["InviteURL"])
	}

	return s.send(email, subject, body)
}

// SendWelcomeEmail sends a welcome email after registration
func (s *SMTPService) SendWelcomeEmail(ctx context.Context, appBaseURL, email, firstName string) error {
	_ = appBaseURL // SMTP welcome template is link-less; param kept for interface uniformity.
	subject := "Welcome to rw3iss"
	data := map[string]string{
		"FirstName": firstName,
	}

	body, err := s.renderTemplate("welcome", data)
	if err != nil {
		body = fmt.Sprintf(`Hello %s,

Welcome to rw3iss! We're excited to have you on board.

You can now access your account and start exploring our auction platform.

If you have any questions, feel free to reach out to our support team.

Best regards,
The rw3iss Team`, firstName)
	}

	return s.send(email, subject, body)
}

// SendPasswordChangedEmail notifies user of password change
func (s *SMTPService) SendPasswordChangedEmail(ctx context.Context, appBaseURL, email, firstName string) error {
	_ = appBaseURL // SMTP plain-text variant doesn't include a link; honored by HTML renderer in sendgrid.go.
	subject := "Your password has been changed"
	data := map[string]string{
		"FirstName": firstName,
	}

	body, err := s.renderTemplate("password_changed", data)
	if err != nil {
		body = fmt.Sprintf(`Hello %s,

Your password has been successfully changed.

If you didn't make this change, please contact our support team immediately.

Best regards,
The rw3iss Team`, firstName)
	}

	return s.send(email, subject, body)
}

// SendSecurityAlertEmail sends a security alert
func (s *SMTPService) SendSecurityAlertEmail(ctx context.Context, appBaseURL, email, firstName, alertType, details string) error {
	_ = appBaseURL // SMTP plain-text variant doesn't include a link; honored by HTML renderer in sendgrid.go.
	subject := "Security Alert"
	data := map[string]string{
		"FirstName": firstName,
		"AlertType": alertType,
		"Details":   details,
	}

	body, err := s.renderTemplate("security_alert", data)
	if err != nil {
		body = fmt.Sprintf(`Hello %s,

We detected unusual activity on your account:

Alert Type: %s
Details: %s

If this wasn't you, please secure your account immediately by changing your password.

Best regards,
The rw3iss Team`, firstName, alertType, details)
	}

	return s.send(email, subject, body)
}

func (s *SMTPService) renderTemplate(name string, data interface{}) (string, error) {
	tmpl, ok := s.templates[name]
	if !ok {
		return "", fmt.Errorf("template %s not found", name)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}

	return buf.String(), nil
}

func (s *SMTPService) send(to, subject, body string) error {
	from := s.cfg.FromAddress
	if s.cfg.FromName != "" {
		from = fmt.Sprintf("%s <%s>", s.cfg.FromName, s.cfg.FromAddress)
	}

	headers := make(map[string]string)
	headers["From"] = from
	headers["To"] = to
	headers["Subject"] = subject
	headers["MIME-Version"] = "1.0"
	headers["Content-Type"] = "text/html; charset=UTF-8"

	message := ""
	for k, v := range headers {
		message += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	message += "\r\n" + body

	addr := fmt.Sprintf("%s:%d", s.cfg.SMTPHost, s.cfg.SMTPPort)

	var auth smtp.Auth
	if s.cfg.SMTPUser != "" {
		auth = smtp.PlainAuth("", s.cfg.SMTPUser, s.cfg.SMTPPassword, s.cfg.SMTPHost)
	}

	if s.cfg.SMTPSecure {
		return s.sendTLS(addr, auth, s.cfg.FromAddress, to, []byte(message))
	}

	return smtp.SendMail(addr, auth, s.cfg.FromAddress, []string{to}, []byte(message))
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

func (s *NoOpEmailService) SendVerificationEmail(_ context.Context, appBaseURL, email, firstName, token string) error {
	url := fmt.Sprintf("%s/auth/verify-email?token=%s", resolveBaseURL(appBaseURL), token)
	s.log.Info("email (suppressed: no provider configured) — verify-email",
		"to", email, "first_name", firstName, "verify_url", url)
	return nil
}

func (s *NoOpEmailService) SendPasswordResetEmail(_ context.Context, appBaseURL, email, firstName, token string) error {
	url := fmt.Sprintf("%s/auth/reset?token=%s", resolveBaseURL(appBaseURL), token)
	s.log.Info("email (suppressed: no provider configured) — password-reset",
		"to", email, "first_name", firstName, "reset_url", url)
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
