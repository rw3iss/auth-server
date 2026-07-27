package email

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/rw3iss/auth/internal/config"
)

// SendGridService delivers email via SendGrid's v3 native API.
//
//	POST https://api.sendgrid.com/v3/mail/send
//	Authorization: Bearer <API_KEY>
//	Content-Type: application/json
//
// HTML is rendered locally (via Renderer) and POSTed as a fully-baked
// string — we do NOT use SendGrid's dynamic-template / handlebars
// substitution, so all rendering choices stay in this codebase and
// designers / operators can preview templates with `go test`.
//
// Why local rendering: keeps providers swappable. The same rendered
// HTML works against SMTP / SES / Mailgun / Postmark / whatever
// without per-provider templates living in their respective consoles.
// Operators who DO want hosted templates can implement another
// concrete type — the EmailService interface doesn't care.
//
// Deliverability requirements (operator concern):
//   - The `from` address MUST be a verified Single Sender or a domain
//     SendGrid is authenticated on. Unverified senders return 403
//     "The from address does not match a verified Sender Identity".
//   - For high-volume transactional traffic, set up domain
//     authentication (SPF + DKIM CNAMEs) in the SendGrid console —
//     the API call doesn't change.
//
// Failure handling: SendGrid responds with 202 Accepted on success.
// Anything else is an error; we log the response body for diagnostics
// (auth, quota, sender-verification issues) but surface a generic
// error upstream — auth-server callers shouldn't second-guess the
// provider.
type SendGridService struct {
	apiKey      string
	fromAddress string
	fromName    string
	renderer    *Renderer
	httpClient  *http.Client
	log         *slog.Logger
}

// NewSendGridService wires the service. Returns an error if the API
// key is empty — boot-time check beats a 401 on first send.
func NewSendGridService(cfg config.EmailConfig, renderer *Renderer, log *slog.Logger) (*SendGridService, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("sendgrid: EMAIL_API_KEY is required (EMAIL_PROVIDER=sendgrid)")
	}
	if cfg.FromAddress == "" {
		return nil, fmt.Errorf("sendgrid: EMAIL_FROM_ADDRESS is required")
	}
	if log == nil {
		log = slog.Default()
	}
	return &SendGridService{
		apiKey:      cfg.APIKey,
		fromAddress: cfg.FromAddress,
		fromName:    cfg.FromName,
		renderer:    renderer,
		httpClient:  &http.Client{Timeout: 10 * time.Second},
		log:         log,
	}, nil
}

// SendVerificationEmail implements service.EmailService.
func (s *SendGridService) SendVerificationEmail(ctx context.Context, appBaseURL, email, firstName, token, colorMode string) error {
	url := fmt.Sprintf("%s/auth/verify-email?token=%s", resolveBaseURL(appBaseURL), token)
	return s.renderAndSend(ctx, sendArgs{
		Template:  "verification",
		To:        email,
		Subject:   "Verify your email address",
		Preview:   "Confirm your email so we know we can reach you.",
		ColorMode: colorMode,
		Data: map[string]any{
			"FirstName":       firstName,
			"VerificationURL": url,
			"ExpiryHours":     24,
		},
		CTAUrl: url,
	})
}

// SendPasswordResetEmail implements service.EmailService.
func (s *SendGridService) SendPasswordResetEmail(ctx context.Context, appBaseURL, email, firstName, token, colorMode string) error {
	url := fmt.Sprintf("%s/auth/reset?token=%s", resolveBaseURL(appBaseURL), token)
	return s.renderAndSend(ctx, sendArgs{
		Template:  "password_reset",
		To:        email,
		Subject:   "Reset your password",
		Preview:   "Click the button to choose a new password.",
		ColorMode: colorMode,
		Data: map[string]any{
			"FirstName":     firstName,
			"ResetURL":      url,
			"ExpiryMinutes": 60,
		},
		CTAUrl: url,
	})
}

// SendInvitationEmail implements service.EmailService.
func (s *SendGridService) SendInvitationEmail(ctx context.Context, appBaseURL, email, orgName, inviterName, code, token string) error {
	url := fmt.Sprintf("%s/auth/accept-invite?code=%s&token=%s", resolveBaseURL(appBaseURL), code, token)
	return s.renderAndSend(ctx, sendArgs{
		Template: "invitation",
		To:       email,
		Subject:  fmt.Sprintf("You've been invited to join %s", orgName),
		Preview:  fmt.Sprintf("%s invited you to %s.", inviterName, orgName),
		Data: map[string]any{
			"OrgName":     orgName,
			"InviterName": inviterName,
			"AcceptURL":   url,
			"Code":        code,
			"ExpiryDays":  7,
		},
		CTAUrl: url,
	})
}

// SendWelcomeEmail implements service.EmailService.
func (s *SendGridService) SendWelcomeEmail(ctx context.Context, appBaseURL, email, firstName string) error {
	base := resolveBaseURL(appBaseURL)
	return s.renderAndSend(ctx, sendArgs{
		Template: "welcome",
		To:       email,
		Subject:  "Welcome to rw3iss",
		Preview:  "Your account is ready.",
		Data: map[string]any{
			"FirstName":    firstName,
			"DashboardURL": base,
		},
	})
}

// SendPasswordChangedEmail implements service.EmailService.
func (s *SendGridService) SendPasswordChangedEmail(ctx context.Context, appBaseURL, email, firstName string) error {
	base := resolveBaseURL(appBaseURL)
	return s.renderAndSend(ctx, sendArgs{
		Template: "password_changed",
		To:       email,
		Subject:  "Your password was changed",
		Preview:  "Heads-up — your password just changed.",
		Data: map[string]any{
			"FirstName":   firstName,
			"ChangedAt":   time.Now().UTC().Format(time.RFC3339),
			"SecurityURL": base + "/profile",
		},
	})
}

// SendSecurityAlertEmail implements service.EmailService.
func (s *SendGridService) SendSecurityAlertEmail(ctx context.Context, appBaseURL, email, firstName, alertType, details string) error {
	base := resolveBaseURL(appBaseURL)
	return s.renderAndSend(ctx, sendArgs{
		Template: "security_alert",
		To:       email,
		Subject:  fmt.Sprintf("Security alert: %s", alertType),
		Preview:  "We noticed something on your account.",
		Data: map[string]any{
			"FirstName":   firstName,
			"AlertType":   alertType,
			"Details":     details,
			"SecurityURL": base + "/profile",
		},
	})
}

// SendMagicLinkEmail implements service.EmailService.
func (s *SendGridService) SendMagicLinkEmail(ctx context.Context, appBaseURL, email, firstName, token string) error {
	url := fmt.Sprintf("%s/auth/magic-link/verify?token=%s", resolveBaseURL(appBaseURL), token)
	return s.renderAndSend(ctx, sendArgs{
		Template: "magic_link",
		To:       email,
		Subject:  "Your sign-in link",
		Preview:  "One-tap sign-in — no password needed.",
		Data: map[string]any{
			"FirstName":     firstName,
			"URL":           url,
			"ExpiryMinutes": 15,
		},
		CTAUrl: url,
	})
}

// sendArgs is the common shape every send method assembles. Wrapped
// in a single helper that renders + POSTs so each method stays a
// thin parameter-mapping.
type sendArgs struct {
	Template string
	To       string
	Subject  string
	Preview  string
	// ColorMode selects the light/dark shell variant. "" ⇒ dark.
	ColorMode string
	Data      map[string]any
	// CTAUrl is the primary action link in the email. Surfaced to the
	// text/plain fallback so non-HTML clients still get a usable
	// message; not used in the HTML render itself (the per-purpose
	// template handles its own CTA markup).
	CTAUrl string
}

// renderAndSend renders the template through the shared Renderer
// and POSTs the result to SendGrid. Returns nil on 2xx; the error
// includes the response body for non-2xx.
func (s *SendGridService) renderAndSend(ctx context.Context, args sendArgs) error {
	rendered, err := s.renderer.Render(RenderInput{
		Name:        args.Template,
		Subject:     args.Subject,
		PreviewText: args.Preview,
		ColorMode:   args.ColorMode,
		Data:        args.Data,
	})
	if err != nil {
		return fmt.Errorf("render %s: %w", args.Template, err)
	}

	plain := PlainTextFallback(s.renderer.brandName, args.Subject, args.CTAUrl)

	body := sgRequest{
		Personalizations: []sgPersonalization{{
			To: []sgAddress{{Email: args.To}},
		}},
		From:    sgAddress{Email: s.fromAddress, Name: s.fromName},
		Subject: args.Subject,
		Content: []sgContent{
			{Type: "text/plain", Value: plain},
			{Type: "text/html", Value: rendered.HTML},
		},
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.sendgrid.com/v3/mail/send", bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+s.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sendgrid POST: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		s.log.Info("email sent via sendgrid",
			"to", args.To, "template", args.Template, "status", resp.StatusCode)
		return nil
	}

	respBody, _ := io.ReadAll(resp.Body)
	s.log.Error("sendgrid send failed",
		"to", args.To, "template", args.Template,
		"status", resp.StatusCode, "body", string(respBody))
	return fmt.Errorf("sendgrid send returned %d: %s", resp.StatusCode, string(respBody))
}

// SendGrid v3 mail/send JSON shape — subset we actually use. Full
// schema documented at https://docs.sendgrid.com/api-reference/mail-send/mail-send.

type sgRequest struct {
	Personalizations []sgPersonalization `json:"personalizations"`
	From             sgAddress           `json:"from"`
	Subject          string              `json:"subject"`
	Content          []sgContent         `json:"content"`
}

type sgPersonalization struct {
	To []sgAddress `json:"to"`
}

type sgAddress struct {
	Email string `json:"email"`
	Name  string `json:"name,omitempty"`
}

type sgContent struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}
