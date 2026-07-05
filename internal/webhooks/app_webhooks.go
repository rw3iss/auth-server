// Per-app webhook dispatch (migration 019). Unlike the operator-level
// Dispatcher stub in webhooks.go (env-configured, audit-event taxonomy),
// these hooks are configured PER APP by a system_admin
// (apps.webhooks JSONB) and fire on app-scoped events — currently only
// "user.registered".
//
// Delivery semantics: async (one goroutine per hook), best-effort.
// 5s timeout per attempt, 3 attempts with linear backoff (0s/2s/4s).
// Failures are slog-logged and dropped — registration NEVER fails or
// blocks on a webhook receiver.
//
// Slack: URLs under hooks.slack.com expect Slack's incoming-webhook
// format, so those receive {"text": "<human summary>"} instead of the
// raw event envelope. (The channel is bound to the Slack webhook URL
// itself — Slack ignores channel overrides on modern incoming hooks.)
package webhooks

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ven/auth/internal/domain"
)

// RegistrationEvent is the JSON envelope POSTed to app webhooks for
// user.registered. The registration body is passed through completely
// (including any extra/unknown fields the client sent) with secrets
// (password) redacted.
type RegistrationEvent struct {
	Event     string `json:"event"` // "user.registered"
	Timestamp string `json:"timestamp"`

	App struct {
		ID   string `json:"id"`
		Code string `json:"code"`
		Name string `json:"name"`
	} `json:"app"`

	User struct {
		ID          string   `json:"id"`
		Email       string   `json:"email"`
		FirstName   string   `json:"first_name,omitempty"`
		LastName    string   `json:"last_name,omitempty"`
		DisplayName string   `json:"display_name,omitempty"`
		Namespace   string   `json:"namespace"`
		Pools       []string `json:"pools,omitempty"` // [home, ...tags]
	} `json:"user"`

	// Organization the user landed in (invite / created / app default),
	// when any.
	Organization *struct {
		ID   string `json:"id"`
		Slug string `json:"slug"`
		Name string `json:"name"`
	} `json:"organization,omitempty"`

	// Registration is the request body as received (password redacted,
	// extra/unknown client fields preserved).
	Registration map[string]any `json:"registration"`

	// Context — server-side request metadata.
	Context struct {
		IP        string `json:"ip,omitempty"`
		UserAgent string `json:"user_agent,omitempty"`
		Server    string `json:"server,omitempty"` // issuer, e.g. "ven-auth"
	} `json:"context"`
}

const (
	dispatchTimeout  = 5 * time.Second
	dispatchAttempts = 3
)

var httpClient = &http.Client{Timeout: dispatchTimeout}

// DispatchRegistration fans a user.registered event out to every
// enabled, subscribed webhook on the app. Returns immediately; delivery
// happens in background goroutines. Safe to call with a nil app or no
// matching hooks (no-op).
func DispatchRegistration(app *domain.App, event RegistrationEvent) {
	hooks := app.WebhooksFor(domain.WebhookEventUserRegistered)
	if len(hooks) == 0 {
		return
	}
	body, err := json.Marshal(event)
	if err != nil {
		slog.Error("webhook: marshal registration event", "err", err)
		return
	}
	for _, h := range hooks {
		go deliver(h, event, body)
	}
}

// deliver posts one event to one hook with retries. Runs detached from
// the request context on purpose — the HTTP response to the registrant
// must not wait on (or be cancelled with) webhook delivery.
func deliver(hook domain.AppWebhook, event RegistrationEvent, rawBody []byte) {
	body := rawBody
	contentType := "application/json"
	if isSlackURL(hook.URL) {
		body = slackBody(event)
	}

	var lastErr error
	for attempt := 1; attempt <= dispatchAttempts; attempt++ {
		if attempt > 1 {
			time.Sleep(time.Duration(attempt-1) * 2 * time.Second)
		}
		ctx, cancel := context.WithTimeout(context.Background(), dispatchTimeout)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, hook.URL, bytes.NewReader(body))
		if err != nil {
			cancel()
			slog.Error("webhook: build request", "url", hook.URL, "err", err)
			return
		}
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("X-Vendidit-Event", event.Event)
		resp, err := httpClient.Do(req)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		if resp.StatusCode < 300 {
			slog.Info("webhook delivered",
				"event", event.Event, "app", event.App.Code,
				"hook", hook.Name, "url", redactURL(hook.URL), "attempt", attempt)
			return
		}
		// 4xx (except 408/429) won't get better — drop without retrying.
		if resp.StatusCode >= 400 && resp.StatusCode < 500 &&
			resp.StatusCode != http.StatusRequestTimeout && resp.StatusCode != http.StatusTooManyRequests {
			slog.Warn("webhook rejected (permanent)",
				"event", event.Event, "app", event.App.Code,
				"hook", hook.Name, "url", redactURL(hook.URL), "status", resp.StatusCode)
			return
		}
		lastErr = nil // retryable status; loop
	}
	slog.Warn("webhook delivery failed (gave up)",
		"event", event.Event, "app", event.App.Code,
		"hook", hook.Name, "url", redactURL(hook.URL),
		"attempts", dispatchAttempts, "err", lastErr)
}

// isSlackURL reports whether the hook points at Slack's incoming-webhook
// service (which requires its own body format).
func isSlackURL(u string) bool {
	return strings.Contains(u, "hooks.slack.com/")
}

// slackBody renders a human-readable Slack message for the event.
func slackBody(e RegistrationEvent) []byte {
	name := strings.TrimSpace(e.User.FirstName + " " + e.User.LastName)
	if name == "" {
		name = e.User.DisplayName
	}
	var b strings.Builder
	b.WriteString(":tada: *New signup* — ")
	if name != "" {
		b.WriteString(name)
		b.WriteString(" ")
	}
	b.WriteString("<mailto:" + e.User.Email + "|" + e.User.Email + ">")
	b.WriteString("\n• App: *" + e.App.Name + "* (`" + e.App.Code + "`)")
	if e.User.Namespace != "" && e.User.Namespace != "default" {
		b.WriteString("\n• Pool: `" + e.User.Namespace + "`")
	}
	if e.Organization != nil {
		b.WriteString("\n• Organization: " + e.Organization.Name)
	}
	// Surface any extra (non-standard) registration fields — useful for
	// campaign / referral metadata that clients attach.
	if len(e.Registration) > 0 {
		std := map[string]bool{
			"email": true, "password": true, "first_name": true, "last_name": true,
			"phone": true, "display_name": true, "organization_name": true,
			"invite_code": true, "invite_token": true, "app_code": true, "mode": true,
		}
		var extras []string
		for k, v := range e.Registration {
			if !std[k] {
				if vb, err := json.Marshal(v); err == nil {
					extras = append(extras, "`"+k+"`="+string(vb))
				}
			}
		}
		if len(extras) > 0 {
			b.WriteString("\n• Extra: " + strings.Join(extras, ", "))
		}
	}
	msg, _ := json.Marshal(map[string]string{"text": b.String()})
	return msg
}

// redactURL trims webhook URLs for logs — Slack hook paths embed a
// secret token, so keep only scheme+host+first path segment.
func redactURL(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		rest := u[i+3:]
		if j := strings.Index(rest, "/"); j >= 0 {
			seg := rest[j:]
			if k := strings.Index(seg[1:], "/"); k >= 0 {
				return u[:i+3] + rest[:j] + seg[:k+1] + "/…"
			}
		}
	}
	return u
}
