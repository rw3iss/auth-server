// Package logging provides the auth-server's structured logger and
// context-propagation utilities.
//
// AUDIT 7.3: the service was using log.Printf everywhere, which produces
// flat text lines with no level, no request correlation, no fields. This
// package replaces that with slog (Go 1.21+):
//
//   - JSON in production, text in development.
//   - Default logger set via slog.SetDefault so a bare slog.Info(...) call
//     anywhere in the codebase routes through the configured handler.
//   - Request IDs propagated via context so service-layer logs are
//     automatically tagged with the request that triggered them.
//
// Usage from non-handler code (services, repos):
//
//	logging.FromContext(ctx).Info("user logged in", "user_id", u.ID)
//
// The returned logger always has the request_id field set when one is
// present in the context.
package logging

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
)

// ctxKey is a private type so callers can't accidentally collide with our
// context keys.
type ctxKey int

const (
	keyRequestID ctxKey = iota
	keyUserID
	keyLogger
)

// New returns a configured slog.Logger for the given environment and level.
// Format: JSON in production, key=value text everywhere else. The level
// string accepts "debug", "info", "warn", "error" (case-insensitive);
// anything else falls back to info.
func New(env, level string, w io.Writer) *slog.Logger {
	if w == nil {
		w = os.Stdout
	}
	opts := &slog.HandlerOptions{
		Level: parseLevel(level),
	}

	var h slog.Handler
	if strings.EqualFold(env, "production") {
		h = slog.NewJSONHandler(w, opts)
	} else {
		h = slog.NewTextHandler(w, opts)
	}
	return slog.New(h)
}

// SetDefault installs the logger as the package-level default so plain
// slog.Info(...) calls from anywhere route through it. Called once at
// server boot.
func SetDefault(l *slog.Logger) {
	slog.SetDefault(l)
}

// WithRequestID returns a context that carries the given request ID.
// FromContext on the returned context will produce a logger pre-bound
// with `request_id=<id>`.
func WithRequestID(ctx context.Context, id string) context.Context {
	if id == "" {
		return ctx
	}
	return context.WithValue(ctx, keyRequestID, id)
}

// RequestIDFromContext returns the request ID, or "" if not present.
func RequestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(keyRequestID).(string); ok {
		return v
	}
	return ""
}

// WithUserID stamps the authenticated user's ID onto the context so log
// lines emitted during the rest of the request are automatically tagged.
// Called from AuthMiddleware after JWT validation.
func WithUserID(ctx context.Context, id string) context.Context {
	if id == "" {
		return ctx
	}
	return context.WithValue(ctx, keyUserID, id)
}

// UserIDFromContext returns the user ID, or "" if not present.
func UserIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(keyUserID).(string); ok {
		return v
	}
	return ""
}

// WithLogger overrides the logger for a request scope. Most callers don't
// need this — FromContext handles the common case.
func WithLogger(ctx context.Context, l *slog.Logger) context.Context {
	return context.WithValue(ctx, keyLogger, l)
}

// FromContext returns a logger pre-bound with the request_id and user_id
// fields when those are present in the context. Falls back to the
// package-level default logger otherwise. Always returns a non-nil logger.
//
// Layered services should always reach for the logger this way rather than
// holding a reference at construction time, so per-request correlation
// fields propagate automatically.
func FromContext(ctx context.Context) *slog.Logger {
	base := slog.Default()
	if v, ok := ctx.Value(keyLogger).(*slog.Logger); ok && v != nil {
		base = v
	}

	attrs := make([]any, 0, 4)
	if rid := RequestIDFromContext(ctx); rid != "" {
		attrs = append(attrs, "request_id", rid)
	}
	if uid := UserIDFromContext(ctx); uid != "" {
		attrs = append(attrs, "user_id", uid)
	}
	if len(attrs) == 0 {
		return base
	}
	return base.With(attrs...)
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
