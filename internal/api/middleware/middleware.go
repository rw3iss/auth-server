package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/rw3iss/auth/internal/cache"
	"github.com/rw3iss/auth/internal/config"
	"github.com/rw3iss/auth/internal/logging"
	"github.com/rw3iss/auth/pkg/shared/errors"
)

// writeError writes an error response
func writeError(w http.ResponseWriter, err *errors.AppError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(err.HTTPStatus)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]interface{}{
			"code":    err.Code,
			"message": err.Message,
			"details": err.Details,
		},
	})
}

// CORS middleware handles Cross-Origin Resource Sharing.
//
// AUDIT 1.19: when the allowlist contains `*` and the previous implementation
// echoed the request origin into Access-Control-Allow-Origin AND set
// Access-Control-Allow-Credentials, browsers' built-in guard against `*` +
// credentials was bypassed (the guard checks the literal `*`, not echoed
// origins). The new behavior:
//
//   - `*` in the list → allow ANY origin, but do NOT set
//     Access-Control-Allow-Credentials. Cookie/Authorization-based flows
//     simply won't work from cross-origin in this mode, which is the
//     correct semantic.
//   - explicit origin in the list → echo + set credentials true. Works as
//     expected for first-party browser apps.
//
// Operators in production should never use `*`. config.Validate() refuses
// to start when CORS_ORIGINS=* in production environment.
func CORS(allowedOrigins []string) func(http.Handler) http.Handler {
	hasWildcard := false
	for _, o := range allowedOrigins {
		if o == "*" {
			hasWildcard = true
			break
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Determine allow/echo behavior. Explicit match always wins
			// (and gets credentials). Wildcard match returns `*` and
			// disables credentials so the browser's same-origin guard
			// kicks in instead.
			allowed := false
			explicit := false
			for _, o := range allowedOrigins {
				if o == origin {
					allowed = true
					explicit = true
					break
				}
			}
			if !allowed && hasWildcard {
				allowed = true
			}

			if allowed {
				if explicit {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				} else {
					// Wildcard match — emit literal `*`, no credentials.
					w.Header().Set("Access-Control-Allow-Origin", "*")
				}
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
				// AUDIT L4: expanded header list. Beyond the originals,
				// browser SDK + middleware features need:
				//   - Idempotency-Key — AUDIT 9.4 / B8 idempotent retries
				//   - X-CSRF-Token — AUDIT 9.2 double-submit cookie defense
				//   - X-App-Code — convenience for app-scoped requests
				//     when the client doesn't include the claim in the body
				w.Header().Set("Access-Control-Allow-Headers",
					"Accept, Authorization, Content-Type, X-Request-ID, "+
						"Idempotency-Key, X-CSRF-Token, X-App-Code")
				w.Header().Set("Access-Control-Max-Age", "86400")
			}

			// Handle preflight
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Recovery middleware recovers from panics. Logs via slog so the request_id
// from context shows up on the stack trace line.
func Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				logging.FromContext(r.Context()).Error("panic recovered",
					"err", err,
					"stack", string(debug.Stack()),
				)
				writeError(w, errors.Internal("Internal server error"))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// RequestID middleware adds a request ID to both the response header and
// the request context. Downstream handlers and services can read it via
// logging.RequestIDFromContext for correlation.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = generateRequestID()
		}
		w.Header().Set("X-Request-ID", requestID)
		ctx := logging.WithRequestID(r.Context(), requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func generateRequestID() string {
	return time.Now().Format("20060102150405.000000")
}

// Logger middleware emits one structured line per request:
//
//	level=info method=POST path=/auth/login status=200 dur_ms=12 request_id=...
//
// AUDIT 1.25: paths that carry sensitive query strings (`?token=...` on
// verify-email, `?code=...&state=...` on SSO callback) get the query
// stripped before logging. Otherwise the access log leaks reset/verify
// tokens via every log forwarder downstream.
func Logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create response writer wrapper to capture status code
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(rw, r)

		duration := time.Since(start)
		path := r.URL.Path
		// Append query for non-sensitive paths only.
		if r.URL.RawQuery != "" && !sensitiveQueryPath(path) {
			path = path + "?" + r.URL.RawQuery
		}
		logging.FromContext(r.Context()).Info("request",
			"method", r.Method,
			"path", path,
			"status", rw.statusCode,
			"dur_ms", duration.Milliseconds(),
		)
	})
}

// sensitiveQueryPath returns true for paths whose query string can carry
// secrets we don't want in access logs. Listed paths drop the query
// entirely from the logged path. AUDIT 1.25.
func sensitiveQueryPath(path string) bool {
	for _, p := range []string{"/auth/verify-email", "/auth/sso/callback", "/auth/password/reset"} {
		if path == p || strings.HasSuffix(path, p) {
			return true
		}
	}
	return false
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// RateLimiter provides rate limiting middleware
type RateLimiter struct {
	cfg        config.SecurityConfig
	tokenCache cache.TokenCache
	clients    map[string]*clientRateLimit
	mu         sync.RWMutex
}

type clientRateLimit struct {
	requests int
	resetAt  time.Time
}

// NewRateLimiter creates a new rate limiter. AUDIT 5.6: pass a context
// derived from the server's shutdown signal so the cleanup goroutine
// exits cleanly when the process is shutting down rather than leaking
// past server.Shutdown(). Pass context.Background() for tests / one-off
// scripts that don't care.
func NewRateLimiter(ctx context.Context, cfg config.SecurityConfig, tokenCache cache.TokenCache) *RateLimiter {
	rl := &RateLimiter{
		cfg:        cfg,
		tokenCache: tokenCache,
		clients:    make(map[string]*clientRateLimit),
	}
	go rl.cleanup(ctx)
	return rl
}

// Limit middleware applies rate limiting
func (rl *RateLimiter) Limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r)

		// Try Redis-based rate limiting first
		if rl.tokenCache != nil {
			count, err := rl.tokenCache.IncrementRateLimit(context.Background(), clientIP, rl.cfg.RateLimitWindow)
			if err == nil {
				if count > int64(rl.cfg.RateLimitRequests) {
					resetAt := time.Now().Add(rl.cfg.RateLimitWindow)
					w.Header().Set("Retry-After", resetAt.Format(time.RFC1123))
					writeError(w, errors.RateLimited())
					return
				}
				next.ServeHTTP(w, r)
				return
			}
			// Fall through to in-memory on Redis error
		}

		// In-memory fallback
		rl.mu.Lock()
		client, ok := rl.clients[clientIP]
		if !ok || time.Now().After(client.resetAt) {
			rl.clients[clientIP] = &clientRateLimit{
				requests: 1,
				resetAt:  time.Now().Add(rl.cfg.RateLimitWindow),
			}
			rl.mu.Unlock()
			next.ServeHTTP(w, r)
			return
		}

		if client.requests >= rl.cfg.RateLimitRequests {
			rl.mu.Unlock()
			w.Header().Set("Retry-After", client.resetAt.Format(time.RFC1123))
			writeError(w, errors.RateLimited())
			return
		}

		client.requests++
		rl.mu.Unlock()

		next.ServeHTTP(w, r)
	})
}

// cleanup periodically evicts expired per-client entries from the
// in-memory fallback map. Exits when ctx is cancelled (typically when
// the server's shutdown context fires). AUDIT 5.6.
func (rl *RateLimiter) cleanup(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rl.mu.Lock()
			now := time.Now()
			for k, v := range rl.clients {
				if now.After(v.resetAt) {
					delete(rl.clients, k)
				}
			}
			rl.mu.Unlock()
		}
	}
}

// getClientIP delegates to RealIP — the trusted-proxy-aware extractor.
// Kept as a thin shim so the middleware call sites read naturally.
func getClientIP(r *http.Request) string {
	return RealIP(r)
}

// ContentType middleware sets the content type header
func ContentType(contentType string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", contentType)
			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeadersOptions configures the SecurityHeaders middleware
// (AUDIT 1.20). All fields are optional; the defaults below match what
// the audit recommended.
type SecurityHeadersOptions struct {
	// Production controls inclusion of Strict-Transport-Security. HSTS
	// pins the browser to HTTPS for the configured max-age; turning it
	// on for a development server that doesn't have valid TLS leaves a
	// stuck-on-HTTPS browser permanently unable to load the dev origin
	// until it expires. So we gate strictly on the production flag.
	Production bool
	// ContentSecurityPolicy overrides the default CSP. Empty value
	// applies the default for a JSON API: `default-src 'none'; frame-ancestors 'none'`.
	// Operators serving an OAuth-callback HTML page from this server
	// would loosen via this override.
	ContentSecurityPolicy string
}

// SecurityHeaders returns the headers middleware. AUDIT 1.20:
//
//   - X-Content-Type-Options: nosniff — kept; cheap defense against
//     MIME confusion.
//   - X-Frame-Options: DENY — kept; legacy clickjacking gate.
//   - Referrer-Policy: strict-origin-when-cross-origin — kept.
//   - Cache-Control: no-store — kept; auth responses shouldn't cache.
//   - Strict-Transport-Security — NEW, production-only (see opts).
//   - Content-Security-Policy — NEW, default 'none' (JSON API surface).
//   - X-XSS-Protection — DROPPED. Deprecated, no modern browser honors
//     it, and the 1; mode=block setting historically introduced its own
//     XSS bypass vectors. Modern protection is CSP.
//   - Permissions-Policy — NEW, locks out powerful browser features so
//     a stolen subdomain can't enable camera/mic/etc on the auth origin.
func SecurityHeaders(opts SecurityHeadersOptions) func(http.Handler) http.Handler {
	csp := opts.ContentSecurityPolicy
	if csp == "" {
		csp = "default-src 'none'; frame-ancestors 'none'"
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Security-Policy", csp)
			w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
			if opts.Production {
				// 1 year, includeSubDomains, preload-ready. Operators
				// who don't want this should not set ENVIRONMENT=production
				// until they've verified TLS works on every subdomain
				// that resolves to the auth origin.
				w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Chain chains multiple middleware together
func Chain(middlewares ...func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(final http.Handler) http.Handler {
		for i := len(middlewares) - 1; i >= 0; i-- {
			final = middlewares[i](final)
		}
		return final
	}
}
