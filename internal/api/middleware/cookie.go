package middleware

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/ven/auth/pkg/shared/errors"
)

// Cookie + CSRF support. AUDIT 9.2: for first-party browser SDKs,
// HttpOnly + SameSite + Secure cookies are immune to the XSS token-theft
// path. They require CSRF defense — we use the double-submit cookie
// pattern (a non-HttpOnly csrf_token cookie + matching X-CSRF-Token header).
//
// The shape stays opt-in: tokens still travel in the Authorization header
// by default. Client sets `cookie_mode: true` on /auth/login (handled by
// the AuthHandler — this file is just the middleware primitives).
//
// Cookie names are constants so any callers (login response writer, future
// admin-dashboard) reference the same values.

const (
	AccessCookieName  = "vendidit_access"
	RefreshCookieName = "vendidit_refresh"
	CSRFCookieName    = "vendidit_csrf"
	CSRFHeaderName    = "X-CSRF-Token"
)

// SetAuthCookies writes the access + refresh + CSRF cookies. The CSRF
// cookie is the only one that is NOT HttpOnly (the JS layer needs to read
// it to mirror in the X-CSRF-Token header). All cookies are Secure in
// production; Path-scoped: refresh tokens are sent only to /auth/refresh
// so they're not leaked into every cross-app request.
func SetAuthCookies(w http.ResponseWriter, isProduction bool, accessToken, refreshToken, csrfToken string, accessMaxAgeSec, refreshMaxAgeSec int) {
	secure := isProduction
	sameSite := http.SameSiteLaxMode

	http.SetCookie(w, &http.Cookie{
		Name:     AccessCookieName,
		Value:    accessToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: sameSite,
		MaxAge:   accessMaxAgeSec,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     RefreshCookieName,
		Value:    refreshToken,
		Path:     "/", // we can scope to /auth/refresh later; broad for now to keep tests simple
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode, // stricter on refresh — never cross-site
		MaxAge:   refreshMaxAgeSec,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     CSRFCookieName,
		Value:    csrfToken,
		Path:     "/",
		HttpOnly: false, // JS must read to mirror into the header
		Secure:   secure,
		SameSite: sameSite,
		MaxAge:   accessMaxAgeSec,
	})
}

// ClearAuthCookies sends expired-cookie headers so the browser drops them.
// Used on logout.
func ClearAuthCookies(w http.ResponseWriter, isProduction bool) {
	secure := isProduction
	for _, name := range []string{AccessCookieName, RefreshCookieName, CSRFCookieName} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			HttpOnly: name != CSRFCookieName,
			Secure:   secure,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
		})
	}
}

// NewCSRFToken returns a fresh CSRF token suitable for the cookie. 256-bit
// random, base64url-encoded.
func NewCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// RequireCSRF middleware enforces the double-submit cookie check: the
// X-CSRF-Token header must equal the vendidit_csrf cookie. Apply this on
// state-changing routes that use cookie auth.
//
// Bypass when the request is using bearer-token auth (no auth cookie
// present) — bearer flows don't suffer from CSRF.
func RequireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only state-changing methods need CSRF protection. GET/HEAD/OPTIONS
		// shouldn't mutate.
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		// Bypass: bearer-token flow doesn't use cookies, so no CSRF risk.
		if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			next.ServeHTTP(w, r)
			return
		}
		// Bypass: no auth cookie present means the user isn't in cookie-mode.
		if _, err := r.Cookie(AccessCookieName); err != nil {
			next.ServeHTTP(w, r)
			return
		}

		cookie, err := r.Cookie(CSRFCookieName)
		if err != nil || cookie.Value == "" {
			writeError(w, errors.Forbidden("CSRF token missing"))
			return
		}
		header := r.Header.Get(CSRFHeaderName)
		if header == "" {
			writeError(w, errors.Forbidden("CSRF header missing"))
			return
		}
		// Constant-time comparison so token length / prefix don't leak.
		if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(header)) != 1 {
			writeError(w, errors.Forbidden("CSRF token mismatch"))
			return
		}
		next.ServeHTTP(w, r)
	})
}
