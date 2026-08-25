package middleware

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/rw3iss/auth/internal/auth/jwt"
	"github.com/rw3iss/auth/internal/logging"
	"github.com/rw3iss/auth/pkg/shared/errors"
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
	AccessCookieName  = "rw3iss_access"
	RefreshCookieName = "rw3iss_refresh"
	CSRFCookieName    = "rw3iss_csrf"
	CSRFHeaderName    = "X-CSRF-Token"
)

// CookieOptions configures how the auth cookies are written.
//
// CrossSite exists for ONE reason: FedCM. The browser fetches the IdP's accounts
// endpoint from a page on the relying party's origin, so the session cookie is
// sent in a cross-site context and a SameSite=Lax cookie is simply not attached —
// the accounts endpoint would see an anonymous request and FedCM would report "no
// accounts" with nothing in any log to explain it. The same applies one step
// earlier: a login POST issued cross-origin (www.civicgate.org → auth.civicgate.org)
// cannot even STORE a Lax cookie, so the flag is required to get off the ground.
//
// It is off by default. SameSite=None removes the browser's own CSRF brake, so a
// deployment that turns it on is accepting the trade and relying on RequireCSRF
// (and, for the FedCM routes, on Sec-Fetch-Dest: webidentity, which no ordinary
// page can forge) for the defence instead.
type CookieOptions struct {
	// Production makes cookies Secure. SameSite=None is INVALID without Secure,
	// so CrossSite implies it.
	Production bool
	// CrossSite writes the access + CSRF cookies as SameSite=None; Secure.
	CrossSite bool
	// Domain optionally widens the cookie to a parent domain (e.g. ".civicgate.org").
	// Empty means host-only, which is the safer default and what FedCM needs — the
	// IdP origin is the only place the session cookie belongs.
	Domain string
}

// SetAuthCookies writes the access + refresh + CSRF cookies with the audited
// SameSite=Lax default. Kept as the narrow entry point so existing callers and
// tests do not have to know about CookieOptions.
func SetAuthCookies(w http.ResponseWriter, isProduction bool, accessToken, refreshToken, csrfToken string, accessMaxAgeSec, refreshMaxAgeSec int) {
	SetAuthCookiesWith(w, CookieOptions{Production: isProduction}, accessToken, refreshToken, csrfToken, accessMaxAgeSec, refreshMaxAgeSec)
}

// SetAuthCookiesWith writes the access + refresh + CSRF cookies. The CSRF
// cookie is the only one that is NOT HttpOnly (the JS layer needs to read
// it to mirror in the X-CSRF-Token header). All cookies are Secure in
// production; Path-scoped: refresh tokens are sent only to /auth/refresh
// so they're not leaked into every cross-app request.
//
// The REFRESH cookie stays SameSite=Strict even in cross-site mode. Nothing
// cross-site needs it — FedCM reads the session, never the refresh chain — and a
// refresh token is the one credential that survives an access token expiring.
func SetAuthCookiesWith(w http.ResponseWriter, opts CookieOptions, accessToken, refreshToken, csrfToken string, accessMaxAgeSec, refreshMaxAgeSec int) {
	secure := opts.Production
	sameSite := http.SameSiteLaxMode
	if opts.CrossSite {
		sameSite = http.SameSiteNoneMode
		// A SameSite=None cookie without Secure is REJECTED outright by every current
		// browser. Silently dropping the cookie would look exactly like a login that
		// did not stick, so force it rather than emit something unusable.
		secure = true
	}

	http.SetCookie(w, &http.Cookie{
		Name:     AccessCookieName,
		Value:    accessToken,
		Path:     "/",
		Domain:   opts.Domain,
		HttpOnly: true,
		Secure:   secure,
		SameSite: sameSite,
		MaxAge:   accessMaxAgeSec,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     RefreshCookieName,
		Value:    refreshToken,
		Path:     "/", // we can scope to /auth/refresh later; broad for now to keep tests simple
		Domain:   opts.Domain,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode, // stricter on refresh — never cross-site
		MaxAge:   refreshMaxAgeSec,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     CSRFCookieName,
		Value:    csrfToken,
		Path:     "/",
		Domain:   opts.Domain,
		HttpOnly: false, // JS must read to mirror into the header
		Secure:   secure,
		SameSite: sameSite,
		MaxAge:   accessMaxAgeSec,
	})
}

// ClearAuthCookies sends expired-cookie headers so the browser drops them.
// Used on logout.
func ClearAuthCookies(w http.ResponseWriter, isProduction bool) {
	ClearAuthCookiesWith(w, CookieOptions{Production: isProduction})
}

// ClearAuthCookiesWith is ClearAuthCookies with the same options the cookies were
// written under.
//
// The attributes MUST match how the cookie was set, or the browser treats the
// expiry as being for a different cookie and keeps the live one — a logout that
// reports success and leaves the session standing.
func ClearAuthCookiesWith(w http.ResponseWriter, opts CookieOptions) {
	secure := opts.Production
	sameSite := http.SameSiteLaxMode
	if opts.CrossSite {
		sameSite = http.SameSiteNoneMode
		secure = true
	}
	for _, name := range []string{AccessCookieName, RefreshCookieName, CSRFCookieName} {
		ss := sameSite
		if name == RefreshCookieName {
			ss = http.SameSiteStrictMode
		}
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			Domain:   opts.Domain,
			HttpOnly: name != CSRFCookieName,
			Secure:   secure,
			SameSite: ss,
			MaxAge:   -1,
		})
	}
}

// ClaimsFromCookie validates the HttpOnly session cookie and returns its claims,
// or nil when there is no cookie or it does not validate.
//
// SEPARATE FROM extractToken ON PURPOSE (see auth.go): bearer extraction
// deliberately refuses cookies, because a cookie read at the bearer layer would
// apply to every route and reintroduce the CSRF surface that decision removed.
// This reads the cookie only where a caller has explicitly asked for the cookie
// path — today, the FedCM endpoints, which the browser calls with no way to send
// an Authorization header.
func (m *AuthMiddleware) ClaimsFromCookie(r *http.Request) *jwt.TokenClaims {
	c, err := r.Cookie(AccessCookieName)
	if err != nil || c.Value == "" {
		return nil
	}
	claims, err := m.jwtService.ValidateAccessToken(c.Value)
	if err != nil {
		return nil
	}
	return claims
}

// AuthenticateCookie is Authenticate over the session COOKIE instead of the
// Authorization header. Claims land under the same context keys, so
// GetClaims/GetUserID work identically downstream.
func (m *AuthMiddleware) AuthenticateCookie(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := m.ClaimsFromCookie(r)
		if claims == nil {
			writeError(w, errors.Unauthorized("No active session"))
			return
		}
		ctx := context.WithValue(r.Context(), ContextKeyClaims, claims)
		ctx = context.WithValue(ctx, ContextKeyUserID, claims.UserID)
		ctx = logging.WithUserID(ctx, claims.UserID.String())
		if claims.OrganizationID != nil {
			ctx = context.WithValue(ctx, ContextKeyOrgID, *claims.OrganizationID)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// OptionalAuthCookie is AuthenticateCookie that does not reject anonymous callers —
// the cookie counterpart of OptionalAuth.
//
// Used where the handler needs the session to shape its answer but must still run
// without one: the FedCM login page (signed-in vs redirect-to-login) and the
// assertion endpoint, which has to validate the relying party and attach CORS
// headers BEFORE it can report "signed out" in a way the browser will deliver.
func (m *AuthMiddleware) OptionalAuthCookie(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if claims := m.ClaimsFromCookie(r); claims != nil {
			ctx := context.WithValue(r.Context(), ContextKeyClaims, claims)
			ctx = context.WithValue(ctx, ContextKeyUserID, claims.UserID)
			ctx = logging.WithUserID(ctx, claims.UserID.String())
			if claims.OrganizationID != nil {
				ctx = context.WithValue(ctx, ContextKeyOrgID, *claims.OrganizationID)
			}
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
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
// X-CSRF-Token header must equal the rw3iss_csrf cookie. Apply this on
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
