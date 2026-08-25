package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequireWebIdentityRejectsAnOrdinaryRequest(t *testing.T) {
	mw := RequireWebIdentity(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	// No Sec-Fetch-Dest at all — a curl, a script, an <img>. Any of those reaching
	// /fedcm/accounts would be a credentialed read of someone's identity.
	r := httptest.NewRequest("GET", "/fedcm/accounts", nil)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}

func TestRequireWebIdentityRejectsAnotherDest(t *testing.T) {
	mw := RequireWebIdentity(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	for _, dest := range []string{"document", "empty", "image", "iframe", ""} {
		r := httptest.NewRequest("GET", "/fedcm/accounts", nil)
		if dest != "" {
			r.Header.Set("Sec-Fetch-Dest", dest)
		}
		w := httptest.NewRecorder()
		mw.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("Sec-Fetch-Dest=%q gave %d, want 403", dest, w.Code)
		}
	}
}

func TestRequireWebIdentityAcceptsTheBrowsersOwnRequest(t *testing.T) {
	called := false
	mw := RequireWebIdentity(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest("GET", "/fedcm/accounts", nil)
	r.Header.Set("Sec-Fetch-Dest", WebIdentityDest)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !called {
		t.Fatalf("status = %d, called = %v", w.Code, called)
	}
}

func TestIsFirstPartyRequest(t *testing.T) {
	allowed := []string{"https://www.civicgate.org"}
	cases := []struct {
		name          string
		secFetchSite  string
		origin        string
		allowedOrigin []string
		want          bool
		why           string
	}{
		// The legitimate CivicGate case: www.civicgate.org → auth.civicgate.org shares a
		// registrable domain, so the browser reports same-site.
		{"same-site", "same-site", "https://www.civicgate.org", allowed, true, "the product's own login"},
		{"same-origin", "same-origin", "https://auth.civicgate.org", allowed, true, "a page on the IdP itself"},
		{"direct navigation", "none", "", allowed, true, "typed URL or bookmark"},
		// The attack: any other page in the victim's browser posting the attacker's own
		// credentials so the victim ends up holding the attacker's session cookie.
		{"cross-site", "cross-site", "https://evil.example", allowed, false, "login CSRF"},
		{"cross-site even if origin is allow-listed", "cross-site", "https://www.civicgate.org", allowed, false,
			"Sec-Fetch-Site is unforgeable and wins over a spoofable Origin"},
		// Header absent — an older browser or a non-browser client.
		{"no header, allow-listed origin", "", "https://www.civicgate.org", allowed, true, "fallback match"},
		{"no header, other origin", "", "https://evil.example", allowed, false, "fallback rejects"},
		{"no header, no origin", "", "", allowed, true, "a non-browser caller has no ambient cookies to fixate"},
		// A wildcard must not silently disable the fallback.
		{"wildcard is not a match", "", "https://evil.example", []string{"*"}, false, "CORS_ORIGINS=* must fail closed here"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("POST", "/auth/login", nil)
		if c.secFetchSite != "" {
			r.Header.Set("Sec-Fetch-Site", c.secFetchSite)
		}
		if c.origin != "" {
			r.Header.Set("Origin", c.origin)
		}
		if got := IsFirstPartyRequest(r, c.allowedOrigin); got != c.want {
			t.Fatalf("%s: got %v, want %v (%s)", c.name, got, c.want, c.why)
		}
	}
}

func TestSetLoginStatus(t *testing.T) {
	w := httptest.NewRecorder()
	SetLoginStatus(w, true)
	if got := w.Header().Get(SetLoginHeader); got != "logged-in" {
		t.Fatalf("%s = %q", SetLoginHeader, got)
	}
	w = httptest.NewRecorder()
	SetLoginStatus(w, false)
	if got := w.Header().Get(SetLoginHeader); got != "logged-out" {
		t.Fatalf("%s = %q", SetLoginHeader, got)
	}
}

func cookieByName(t *testing.T, w *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("cookie %q was not set", name)
	return nil
}

func TestSetAuthCookiesDefaultsToLax(t *testing.T) {
	w := httptest.NewRecorder()
	SetAuthCookies(w, true, "a", "r", "c", 900, 604800)
	access := cookieByName(t, w, AccessCookieName)
	if access.SameSite != http.SameSiteLaxMode {
		t.Fatalf("SameSite = %v, want Lax by default", access.SameSite)
	}
	if !access.HttpOnly {
		t.Fatal("the access cookie must stay HttpOnly")
	}
}

func TestCrossSiteCookiesAreSameSiteNoneAndSecure(t *testing.T) {
	w := httptest.NewRecorder()
	// Production deliberately FALSE here: SameSite=None without Secure is rejected
	// outright by browsers, so CrossSite has to force Secure on regardless.
	SetAuthCookiesWith(w, CookieOptions{Production: false, CrossSite: true}, "a", "r", "c", 900, 604800)

	access := cookieByName(t, w, AccessCookieName)
	if access.SameSite != http.SameSiteNoneMode {
		t.Fatalf("access SameSite = %v, want None — FedCM's accounts call is cross-site", access.SameSite)
	}
	if !access.Secure {
		t.Fatal("SameSite=None without Secure is silently dropped by the browser")
	}
	// The refresh token is never needed cross-site and is the credential that
	// outlives the access token, so it stays Strict.
	refresh := cookieByName(t, w, RefreshCookieName)
	if refresh.SameSite != http.SameSiteStrictMode {
		t.Fatalf("refresh SameSite = %v, want Strict even in cross-site mode", refresh.SameSite)
	}
	csrf := cookieByName(t, w, CSRFCookieName)
	if csrf.HttpOnly {
		t.Fatal("the CSRF cookie must remain readable by JS to be mirrored into the header")
	}
}

func TestClearAuthCookiesMatchesHowTheyWereSet(t *testing.T) {
	// Attributes must match or the browser treats the expiry as a different cookie
	// and keeps the live one — a logout that reports success and does nothing.
	w := httptest.NewRecorder()
	opts := CookieOptions{CrossSite: true, Domain: ".example.org"}
	ClearAuthCookiesWith(w, opts)
	for _, name := range []string{AccessCookieName, RefreshCookieName, CSRFCookieName} {
		c := cookieByName(t, w, name)
		if c.MaxAge >= 0 {
			t.Fatalf("%s MaxAge = %d, want negative", name, c.MaxAge)
		}
		// Go's cookie parser drops the legacy leading dot on read (RFC 6265), so the
		// round-tripped value is the bare domain.
		if c.Domain != "example.org" {
			t.Fatalf("%s Domain = %q", name, c.Domain)
		}
		if !c.Secure {
			t.Fatalf("%s must be Secure to match how it was written", name)
		}
	}
	if got := cookieByName(t, w, RefreshCookieName).SameSite; got != http.SameSiteStrictMode {
		t.Fatalf("refresh clear SameSite = %v, want Strict to match", got)
	}
}
