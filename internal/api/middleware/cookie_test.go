package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequireCSRFBypassForGET(t *testing.T) {
	mw := RequireCSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("GET should bypass CSRF, got %d", w.Code)
	}
}

func TestRequireCSRFBypassForBearerAuth(t *testing.T) {
	mw := RequireCSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest("POST", "/", nil)
	r.Header.Set("Authorization", "Bearer abc")
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("bearer-token POST should bypass CSRF, got %d", w.Code)
	}
}

func TestRequireCSRFBypassWhenNoAuthCookie(t *testing.T) {
	mw := RequireCSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest("POST", "/", nil)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("POST without auth cookie should bypass CSRF, got %d", w.Code)
	}
}

func TestRequireCSRFMatchingTokenAccepted(t *testing.T) {
	mw := RequireCSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest("POST", "/", nil)
	r.AddCookie(&http.Cookie{Name: AccessCookieName, Value: "x"})
	r.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "csrf-abc"})
	r.Header.Set(CSRFHeaderName, "csrf-abc")
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("matching CSRF should pass, got %d", w.Code)
	}
}

func TestRequireCSRFMismatchRejected(t *testing.T) {
	mw := RequireCSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest("POST", "/", nil)
	r.AddCookie(&http.Cookie{Name: AccessCookieName, Value: "x"})
	r.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "csrf-abc"})
	r.Header.Set(CSRFHeaderName, "csrf-DIFFERENT")
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, r)
	if w.Code == http.StatusOK {
		t.Fatal("CSRF mismatch should be rejected")
	}
}

func TestNewCSRFTokenLength(t *testing.T) {
	for i := 0; i < 5; i++ {
		tok, err := NewCSRFToken()
		if err != nil {
			t.Fatalf("NewCSRFToken: %v", err)
		}
		if len(tok) < 32 {
			t.Fatalf("token too short: %s", tok)
		}
	}
}
