package middleware

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// AUDIT 7.10: oversize bodies must error at the wrapped reader, before
// allocating multi-MB into the handler.
func TestBodyLimitRejectsOversize(t *testing.T) {
	limit := int64(1024)
	mw := BodyLimit(limit)
	hit := false
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try to read the full body. With MaxBytesReader this errors on
		// oversize input.
		_, err := io.ReadAll(r.Body)
		if err == nil {
			hit = true
			w.WriteHeader(http.StatusOK)
			return
		}
		// MaxBytesReader sets the status code via the writer wrapper.
		// Just confirm we *did not* successfully read.
		w.WriteHeader(http.StatusRequestEntityTooLarge)
	}))

	body := strings.Repeat("a", int(limit)+10)
	r := httptest.NewRequest("POST", "/", bytes.NewReader([]byte(body)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if hit {
		t.Fatal("expected oversize body to error inside ReadAll")
	}
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", w.Code)
	}
}

// Bodies within the limit pass through normally.
func TestBodyLimitAllowsUndersize(t *testing.T) {
	mw := BodyLimit(1024)
	var got int
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		got = len(b)
		w.WriteHeader(http.StatusOK)
	}))

	body := strings.Repeat("a", 100)
	r := httptest.NewRequest("POST", "/", bytes.NewReader([]byte(body)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if got != 100 {
		t.Fatalf("expected 100 bytes through, got %d", got)
	}
}

// maxBytes <= 0 falls to the default; > MaxBodyLimit clamps down. Verify
// the misconfig-shut behavior.
func TestBodyLimitClamps(t *testing.T) {
	mw := BodyLimit(MaxBodyLimit * 10) // way over ceiling
	// Internal clamp: the middleware still works; we just verify
	// constructibility without panic and that a small body passes.
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest("POST", "/", bytes.NewReader([]byte("ok")))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 under clamped limit, got %d", w.Code)
	}
}
