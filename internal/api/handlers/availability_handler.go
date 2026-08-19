package handlers

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/rw3iss/auth/internal/api/middleware"
	auth "github.com/rw3iss/auth/internal/service/auth"
	"github.com/rw3iss/auth/pkg/shared/errors"
)

// AvailabilityHandler answers "is this email free to register?" for a SIGNUP FORM.
//
// WHY THIS IS SEPARATE FROM CheckEmail. `POST /auth/check-email` is an admin/service route: it requires a
// system_admin token and answers "does this account exist" for back-office use. A signup form has no
// session at all, so it cannot use that — which is why the registration form previously had no way to tell
// someone their address was taken until they submitted.
//
// THIS IS AN ENUMERATION SURFACE, and it is treated as one:
//   - Per-IP rate limit, tighter than the global middleware limit, because bulk is the only dangerous use.
//   - The response is a BARE BOOLEAN. Never "verified", never "which app", never a distinguishable error.
//   - OVER THE LIMIT WE ANSWER "available", not an error. Registration itself is the real gate and rejects
//     duplicates, so a throttled attacker learns nothing; a fast legitimate typist just loses the hint.
//   - The lookup is one indexed query in both branches, so the timing does not disclose the answer either.
type AvailabilityHandler struct {
	authService *auth.AuthService
	limiter     *ipLimiter
}

func NewAvailabilityHandler(authService *auth.AuthService) *AvailabilityHandler {
	return &AvailabilityHandler{
		authService: authService,
		// 20 checks/minute/IP: far above a person filling in one form, far below a useful harvest rate.
		limiter: newIPLimiter(20, time.Minute),
	}
}

type availabilityRequest struct {
	Email   string `json:"email"`
	AppCode string `json:"app_code,omitempty"`
}

type availabilityResponse struct {
	Available bool `json:"available"`
}

// CheckAvailability handles POST /auth/availability (public).
func (h *AvailabilityHandler) CheckAvailability(w http.ResponseWriter, r *http.Request) {
	var req availabilityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.InvalidInput("body", "Invalid request body"))
		return
	}

	// Throttled → answer "available" rather than erroring. See the type comment.
	if !h.limiter.allow(middleware.RealIP(r)) {
		writeJSON(w, http.StatusOK, availabilityResponse{Available: true})
		return
	}

	appCode := req.AppCode
	if appCode == "" {
		appCode = r.Header.Get("X-App-Code")
	}

	exists, err := h.authService.CheckEmail(r.Context(), req.Email, appCode)
	if err != nil {
		// A malformed address is the caller's own client-side validation problem, and a backend failure
		// must not be distinguishable from "taken". Both answer "available" and let registration decide.
		writeJSON(w, http.StatusOK, availabilityResponse{Available: true})
		return
	}
	writeJSON(w, http.StatusOK, availabilityResponse{Available: !exists})
}

// ── A small per-IP sliding window ─────────────────────────────────────────────────────────────────────
// Deliberately in-process: the cost of an over-limit request here is one missing inline hint, so
// cross-instance precision buys nothing and a restart clearing the window is harmless. Anything
// protecting data integrity would need the shared Redis limiter instead.
type ipLimiter struct {
	mu     sync.Mutex
	hits   map[string][]time.Time
	max    int
	window time.Duration
}

const maxTrackedIPs = 5000

func newIPLimiter(max int, window time.Duration) *ipLimiter {
	return &ipLimiter{hits: make(map[string][]time.Time), max: max, window: window}
}

func (l *ipLimiter) allow(key string) bool {
	if key == "" {
		key = "unknown"
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	recent := l.hits[key][:0:0]
	for _, t := range l.hits[key] {
		if now.Sub(t) < l.window {
			recent = append(recent, t)
		}
	}
	if len(recent) >= l.max {
		l.hits[key] = recent
		return false
	}
	l.hits[key] = append(recent, now)

	// Stop a stream of distinct IPs growing the map without bound.
	if len(l.hits) > maxTrackedIPs {
		for k, v := range l.hits {
			stale := true
			for _, t := range v {
				if now.Sub(t) < l.window {
					stale = false
					break
				}
			}
			if stale {
				delete(l.hits, k)
			}
			if len(l.hits) <= maxTrackedIPs/2 {
				break
			}
		}
	}
	return true
}
