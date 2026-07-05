package handlers

import (
	"encoding/json"
	"net/http"

	auth "github.com/ven/auth/internal/service/auth"
	"github.com/ven/auth/pkg/shared/errors"
)

// MagicLinkHandler exposes the magic-link sign-in endpoints. Public —
// no auth required for either; the request endpoint validates the
// email, the verify endpoint validates the token.
type MagicLinkHandler struct {
	svc *auth.MagicLinkService
}

// NewMagicLinkHandler wires the handler with the service.
func NewMagicLinkHandler(svc *auth.MagicLinkService) *MagicLinkHandler {
	return &MagicLinkHandler{svc: svc}
}

type magicLinkRequestRequest struct {
	Email   string `json:"email"`
	AppCode string `json:"app_code,omitempty"`
}

// Request handles POST /auth/magic-link/request. Always 204 No Content
// on success — never reveals whether the email is registered. A real
// row was created and an email dispatched only when the email maps to
// an existing user; otherwise the call is silently no-op'd at the
// service layer.
func (h *MagicLinkHandler) Request(w http.ResponseWriter, r *http.Request) {
	var req magicLinkRequestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.InvalidInput("body", "invalid request body"))
		return
	}
	if err := h.svc.Request(r.Context(), auth.MagicLinkRequestInput{
		Email:     req.Email,
		AppCode:   req.AppCode,
		IPAddress: clientIP(r),
		UserAgent: r.UserAgent(),
	}); err != nil {
		handleServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type magicLinkVerifyRequest struct {
	Token string `json:"token"`
}

// Verify handles POST /auth/magic-link/verify. Exchange a magic-link
// token for a full token-pair (same shape as /auth/login).
func (h *MagicLinkHandler) Verify(w http.ResponseWriter, r *http.Request) {
	var req magicLinkVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.InvalidInput("body", "invalid request body"))
		return
	}
	result, err := h.svc.Verify(r.Context(), req.Token, clientIP(r), r.UserAgent())
	if err != nil {
		handleServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user":   result.User,
		"tokens": result.TokenPair,
	})
}

// clientIP returns the best-available client IP. Prefers
// X-Forwarded-For when the request is from a trusted proxy (the auth
// middleware already strips spoofed XFF — this helper is just a
// convenience for the handlers).
func clientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first hop only.
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}
	return r.RemoteAddr
}
