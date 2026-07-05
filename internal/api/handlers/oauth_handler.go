// Package handlers contains the HTTP handlers for the auth server's REST
// surface.
package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/rw3iss/auth/internal/service"
	"github.com/rw3iss/auth/pkg/shared/errors"
)

// OAuthHandler hosts OAuth2-style token endpoints — currently only the
// client_credentials grant for machine-to-machine consumers. RFC 6749 §4.4.
//
// The endpoint is public (no Authorization header expected); authentication
// is performed via `client_id` + `client_secret` in the request body.
// Failures map to the same NotFound error envelope as missing clients so
// the response never distinguishes "wrong secret" from "unknown client"
// (prevents enumeration via timing or message-shape inspection).
type OAuthHandler struct {
	m2m *service.M2MService
}

// NewOAuthHandler wires the handler with the M2MService.
func NewOAuthHandler(m2m *service.M2MService) *OAuthHandler {
	return &OAuthHandler{m2m: m2m}
}

// tokenRequest mirrors RFC 6749 §4.4.2 with one practical extension:
// we accept both JSON bodies (rw3iss-internal callers — they're all
// JSON-first) and `application/x-www-form-urlencoded` bodies (per the RFC).
// The dispatch happens in Token() based on Content-Type.
type tokenRequest struct {
	GrantType    string `json:"grant_type" form:"grant_type"`
	ClientID     string `json:"client_id" form:"client_id"`
	ClientSecret string `json:"client_secret" form:"client_secret"`
	// Scope is space-separated per RFC 6749 §3.3. Empty/omitted means
	// "grant the client's full configured scopes".
	Scope string `json:"scope" form:"scope"`
}

// Token handles POST /oauth/token. The only supported grant is
// `client_credentials`; every other grant type returns
// `unsupported_grant_type` as specified by RFC 6749 §5.2.
//
// Body parsing:
//   - application/x-www-form-urlencoded — standard OAuth client behavior.
//   - application/json (or any Content-Type with `+json`) — rw3iss-
//     internal callers; convenient for SDKs that already speak JSON.
//
// Success response shape (RFC 6749 §5.1):
//
//	{
//	  "access_token": "...",
//	  "token_type": "Bearer",
//	  "expires_in": 900,
//	  "expires_at": 1736870400,
//	  "scope": "read:foo write:bar"
//	}
//
// Failure response shape (RFC 6749 §5.2 superset — we add the standard
// `error` / `error_description` fields on top of the project's envelope
// so OAuth-aware clients can branch on the error code):
//
//	{ "error": "invalid_client", "error_description": "..." }
func (h *OAuthHandler) Token(w http.ResponseWriter, r *http.Request) {
	req, err := parseTokenRequest(r)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	if req.GrantType != "client_credentials" {
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type",
			"only client_credentials is supported")
		return
	}

	var scopes []string
	if s := strings.TrimSpace(req.Scope); s != "" {
		scopes = strings.Fields(s)
	}

	tok, err := h.m2m.IssueToken(r.Context(), service.IssueTokenInput{
		ClientID:     req.ClientID,
		ClientSecret: req.ClientSecret,
		Scopes:       scopes,
	})
	if err != nil {
		// Map the project's error envelope to the OAuth `error` field
		// so OAuth-aware clients (and the auth-server-client SDK) can
		// branch on it. All credential-shaped failures collapse to
		// `invalid_client` per RFC 6749 §5.2 to avoid enumeration.
		appErr, ok := err.(*errors.AppError)
		switch {
		case ok && appErr.Code == errors.ErrCodeInvalidInput:
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", appErr.Message)
		case ok && appErr.Code == errors.ErrCodeNotFound:
			writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "invalid client credentials")
		default:
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "token issuance failed")
		}
		return
	}

	writeJSON(w, http.StatusOK, tok)
}

// parseTokenRequest reads the body in either JSON or form-encoded form,
// based on Content-Type. Form takes precedence when both are theoretically
// possible — the RFC mandates form, JSON is our extension.
func parseTokenRequest(r *http.Request) (*tokenRequest, error) {
	ct := r.Header.Get("Content-Type")
	// Strip parameters like "; charset=utf-8".
	if i := strings.Index(ct, ";"); i >= 0 {
		ct = ct[:i]
	}
	ct = strings.TrimSpace(strings.ToLower(ct))

	req := &tokenRequest{}
	switch {
	case ct == "application/x-www-form-urlencoded":
		if err := r.ParseForm(); err != nil {
			return nil, err
		}
		req.GrantType = r.PostFormValue("grant_type")
		req.ClientID = r.PostFormValue("client_id")
		req.ClientSecret = r.PostFormValue("client_secret")
		req.Scope = r.PostFormValue("scope")
	case ct == "application/json" || strings.HasSuffix(ct, "+json") || ct == "":
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			return nil, err
		}
	default:
		return nil, errors.InvalidInput("Content-Type",
			"Content-Type must be application/json or application/x-www-form-urlencoded")
	}
	return req, nil
}

// writeOAuthError emits an RFC 6749 §5.2 error envelope. We don't merge
// this with writeError because OAuth clients have hard expectations about
// the `error` / `error_description` field names — the project's standard
// envelope uses `code` / `message`.
func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	// Cache-Control: no-store per RFC 6749 §5.2 — token responses must
	// never be cached.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
}
