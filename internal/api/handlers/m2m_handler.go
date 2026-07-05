package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/ven/auth/internal/api/middleware"
	"github.com/ven/auth/internal/service"
	"github.com/ven/auth/pkg/shared/errors"
	"github.com/ven/auth/pkg/shared/types"
)

// M2MHandler exposes the M2M client admin surface (/admin/m2m-clients/*).
// Gated to system_admin at the router layer — these credentials authorize
// platform-internal services and live below the line of every other
// admin tier. Only the platform owner should be minting them.
//
// The plaintext client_secret is returned ONLY in the Create response.
// All subsequent reads omit the secret (the domain model marks the hash
// field as json:"-"). Lose the secret → rotate the client.
type M2MHandler struct {
	m2m *service.M2MService
}

// NewM2MHandler wires the handler with the M2MService.
func NewM2MHandler(m2m *service.M2MService) *M2MHandler {
	return &M2MHandler{m2m: m2m}
}

// createClientRequest is the body for POST /admin/m2m-clients.
type createClientRequest struct {
	ClientID         string   `json:"client_id"`
	Name             string   `json:"name"`
	Description      string   `json:"description"`
	Scopes           []string `json:"scopes"`
	AllowedAudiences []string `json:"allowed_audiences"`
}

// createClientResponse mirrors service.CreateClientResult but inlines the
// plaintext secret at the top level for ergonomics (callers don't need to
// reach into a nested object). Field names are snake_case to match the
// rest of the API surface.
type createClientResponse struct {
	Client       any    `json:"client"`
	ClientSecret string `json:"client_secret"`
}

// Create handles POST /admin/m2m-clients. Returns 201 with the plaintext
// secret. The secret is never reissued — operator must rotate to recover.
func (h *M2MHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req createClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.InvalidInput("body", "invalid request body"))
		return
	}
	createdBy := middleware.GetUserID(r.Context())
	result, err := h.m2m.CreateClient(r.Context(), service.CreateClientInput{
		ClientID:         req.ClientID,
		Name:             req.Name,
		Description:      req.Description,
		Scopes:           req.Scopes,
		AllowedAudiences: req.AllowedAudiences,
		CreatedBy:        createdBy,
	})
	if err != nil {
		handleServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, createClientResponse{
		Client:       result.Client,
		ClientSecret: result.ClientSecret,
	})
}

// List handles GET /admin/m2m-clients. Returns every non-revoked client.
// No pagination — M2M inventories are intentionally small.
func (h *M2MHandler) List(w http.ResponseWriter, r *http.Request) {
	clients, err := h.m2m.List(r.Context())
	if err != nil {
		handleServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"clients": clients})
}

// Get handles GET /admin/m2m-clients/{clientId} (UUID, not the
// operator-chosen client_id string).
func (h *M2MHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := types.ParseID(r.PathValue("clientId"))
	if err != nil {
		writeError(w, errors.InvalidInput("clientId", "invalid client ID"))
		return
	}
	c, err := h.m2m.GetByID(r.Context(), id)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

// Revoke handles DELETE /admin/m2m-clients/{clientId}. Soft-revoke —
// idempotent. Outstanding tokens still validate until their natural
// expiry (≤ AccessTokenExpiry, ~15m); future grants fail immediately.
func (h *M2MHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	id, err := types.ParseID(r.PathValue("clientId"))
	if err != nil {
		writeError(w, errors.InvalidInput("clientId", "invalid client ID"))
		return
	}
	if err := h.m2m.Revoke(r.Context(), id); err != nil {
		handleServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
