package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/ven/auth/internal/service"
	"github.com/ven/auth/pkg/shared/errors"
	"github.com/ven/auth/pkg/shared/types"
)

// AuditHandler exposes the audit-log read endpoint. Gated to admins
// at the router layer.
type AuditHandler struct {
	svc *service.AuditQueryService
}

// NewAuditHandler wires the handler with its service.
func NewAuditHandler(svc *service.AuditQueryService) *AuditHandler {
	return &AuditHandler{svc: svc}
}

// auditEntryWire wraps AuditEntry with an inline-decoded `details`
// field — sqlx scans details into sql.NullString (it's TEXT/JSONB), but
// the JSON API surface should be an object. We re-encode at serialize
// time so clients don't have to second-pass-parse it themselves.
type auditEntryWire struct {
	*service.AuditEntry
	Details map[string]any `json:"details,omitempty"`
}

// List handles GET /admin/audit-log. Supports filters as query params:
//
//	?action=login.success | login.* (glob prefix)
//	?user_id=<uuid>
//	?organization_id=<uuid>
//	?since=2026-05-01T00:00:00Z       (RFC3339)
//	?until=2026-05-15T00:00:00Z
//	?page=1
//	?page_size=50    (max 200)
func (h *AuditHandler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	in := service.AuditListInput{
		Action:   q.Get("action"),
		Page:     atoi(q.Get("page"), 1),
		PageSize: atoi(q.Get("page_size"), 50),
	}
	if v := q.Get("user_id"); v != "" {
		id, err := types.ParseID(v)
		if err != nil {
			writeError(w, errors.InvalidInput("user_id", "invalid uuid"))
			return
		}
		in.UserID = &id
	}
	if v := q.Get("organization_id"); v != "" {
		id, err := types.ParseID(v)
		if err != nil {
			writeError(w, errors.InvalidInput("organization_id", "invalid uuid"))
			return
		}
		in.OrganizationID = &id
	}
	if v := q.Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeError(w, errors.InvalidInput("since", "RFC3339 timestamp required"))
			return
		}
		in.Since = &t
	}
	if v := q.Get("until"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeError(w, errors.InvalidInput("until", "RFC3339 timestamp required"))
			return
		}
		in.Until = &t
	}

	result, err := h.svc.List(r.Context(), in)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	// Decode details JSON for each entry. JSONB column can be NULL or a
	// JSON object — handle both cleanly so a malformed row doesn't fail
	// the whole page.
	wire := make([]auditEntryWire, len(result.Entries))
	for i, e := range result.Entries {
		w := auditEntryWire{AuditEntry: e}
		if e.Details.Valid && e.Details.String != "" {
			_ = json.Unmarshal([]byte(e.Details.String), &w.Details)
		}
		wire[i] = w
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"entries":   wire,
		"page":      result.Page,
		"page_size": result.PageSize,
		"total":     result.Total,
	})
}

func atoi(s string, fallback int) int {
	if s == "" {
		return fallback
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return fallback
	}
	return n
}
