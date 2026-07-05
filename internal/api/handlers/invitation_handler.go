package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/rw3iss/auth/internal/api/middleware"
	"github.com/rw3iss/auth/internal/service"
	"github.com/rw3iss/auth/pkg/shared/errors"
	"github.com/rw3iss/auth/pkg/shared/types"
)

// InvitationHandler exposes the invitation surface that the
// OrganizationService already supports internally:
//
//   - Org-side: /orgs/{orgId}/invitations  → CRUD by org admins. Replaces
//     the awkward "add a member by user_id" path with the more natural
//     "invite by email" UX.
//
//   - Invitee-side: /me/invitations         → list/accept/decline for the
//     currently-authenticated user. Lets a signed-in user join additional
//     orgs without re-registering.
//
// Auth gating is done at the router layer (orgSelfChain for org paths,
// authMw.Authenticate for /me/*). The handler validates ownership of
// the invitation at service-layer (email match) to prevent enumeration.
type InvitationHandler struct {
	orgService  *service.OrganizationService
	userService *service.UserService
}

// NewInvitationHandler wires the handler with its collaborators.
func NewInvitationHandler(orgService *service.OrganizationService, userService *service.UserService) *InvitationHandler {
	return &InvitationHandler{orgService: orgService, userService: userService}
}

/* ──────────────────────────────────────────────────────────────────── */
/* Org-side                                                              */
/* ──────────────────────────────────────────────────────────────────── */

// CreateOrgInvitation handles POST /orgs/{orgId}/invitations.
// Body: { email, role_ids? }. On success the invitation row is created
// AND an invitation email is sent.
func (h *InvitationHandler) CreateOrgInvitation(w http.ResponseWriter, r *http.Request) {
	orgID, err := types.ParseID(r.PathValue("orgId"))
	if err != nil {
		writeError(w, errors.InvalidInput("orgId", "invalid org id"))
		return
	}
	callerID := middleware.GetUserID(r.Context())
	if callerID == nil {
		writeError(w, errors.Unauthorized("authentication required"))
		return
	}

	var req struct {
		Email   string     `json:"email"`
		RoleIDs []types.ID `json:"role_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.InvalidInput("body", "invalid request body"))
		return
	}

	invitation, err := h.orgService.CreateInvitation(r.Context(), orgID, *callerID, service.CreateInvitationInput{
		Email:   req.Email,
		RoleIDs: req.RoleIDs,
	})
	if err != nil {
		handleServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, invitation)
}

// ListOrgInvitations handles GET /orgs/{orgId}/invitations.
// Returns pending invitations for the org. Includes accepted/declined
// rows only when ?status=all is set (the default is pending-only —
// that's what an admin needs 95 % of the time).
func (h *InvitationHandler) ListOrgInvitations(w http.ResponseWriter, r *http.Request) {
	orgID, err := types.ParseID(r.PathValue("orgId"))
	if err != nil {
		writeError(w, errors.InvalidInput("orgId", "invalid org id"))
		return
	}
	result, err := h.orgService.ListInvitations(r.Context(), orgID, service.ListInvitationsInput{})
	if err != nil {
		handleServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"invitations": result.Invitations,
		"pagination":  result.Pagination,
	})
}

// RevokeOrgInvitation handles DELETE /orgs/{orgId}/invitations/{invitationId}.
// Marks the invitation as revoked. The {orgId} in the path is informational —
// the service-layer revoke is keyed on the invitation id alone — but
// keeping it in the URL preserves REST hierarchy and lets the router
// chain enforce org-self-service gating.
func (h *InvitationHandler) RevokeOrgInvitation(w http.ResponseWriter, r *http.Request) {
	invitationID, err := types.ParseID(r.PathValue("invitationId"))
	if err != nil {
		writeError(w, errors.InvalidInput("invitationId", "invalid invitation id"))
		return
	}
	if err := h.orgService.RevokeInvitation(r.Context(), invitationID); err != nil {
		handleServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

/* ──────────────────────────────────────────────────────────────────── */
/* Invitee-side (/me/invitations)                                        */
/* ──────────────────────────────────────────────────────────────────── */

// ListMyInvitations handles GET /me/invitations. Lists every pending
// invitation addressed to the authenticated user's email. Only pending
// rows are returned — accepted/declined/revoked rows belong on the
// admin org-side endpoints.
func (h *InvitationHandler) ListMyInvitations(w http.ResponseWriter, r *http.Request) {
	uid := middleware.GetUserID(r.Context())
	if uid == nil {
		writeError(w, errors.Unauthorized("authentication required"))
		return
	}
	user, err := h.userService.GetUser(r.Context(), *uid)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	invitations, err := h.orgService.GetPendingInvitations(r.Context(), string(user.Email))
	if err != nil {
		handleServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"invitations": invitations})
}

// AcceptMyInvitation handles POST /me/invitations/{invitationId}/accept.
// Verifies the invitation is addressed to the caller's email, then
// creates the org_member row + assigns roles. The caller's existing
// token-pair stays valid; switch to the newly-joined org via
// AuthClient.switchOrg(orgId) after a successful accept.
func (h *InvitationHandler) AcceptMyInvitation(w http.ResponseWriter, r *http.Request) {
	uid := middleware.GetUserID(r.Context())
	if uid == nil {
		writeError(w, errors.Unauthorized("authentication required"))
		return
	}
	invitationID, err := types.ParseID(r.PathValue("invitationId"))
	if err != nil {
		writeError(w, errors.InvalidInput("invitationId", "invalid invitation id"))
		return
	}
	user, err := h.userService.GetUser(r.Context(), *uid)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	org, err := h.orgService.AcceptInvitationByID(r.Context(), *uid, invitationID, user.Email)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"organization": org})
}

// DeclineMyInvitation handles POST /me/invitations/{invitationId}/decline.
// Idempotent in spirit — declining an already-declined invitation
// returns InviteAlreadyUsed (the service-layer guard).
func (h *InvitationHandler) DeclineMyInvitation(w http.ResponseWriter, r *http.Request) {
	uid := middleware.GetUserID(r.Context())
	if uid == nil {
		writeError(w, errors.Unauthorized("authentication required"))
		return
	}
	invitationID, err := types.ParseID(r.PathValue("invitationId"))
	if err != nil {
		writeError(w, errors.InvalidInput("invitationId", "invalid invitation id"))
		return
	}
	user, err := h.userService.GetUser(r.Context(), *uid)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	if err := h.orgService.DeclineInvitationByID(r.Context(), invitationID, user.Email); err != nil {
		handleServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
