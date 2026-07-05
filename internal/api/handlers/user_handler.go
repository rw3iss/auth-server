package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/rw3iss/auth/internal/api/dto"
	"github.com/rw3iss/auth/internal/api/middleware"
	"github.com/rw3iss/auth/internal/domain"
	"github.com/rw3iss/auth/internal/service"
	auth "github.com/rw3iss/auth/internal/service/auth"
	"github.com/rw3iss/auth/pkg/shared/errors"
	"github.com/rw3iss/auth/pkg/shared/types"
)

// UserHandler handles user management endpoints
type UserHandler struct {
	userService *service.UserService
	roleService *service.RoleService
	authService *auth.AuthService
}

// NewUserHandler creates a new user handler
func NewUserHandler(userService *service.UserService, roleService *service.RoleService, authService *auth.AuthService) *UserHandler {
	return &UserHandler{
		userService: userService,
		roleService: roleService,
		authService: authService,
	}
}

// userListResponse converts a slice of domain users to UserResponse +
// attaches base-role summaries fetched in a single bulk query. Used
// by both the structured list and search paths on /admin/users.
//
// On a roles-fetch error we still return the user rows (with nil
// `roles` fields) instead of failing the whole list — the page is
// usable without the column, and degrading-with-data beats degrading-
// to-empty for a back-office surface.
func (h *UserHandler) userListResponse(ctx context.Context, users []*domain.User) ([]*dto.UserResponse, error) {
	resp := make([]*dto.UserResponse, len(users))
	ids := make([]types.ID, len(users))
	for i, u := range users {
		resp[i] = dto.ToUserResponse(u)
		ids[i] = u.ID
	}
	if len(ids) == 0 {
		return resp, nil
	}
	rolesByUser, err := h.userService.GetUserBaseRolesBulk(ctx, ids)
	if err != nil {
		// Return rows without roles rather than fail the whole list.
		return resp, nil
	}
	for i, u := range users {
		roles := rolesByUser[u.ID]
		// Always emit a non-nil slice when we successfully queried —
		// nil means "not populated"; [] means "no roles". The
		// front-end uses the distinction.
		summaries := make([]dto.UserRoleSummary, 0, len(roles))
		for _, role := range roles {
			summaries = append(summaries, dto.UserRoleSummary{
				Code: role.Code,
				Name: role.Name,
			})
		}
		resp[i].Roles = summaries
	}
	return resp, nil
}

// requireSystemAdmin checks if the caller is a system_admin, writing an error if not
func requireSystemAdmin(w http.ResponseWriter, r *http.Request) bool {
	claims := middleware.GetClaims(r.Context())
	if claims == nil || !claims.HasRole("system_admin") {
		writeError(w, errors.Forbidden("Super admin access required"))
		return false
	}
	return true
}

// ListUsers returns a paginated, filterable list of users.
// GET /admin/users?search=&status=&sort_by=&sort_order=&page=&page_size=
func (h *UserHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	if !requireSystemAdmin(w, r) {
		return
	}

	q := r.URL.Query()

	// If search param is provided, delegate to SearchUsers for full-text search
	if search := q.Get("search"); search != "" {
		page, _ := strconv.Atoi(q.Get("page"))
		pageSize, _ := strconv.Atoi(q.Get("page_size"))
		if page <= 0 {
			page = 1
		}
		if pageSize <= 0 {
			pageSize = 25
		}
		result, err := h.userService.SearchUsers(r.Context(), search, page, pageSize)
		if err != nil {
			handleServiceError(w, err)
			return
		}
		enriched, err := h.userListResponse(r.Context(), result.Users)
		if err != nil {
			handleServiceError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"users": enriched,
			"total": result.Pagination.Total,
		})
		return
	}

	// Structured filter
	input := service.ListUsersInput{
		SortBy:   q.Get("sort_by"),
		Page:     1,
		PageSize: 25,
	}

	if v := q.Get("sort_order"); v != "" {
		input.SortOrder = types.SortOrder(v)
	}
	if v := q.Get("status"); v != "" {
		s := types.UserStatus(v)
		input.Status = &s
	}
	// Filter to members of a specific organization. The service layer
	// already supports this via `OrganizationID` on the filter struct;
	// the handler just needs to forward the query param.
	if v := q.Get("organization_id"); v != "" {
		orgID, err := types.ParseID(v)
		if err != nil {
			writeError(w, errors.ValidationError("Invalid organization ID"))
			return
		}
		input.OrganizationID = &orgID
	}

	// Filter to active members of a specific app (user_apps). Parsed
	// here since 2026-06-10 — previously the SDK sent ?app_id= but the
	// server never read it.
	if v := q.Get("app_id"); v != "" {
		appID, err := types.ParseID(v)
		if err != nil {
			writeError(w, errors.ValidationError("Invalid app ID"))
			return
		}
		input.AppID = &appID
	}
	if v, err := strconv.Atoi(q.Get("page")); err == nil && v > 0 {
		input.Page = v
	}
	if v, err := strconv.Atoi(q.Get("page_size")); err == nil && v > 0 {
		input.PageSize = v
	}
	// Support offset-based pagination from the API server
	if offset, err := strconv.Atoi(q.Get("offset")); err == nil && offset > 0 {
		input.Page = (offset / input.PageSize) + 1
	}
	if v, err := strconv.Atoi(q.Get("limit")); err == nil && v > 0 {
		input.PageSize = v
	}

	result, err := h.userService.ListUsers(r.Context(), input)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	enriched, err := h.userListResponse(r.Context(), result.Users)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"users": enriched,
		"total": result.Pagination.Total,
	})
}

// GetUser returns a single user by ID.
// GET /admin/users/{userId}
func (h *UserHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	if !requireSystemAdmin(w, r) {
		return
	}

	userId := r.PathValue("userId")
	id, err := types.ParseID(userId)
	if err != nil {
		writeError(w, errors.ValidationError("Invalid user ID"))
		return
	}

	user, err := h.userService.GetUser(r.Context(), id)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"user": user,
	})
}

// ListSystemRoles returns all system roles
// GET /admin/roles
func (h *UserHandler) ListSystemRoles(w http.ResponseWriter, r *http.Request) {
	if !requireSystemAdmin(w, r) {
		return
	}

	roles, err := h.roleService.ListSystemRoles(r.Context())
	if err != nil {
		handleServiceError(w, err)
		return
	}

	resp := make([]*dto.RoleResponse, len(roles))
	for i, role := range roles {
		resp[i] = dto.ToRoleResponse(role)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"roles": resp,
	})
}

// GetUserRoles returns the base roles assigned to a user
// GET /admin/users/{userId}/roles
func (h *UserHandler) GetUserRoles(w http.ResponseWriter, r *http.Request) {
	if !requireSystemAdmin(w, r) {
		return
	}

	userIDStr := r.PathValue("userId")
	if userIDStr == "" {
		writeError(w, errors.InvalidInput("userId", "User ID is required"))
		return
	}

	userID, err := types.ParseID(userIDStr)
	if err != nil {
		writeError(w, errors.InvalidInput("userId", "Invalid user ID"))
		return
	}

	roles, err := h.userService.GetUserBaseRoles(r.Context(), userID)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	resp := make([]*dto.RoleResponse, len(roles))
	for i, role := range roles {
		resp[i] = dto.ToRoleResponse(role)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"roles": resp,
	})
}

// SetUserRoles replaces a user's base roles with the provided set
// PUT /admin/users/{userId}/roles
func (h *UserHandler) SetUserRoles(w http.ResponseWriter, r *http.Request) {
	if !requireSystemAdmin(w, r) {
		return
	}

	callerID := middleware.GetUserID(r.Context())
	if callerID == nil {
		writeError(w, errors.Unauthorized("Authentication required"))
		return
	}

	userIDStr := r.PathValue("userId")
	if userIDStr == "" {
		writeError(w, errors.InvalidInput("userId", "User ID is required"))
		return
	}

	userID, err := types.ParseID(userIDStr)
	if err != nil {
		writeError(w, errors.InvalidInput("userId", "Invalid user ID"))
		return
	}

	// Accept either `role_codes` (preferred — what every SDK + the demo
	// UI emit) OR `role_ids` (UUID form, kept for back-compat with any
	// caller that pre-resolved). At least one must be present.
	//
	// Role CODES are the user-facing identifier (`system_admin`,
	// `super_admin`, `org_admin`, …); the UUID is an internal detail.
	// Earlier handler versions only accepted `role_ids` and silently
	// removed every existing role + assigned nothing when the SDK sent
	// `role_codes` — fixed here.
	var req struct {
		RoleCodes      []string `json:"role_codes"`
		RoleIDs        []string `json:"role_ids"`
		RevokeSessions bool     `json:"revoke_sessions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.InvalidInput("body", "Invalid request body"))
		return
	}

	desiredRoleIDs := make([]types.ID, 0, len(req.RoleIDs)+len(req.RoleCodes))

	// Resolve any codes to IDs via the role service.
	for _, code := range req.RoleCodes {
		role, err := h.roleService.GetRoleByCode(r.Context(), code)
		if err != nil {
			writeError(w, errors.InvalidInput("role_codes", "Unknown role code: "+code))
			return
		}
		desiredRoleIDs = append(desiredRoleIDs, role.ID)
	}

	for _, idStr := range req.RoleIDs {
		id, err := types.ParseID(idStr)
		if err != nil {
			writeError(w, errors.InvalidInput("role_ids", "Invalid role ID: "+idStr))
			return
		}
		desiredRoleIDs = append(desiredRoleIDs, id)
	}

	// Get current roles
	currentRoles, err := h.userService.GetUserBaseRoles(r.Context(), userID)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	currentRoleIDs := make(map[types.ID]bool)
	for _, role := range currentRoles {
		currentRoleIDs[role.ID] = true
	}

	desiredRoleIDSet := make(map[types.ID]bool)
	for _, id := range desiredRoleIDs {
		desiredRoleIDSet[id] = true
	}

	// Remove roles that are no longer desired
	for _, role := range currentRoles {
		if !desiredRoleIDSet[role.ID] {
			if err := h.userService.RemoveBaseRole(r.Context(), userID, role.ID); err != nil {
				handleServiceError(w, err)
				return
			}
		}
	}

	// Add new roles
	for _, roleID := range desiredRoleIDs {
		if !currentRoleIDs[roleID] {
			if err := h.userService.AssignBaseRole(r.Context(), userID, roleID, callerID); err != nil {
				handleServiceError(w, err)
				return
			}
		}
	}

	// Optionally revoke all sessions so new roles take effect
	if req.RevokeSessions {
		_ = h.authService.LogoutAll(r.Context(), userID)
	}

	// Return updated roles
	updatedRoles, err := h.userService.GetUserBaseRoles(r.Context(), userID)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	resp := make([]*dto.RoleResponse, len(updatedRoles))
	for i, role := range updatedRoles {
		resp[i] = dto.ToRoleResponse(role)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"roles":            resp,
		"sessions_revoked": req.RevokeSessions,
	})
}

// LookupUsersRequest is the inbound body for POST /admin/users/lookup.
//
// Either or both lists may be supplied; the response is the union of
// matches with soft-deleted users excluded. Caps and dedup are enforced
// in service.LookupUsersInput.Validate (max 200 keys combined).
type LookupUsersRequest struct {
	Emails []string `json:"emails,omitempty"`
	IDs    []string `json:"ids,omitempty"`
}

// LookupUsers resolves a batch of users by email and/or id in one call.
//
// POST /admin/users/lookup
//
// Body: { "emails": ["a@b.com", ...], "ids": ["uuid", ...] }
//
// Gated by adminChain (system_admin OR super_admin) at the route layer.
// Replaces the back-office workflow of POST /auth/check-email per email
// followed by GET /admin/users + client-side filter; one round-trip
// instead of N + 1.
//
// AUDIT-PHP-LARAVEL-DESIGN §5: feeds the PHP package's
// AdminFlow.lookupUsers and Laravel-side "find users by email" helpers
// used by back-office UIs.
func (h *UserHandler) LookupUsers(w http.ResponseWriter, r *http.Request) {
	var req LookupUsersRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.InvalidInput("body", "invalid JSON body"))
		return
	}

	// Parse + dedupe per type. Invalid UUIDs / emails return 400 with the
	// offending entry so the caller can fix and retry, rather than
	// silently dropping rows.
	emails := make([]types.Email, 0, len(req.Emails))
	for _, e := range req.Emails {
		emails = append(emails, types.Email(e))
	}
	ids := make([]types.ID, 0, len(req.IDs))
	for _, s := range req.IDs {
		id, err := types.ParseID(s)
		if err != nil {
			writeError(w, errors.InvalidInput("ids", "invalid user id: "+s))
			return
		}
		ids = append(ids, id)
	}

	users, err := h.userService.LookupUsers(r.Context(), service.LookupUsersInput{
		Emails: emails,
		IDs:    ids,
	})
	if err != nil {
		handleServiceError(w, err)
		return
	}

	resp := make([]*dto.UserResponse, 0, len(users))
	for _, u := range users {
		resp = append(resp, dto.ToUserResponse(u))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"users": resp,
		"count": len(resp),
	})
}

// GetMyOrganizations returns the authenticated user's organization
// memberships.
//
// GET /me/orgs
//
// Self-service mirror of GET /admin/users/{userId}/organizations.
// Powers "switch organization" UIs without requiring the caller to
// have admin scope. Mirrors the existing GET /me/apps pattern
// (app_handler.go MyApps).
//
// Response shape matches GetUserOrganizations for consistency, so a
// front-end can share the rendering code:
//
//	{
//	  "memberships": [
//	    { "organization": {...}, "status": "active", "joined_at": "...", "roles": [...] },
//	    ...
//	  ]
//	}
//
// Reused: service.GetUserOrganizations is identity-blind — handler
// supplies the user id from the request claims; no admin gate.
//
// AUTH-PHP-LARAVEL-DESIGN §5: closes the gap for the PHP/Laravel
// package's MeFlow.getOrgs and the browser SDK's AuthClient.getMyOrgs.
func (h *UserHandler) GetMyOrganizations(w http.ResponseWriter, r *http.Request) {
	uid := middleware.GetUserID(r.Context())
	if uid == nil {
		writeError(w, errors.Unauthorized("authentication required"))
		return
	}

	memberships, err := h.userService.GetUserOrganizations(r.Context(), *uid)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	// Identical response shape to GetUserOrganizations so the browser
	// SDK + PHP package can hydrate either result into the same model.
	type orgMembershipResponse struct {
		Organization *dto.OrganizationResponse `json:"organization"`
		Status       string                    `json:"status"`
		JoinedAt     string                    `json:"joined_at"`
		Roles        []*dto.RoleResponse       `json:"roles,omitempty"`
	}

	resp := make([]orgMembershipResponse, 0, len(memberships))
	for _, m := range memberships {
		entry := orgMembershipResponse{
			Status:   string(m.Status),
			JoinedAt: m.JoinedAt.Format("2006-01-02T15:04:05Z07:00"),
		}
		if m.Organization != nil {
			entry.Organization = dto.ToOrganizationResponse(m.Organization)
		}
		if len(m.Roles) > 0 {
			entry.Roles = make([]*dto.RoleResponse, len(m.Roles))
			for i, role := range m.Roles {
				entry.Roles[i] = dto.ToRoleResponse(&role)
			}
		}
		resp = append(resp, entry)
	}

	writeJSON(w, http.StatusOK, map[string]any{"memberships": resp})
}

// GetUserOrganizations returns the organizations a user belongs to
// GET /admin/users/{userId}/organizations
func (h *UserHandler) GetUserOrganizations(w http.ResponseWriter, r *http.Request) {
	if !requireSystemAdmin(w, r) {
		return
	}

	userIDStr := r.PathValue("userId")
	if userIDStr == "" {
		writeError(w, errors.InvalidInput("userId", "User ID is required"))
		return
	}

	userID, err := types.ParseID(userIDStr)
	if err != nil {
		writeError(w, errors.InvalidInput("userId", "Invalid user ID"))
		return
	}

	memberships, err := h.userService.GetUserOrganizations(r.Context(), userID)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	type orgMembershipResponse struct {
		Organization *dto.OrganizationResponse `json:"organization"`
		Status       string                    `json:"status"`
		JoinedAt     string                    `json:"joined_at"`
		Roles        []*dto.RoleResponse       `json:"roles,omitempty"`
	}

	resp := make([]orgMembershipResponse, 0, len(memberships))
	for _, m := range memberships {
		entry := orgMembershipResponse{
			Status:   string(m.Status),
			JoinedAt: m.JoinedAt.Format("2006-01-02T15:04:05Z07:00"),
		}
		if m.Organization != nil {
			entry.Organization = dto.ToOrganizationResponse(m.Organization)
		}
		if len(m.Roles) > 0 {
			entry.Roles = make([]*dto.RoleResponse, len(m.Roles))
			for i, role := range m.Roles {
				entry.Roles[i] = dto.ToRoleResponse(&role)
			}
		}
		resp = append(resp, entry)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"memberships": resp,
	})
}

// RevokeUserSessions terminates ALL sessions for a target user — the
// admin-side equivalent of /auth/logout/all the user might run on
// themselves. Revokes every refresh-token + bumps the per-user
// token-version counter so outstanding access tokens are rejected
// cross-replica.
//
// Route: POST /admin/users/{userId}/revoke-sessions
// Auth:  system_admin or super_admin (gated by adminChain at the
//
//	route layer). Use this for "kick this user out everywhere"
//	flows; for surgical per-session control use ListUserSessions
//	+ TerminateUserSession instead.
func (h *UserHandler) RevokeUserSessions(w http.ResponseWriter, r *http.Request) {
	if !requireSystemAdmin(w, r) {
		return
	}

	userIDStr := r.PathValue("userId")
	if userIDStr == "" {
		writeError(w, errors.InvalidInput("userId", "User ID is required"))
		return
	}

	userID, err := types.ParseID(userIDStr)
	if err != nil {
		writeError(w, errors.InvalidInput("userId", "Invalid user ID"))
		return
	}

	if err := h.authService.LogoutAll(r.Context(), userID); err != nil {
		handleServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// ResetLockout clears a user's failed-login attempts + account lock, so a
// platform admin can unlock someone locked out by too many bad passwords.
//
// Route: POST /admin/users/{userId}/reset-lockout
// Auth:  system_admin only (adminChain route + requireSystemAdmin here).
func (h *UserHandler) ResetLockout(w http.ResponseWriter, r *http.Request) {
	if !requireSystemAdmin(w, r) {
		return
	}

	userIDStr := r.PathValue("userId")
	if userIDStr == "" {
		writeError(w, errors.InvalidInput("userId", "User ID is required"))
		return
	}

	userID, err := types.ParseID(userIDStr)
	if err != nil {
		writeError(w, errors.InvalidInput("userId", "Invalid user ID"))
		return
	}

	if _, err := h.userService.ResetLockout(r.Context(), userID); err != nil {
		handleServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// ListUserSessions returns every active session for a target user.
// Mirrors /auth/sessions but lets a platform admin inspect anyone's
// active sessions — useful for support cases ("kick me out of my
// other laptop"), incident response, or auditing a compromised
// account before deciding whether to nuke everything.
//
// Route: GET /admin/users/{userId}/sessions
// Auth:  system_admin or super_admin (gated by adminChain at the
//
//	route layer). Returns a bare JSON array of SessionResponse,
//	matching the self-service /auth/sessions shape so the UI
//	can reuse the same row renderer.
//
// is_current is set only when the admin is viewing their OWN
// sessions (i.e. userId == caller's user_id). When inspecting
// someone else's sessions the flag is meaningless and is omitted —
// "current" is a property of THIS HTTP request, not of the target
// user. The single-handler-for-both-views design saves the UI from
// having to fork between /auth/sessions and the admin endpoint just
// to learn which row is the one the admin is currently sitting in.
func (h *UserHandler) ListUserSessions(w http.ResponseWriter, r *http.Request) {
	userIDStr := r.PathValue("userId")
	userID, err := types.ParseID(userIDStr)
	if err != nil {
		writeError(w, errors.InvalidInput("userId", "Invalid user ID"))
		return
	}

	sessions, err := h.authService.GetUserSessions(r.Context(), userID)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	// Only thread the caller's session_id through when they're looking
	// at their own sessions — otherwise "is_current" would mark a row
	// in the target user's list that has nothing to do with this
	// request. GetClaims always populates SessionID on authenticated
	// admin paths, but we still nil-check defensively.
	var currentSessionID *types.ID
	callerID := middleware.GetUserID(r.Context())
	if callerID != nil && *callerID == userID {
		if claims := middleware.GetClaims(r.Context()); claims != nil && claims.SessionID != nil {
			currentSessionID = claims.SessionID
		}
	}

	resp := make([]*dto.SessionResponse, len(sessions))
	for i, session := range sessions {
		resp[i] = dto.ToSessionResponse(session, currentSessionID)
	}

	writeJSON(w, http.StatusOK, resp)
}

// TerminateUserSession kills one specific session belonging to a
// target user — granular alternative to RevokeUserSessions (which
// blows away every session at once).
//
// Route: DELETE /admin/users/{userId}/sessions/{sessionId}
// Auth:  system_admin or super_admin (gated by adminChain at the
//
//	route layer).
//
// Returns 200 {success:true} on a successful terminate. Returns 404
// if the session doesn't exist OR if it doesn't belong to the
// specified userId — the service layer enforces ownership so an
// admin can't accidentally terminate a session by mismatched ids.
func (h *UserHandler) TerminateUserSession(w http.ResponseWriter, r *http.Request) {
	userIDStr := r.PathValue("userId")
	userID, err := types.ParseID(userIDStr)
	if err != nil {
		writeError(w, errors.InvalidInput("userId", "Invalid user ID"))
		return
	}

	sessionIDStr := r.PathValue("sessionId")
	sessionID, err := types.ParseID(sessionIDStr)
	if err != nil {
		writeError(w, errors.InvalidInput("sessionId", "Invalid session ID"))
		return
	}

	if err := h.authService.TerminateSession(r.Context(), userID, sessionID); err != nil {
		handleServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// --- User pools (namespaces) administration. All routes below are
// system_admin-only (systemAdminChain in routes.go). Pool model:
// docs/USER_POOLS.md — one default (home) pool per user + N tag pools.

// ListNamespaces handles GET /admin/namespaces — every known pool with
// user counts (home / tag / distinct total) and the app codes whose
// pool config references it. Pools with zero users are app-config-only
// ("empty") and the admin UI flags them.
func (h *UserHandler) ListNamespaces(w http.ResponseWriter, r *http.Request) {
	namespaces, err := h.userService.ListNamespaces(r.Context())
	if err != nil {
		handleServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"namespaces": namespaces})
}

// GetUserNamespaces handles GET /admin/users/{userId}/namespaces.
// Response: { "namespace": "<home pool>", "namespaces": ["<tag>", ...] }.
func (h *UserHandler) GetUserNamespaces(w http.ResponseWriter, r *http.Request) {
	userID, err := types.ParseID(r.PathValue("userId"))
	if err != nil {
		writeError(w, errors.InvalidInput("userId", "invalid user ID"))
		return
	}
	home, others, err := h.userService.GetUserNamespaces(r.Context(), userID)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"namespace": home, "namespaces": others})
}

// SetUserHomeNamespace handles PUT /admin/users/{userId}/namespace —
// moves the user's default (home) pool. 409 when the email already
// exists in the target pool.
func (h *UserHandler) SetUserHomeNamespace(w http.ResponseWriter, r *http.Request) {
	userID, err := types.ParseID(r.PathValue("userId"))
	if err != nil {
		writeError(w, errors.InvalidInput("userId", "invalid user ID"))
		return
	}
	var req struct {
		Namespace string `json:"namespace"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.InvalidInput("body", "invalid request body"))
		return
	}
	if err := h.userService.SetUserHomeNamespace(r.Context(), userID, req.Namespace); err != nil {
		handleServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// AddUserNamespace handles POST /admin/users/{userId}/namespaces —
// tags the user into an additional pool. Idempotent.
func (h *UserHandler) AddUserNamespace(w http.ResponseWriter, r *http.Request) {
	userID, err := types.ParseID(r.PathValue("userId"))
	if err != nil {
		writeError(w, errors.InvalidInput("userId", "invalid user ID"))
		return
	}
	var req struct {
		Namespace string `json:"namespace"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.InvalidInput("body", "invalid request body"))
		return
	}
	if err := h.userService.AddUserNamespace(r.Context(), userID, req.Namespace); err != nil {
		handleServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// RemoveUserNamespace handles DELETE /admin/users/{userId}/namespaces/{namespace}.
// The home pool is refused — change it via PUT .../namespace instead.
func (h *UserHandler) RemoveUserNamespace(w http.ResponseWriter, r *http.Request) {
	userID, err := types.ParseID(r.PathValue("userId"))
	if err != nil {
		writeError(w, errors.InvalidInput("userId", "invalid user ID"))
		return
	}
	ns := r.PathValue("namespace")
	if err := h.userService.RemoveUserNamespace(r.Context(), userID, ns); err != nil {
		handleServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
