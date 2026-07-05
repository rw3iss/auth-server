package handlers

// OrgRoleHandler — org self-service custom-role CRUD (AUDIT C3).
//
// All routes are mounted under /orgs/{orgId}/roles/* and go through the
// same RequireOrgContext + RequirePermission middleware chain used for the
// existing /orgs/{orgId}/members endpoints. The service layer enforces the
// org_assignable safety gate so an org admin can't grant platform-scoped
// permissions to a custom role. system_admin bypasses the path-match in
// the middleware.

import (
	"encoding/json"
	"net/http"

	"github.com/rw3iss/auth/internal/api/dto"
	"github.com/rw3iss/auth/internal/service"
	"github.com/rw3iss/auth/pkg/shared/errors"
	"github.com/rw3iss/auth/pkg/shared/types"
)

type OrgRoleHandler struct {
	roleService *service.RoleService
}

func NewOrgRoleHandler(roleService *service.RoleService) *OrgRoleHandler {
	return &OrgRoleHandler{roleService: roleService}
}

// List returns the roles available within an organization — system roles
// flagged `is_org_role=true` plus custom roles bound to this org. Drives
// the assign-role picker on the org members surface.
func (h *OrgRoleHandler) List(w http.ResponseWriter, r *http.Request) {
	orgID, err := types.ParseID(r.PathValue("orgId"))
	if err != nil {
		writeError(w, errors.InvalidInput("orgId", "invalid org id"))
		return
	}
	roles, err := h.roleService.ListOrganizationRoles(r.Context(), orgID)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	resp := make([]*dto.RoleResponse, len(roles))
	for i, role := range roles {
		resp[i] = dto.ToRoleResponse(role)
	}
	writeJSON(w, http.StatusOK, map[string]any{"roles": resp})
}

// Get returns a single role. Confirms the role belongs to the path org so a
// caller can't probe role IDs outside their tenant.
func (h *OrgRoleHandler) Get(w http.ResponseWriter, r *http.Request) {
	orgID, err := types.ParseID(r.PathValue("orgId"))
	if err != nil {
		writeError(w, errors.InvalidInput("orgId", "invalid org id"))
		return
	}
	roleID, err := types.ParseID(r.PathValue("roleId"))
	if err != nil {
		writeError(w, errors.InvalidInput("roleId", "invalid role id"))
		return
	}
	role, err := h.roleService.GetRole(r.Context(), roleID)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	// Refuse to surface roles from a different org. System roles (is_org_role
	// shared across orgs) pass through unchanged.
	if role.OrganizationID != nil && *role.OrganizationID != orgID {
		writeError(w, errors.NotFound("role"))
		return
	}
	writeJSON(w, http.StatusOK, dto.ToRoleResponse(role))
}

// Create builds a custom role for the path org. The service enforces:
//   - role code is not a reserved system role code
//   - every permission code maps to an existing permission
//   - every selected permission is org_assignable
//
// 403 is returned on the third failure mode; 400 on the others.
func (h *OrgRoleHandler) Create(w http.ResponseWriter, r *http.Request) {
	orgID, err := types.ParseID(r.PathValue("orgId"))
	if err != nil {
		writeError(w, errors.InvalidInput("orgId", "invalid org id"))
		return
	}
	var req dto.CreateOrgRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.InvalidInput("body", "invalid request body"))
		return
	}
	role, err := h.roleService.CreateOrgRole(r.Context(), orgID, service.CreateOrgRoleInput{
		Code:            req.Code,
		Name:            req.Name,
		Description:     req.Description,
		Level:           req.Level,
		PermissionCodes: req.PermissionCodes,
	})
	if err != nil {
		handleServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, dto.ToRoleResponse(role))
}

// Update modifies a custom org role. Refuses system roles and any role
// bound to a different org. PermissionCodes is treated as a replace-set
// when present (nil leaves permissions unchanged; empty slice clears).
func (h *OrgRoleHandler) Update(w http.ResponseWriter, r *http.Request) {
	orgID, err := types.ParseID(r.PathValue("orgId"))
	if err != nil {
		writeError(w, errors.InvalidInput("orgId", "invalid org id"))
		return
	}
	roleID, err := types.ParseID(r.PathValue("roleId"))
	if err != nil {
		writeError(w, errors.InvalidInput("roleId", "invalid role id"))
		return
	}
	var req dto.UpdateOrgRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.InvalidInput("body", "invalid request body"))
		return
	}
	role, err := h.roleService.UpdateOrgRole(r.Context(), orgID, roleID, service.UpdateOrgRoleInput{
		Name:            req.Name,
		Description:     req.Description,
		Level:           req.Level,
		PermissionCodes: req.PermissionCodes,
	})
	if err != nil {
		handleServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, dto.ToRoleResponse(role))
}

// Delete removes a custom org role. Refuses system roles + cross-org IDs.
// Member-role assignments cascade via the schema FK so the role-permissions
// + member-role link rows clean up automatically.
func (h *OrgRoleHandler) Delete(w http.ResponseWriter, r *http.Request) {
	orgID, err := types.ParseID(r.PathValue("orgId"))
	if err != nil {
		writeError(w, errors.InvalidInput("orgId", "invalid org id"))
		return
	}
	roleID, err := types.ParseID(r.PathValue("roleId"))
	if err != nil {
		writeError(w, errors.InvalidInput("roleId", "invalid role id"))
		return
	}
	if err := h.roleService.DeleteOrgRole(r.Context(), orgID, roleID); err != nil {
		handleServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ListAssignablePermissions lists permissions an org admin is allowed to
// grant via a custom role — the UI's source for the permission picker on
// the role-create/edit form.
func (h *OrgRoleHandler) ListAssignablePermissions(w http.ResponseWriter, r *http.Request) {
	perms, err := h.roleService.ListOrgAssignablePermissions(r.Context())
	if err != nil {
		handleServiceError(w, err)
		return
	}
	resp := &dto.ListOrgAssignablePermissionsResponse{
		Permissions: make([]*dto.PermissionResponse, len(perms)),
	}
	for i, p := range perms {
		resp.Permissions[i] = dto.ToPermissionResponse(p)
	}
	writeJSON(w, http.StatusOK, resp)
}
