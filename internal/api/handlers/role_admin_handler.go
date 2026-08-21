package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/rw3iss/auth/internal/service"
	"github.com/rw3iss/auth/pkg/shared/errors"
	"github.com/rw3iss/auth/pkg/shared/types"
)

// RoleAdminHandler creates and edits roles.
//
// Until now the server could LIST roles and ASSIGN them, but not create one — `RoleService` had the
// capability with no route in front of it, so standing up an application meant dropping to SQL for that
// one step. These routes close that gap so onboarding an app is entirely API-driven.
type RoleAdminHandler struct{ roles *service.RoleService }

func NewRoleAdminHandler(roles *service.RoleService) *RoleAdminHandler {
	return &RoleAdminHandler{roles: roles}
}

type createRoleRequest struct {
	Code        string `json:"code"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Level       int    `json:"level"`
	// Omit (or null) for a PLATFORM-WIDE role; set it to scope the role to one organization.
	OrganizationID string `json:"organization_id,omitempty"`
	// Service-qualified. A bare code is ambiguous since migration 026, so this deliberately does not
	// accept one — attaching another service's identically-named permission would be silent and wrong.
	Permissions []service.PermissionRef `json:"permissions,omitempty"`
}

// Create handles POST /admin/roles.
func (h *RoleAdminHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req createRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.InvalidInput("body", "Invalid request body"))
		return
	}
	req.Code = strings.TrimSpace(req.Code)
	if req.Code == "" || strings.TrimSpace(req.Name) == "" {
		writeError(w, errors.InvalidInput("code", "code and name are required"))
		return
	}
	// `system_admin` bypasses every permission check, so allowing it to be minted here would turn role
	// creation into privilege escalation. It is seeded, never created.
	if req.Code == "system_admin" {
		writeError(w, errors.InvalidInput("code", "system_admin is reserved and cannot be created"))
		return
	}

	ids, err := h.roles.ResolvePermissionRefs(r.Context(), req.Permissions)
	if err != nil {
		// An unresolved permission fails the whole request: a role created with half its permissions is
		// harder to notice, and more dangerous, than one that was refused.
		writeError(w, errors.InvalidInput("permissions", err.Error()))
		return
	}

	in := service.CreateRoleInput{
		Code: req.Code, Name: req.Name, Description: req.Description,
		Level: req.Level, PermissionIDs: ids,
	}

	var role any
	if req.OrganizationID != "" {
		orgID, perr := uuid.Parse(req.OrganizationID)
		if perr != nil {
			writeError(w, errors.InvalidInput("organization_id", "Not a valid organization id"))
			return
		}
		role, err = h.roles.CreateCustomRole(r.Context(), types.ID(orgID), in)
	} else {
		role, err = h.roles.CreateSystemRole(r.Context(), in)
	}
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			writeError(w, errors.InvalidInput("code", "A role with that code already exists in this scope"))
			return
		}
		writeError(w, errors.InvalidInput("code", "Could not create role: "+err.Error()))
		return
	}
	writeJSON(w, http.StatusCreated, role)
}

type updateRoleRequest struct {
	Name        *string                 `json:"name,omitempty"`
	Description *string                 `json:"description,omitempty"`
	Level       *int                    `json:"level,omitempty"`
	// Supplying this REPLACES the role's permissions — it is not additive. Omit to leave them alone.
	Permissions *[]service.PermissionRef `json:"permissions,omitempty"`
}

// Update handles PUT /admin/roles/{roleId}.
func (h *RoleAdminHandler) Update(w http.ResponseWriter, r *http.Request) {
	roleID, err := uuid.Parse(r.PathValue("roleId"))
	if err != nil {
		writeError(w, errors.InvalidInput("roleId", "Not a valid role id"))
		return
	}
	var req updateRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.InvalidInput("body", "Invalid request body"))
		return
	}
	in := service.UpdateRoleInput{Name: req.Name, Description: req.Description, Level: req.Level}
	if req.Permissions != nil {
		ids, rerr := h.roles.ResolvePermissionRefs(r.Context(), *req.Permissions)
		if rerr != nil {
			writeError(w, errors.InvalidInput("permissions", rerr.Error()))
			return
		}
		in.PermissionIDs = ids
	}
	role, err := h.roles.UpdateRole(r.Context(), types.ID(roleID), in)
	if err != nil {
		writeError(w, errors.InvalidInput("roleId", "Could not update role: "+err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, role)
}

// Delete handles DELETE /admin/roles/{roleId}.
func (h *RoleAdminHandler) Delete(w http.ResponseWriter, r *http.Request) {
	roleID, err := uuid.Parse(r.PathValue("roleId"))
	if err != nil {
		writeError(w, errors.InvalidInput("roleId", "Not a valid role id"))
		return
	}
	// Deleting a role revokes it from everyone holding it, on their next token issue. The service layer
	// refuses to delete a system-seeded role.
	if err := h.roles.DeleteRole(r.Context(), types.ID(roleID)); err != nil {
		writeError(w, errors.InvalidInput("roleId", "Could not delete role: "+err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
