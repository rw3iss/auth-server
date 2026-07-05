package dto

import (
	"github.com/ven/auth/internal/domain"
)

// RoleResponse represents a role in API responses
type RoleResponse struct {
	ID             string                `json:"id"`
	Code           string                `json:"code"`
	Name           string                `json:"name"`
	Description    string                `json:"description,omitempty"`
	Type           string                `json:"type"`
	Level          int                   `json:"level"`
	IsOrgRole      bool                  `json:"is_org_role"`
	OrganizationID string                `json:"organization_id,omitempty"`
	Permissions    []*PermissionResponse `json:"permissions,omitempty"`
	CreatedAt      string                `json:"created_at"`
	UpdatedAt      string                `json:"updated_at"`
}

// ToRoleResponse converts a domain role to response
func ToRoleResponse(role *domain.Role) *RoleResponse {
	resp := &RoleResponse{
		ID:          role.ID.String(),
		Code:        role.Code,
		Name:        role.Name,
		Description: role.Description,
		Type:        string(role.Type),
		Level:       role.Level,
		IsOrgRole:   role.IsOrgRole,
		CreatedAt:   role.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:   role.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	if role.OrganizationID != nil {
		resp.OrganizationID = role.OrganizationID.String()
	}

	if len(role.Permissions) > 0 {
		resp.Permissions = make([]*PermissionResponse, len(role.Permissions))
		for i, perm := range role.Permissions {
			resp.Permissions[i] = ToPermissionResponse(&perm)
		}
	}

	return resp
}

// CreateRoleRequest represents a request to create a role
type CreateRoleRequest struct {
	Code          string   `json:"code" validate:"required"`
	Name          string   `json:"name" validate:"required"`
	Description   string   `json:"description,omitempty"`
	Level         int      `json:"level,omitempty"`
	PermissionIDs []string `json:"permission_ids,omitempty"`
}

// UpdateRoleRequest represents a request to update a role
type UpdateRoleRequest struct {
	Name          *string  `json:"name,omitempty"`
	Description   *string  `json:"description,omitempty"`
	Level         *int     `json:"level,omitempty"`
	PermissionIDs []string `json:"permission_ids,omitempty"`
}

// ListRolesRequest represents a request to list roles
type ListRolesRequest struct {
	Type           string `query:"type"`
	IsOrgRole      *bool  `query:"is_org_role"`
	OrganizationID string `query:"organization_id"`
	Page           int    `query:"page"`
	PageSize       int    `query:"page_size"`
}

// ListRolesResponse represents the response for listing roles
type ListRolesResponse struct {
	Roles      []*RoleResponse    `json:"roles"`
	Pagination PaginationResponse `json:"pagination"`
}

// AssignPermissionRequest represents a request to assign a permission
type AssignPermissionRequest struct {
	PermissionID string `json:"permission_id" validate:"required"`
}

// PermissionResponse represents a permission in API responses
type PermissionResponse struct {
	ID            string `json:"id"`
	Code          string `json:"code"`
	Name          string `json:"name"`
	Description   string `json:"description,omitempty"`
	Resource      string `json:"resource"`
	Action        string `json:"action"`
	Category      string `json:"category"`
	OrgAssignable bool   `json:"org_assignable"`
}

// ToPermissionResponse converts a domain permission to response
func ToPermissionResponse(perm *domain.Permission) *PermissionResponse {
	return &PermissionResponse{
		ID:            perm.ID.String(),
		Code:          perm.Code,
		Name:          perm.Name,
		Description:   perm.Description,
		Resource:      perm.Resource,
		Action:        perm.Action,
		Category:      perm.Category,
		OrgAssignable: perm.OrgAssignable,
	}
}

// CreateOrgRoleRequest represents a request to create a custom org role
// (AUDIT C3). PermissionCodes is the human-friendly identifier set; the
// service resolves codes to IDs and validates the org_assignable gate.
type CreateOrgRoleRequest struct {
	Code            string   `json:"code" validate:"required"`
	Name            string   `json:"name" validate:"required"`
	Description     string   `json:"description,omitempty"`
	Level           int      `json:"level,omitempty"`
	PermissionCodes []string `json:"permission_codes,omitempty"`
}

// UpdateOrgRoleRequest — same field set, all optional.
type UpdateOrgRoleRequest struct {
	Name            *string  `json:"name,omitempty"`
	Description     *string  `json:"description,omitempty"`
	Level           *int     `json:"level,omitempty"`
	PermissionCodes []string `json:"permission_codes,omitempty"`
}

// ListOrgAssignablePermissionsResponse lists permissions an org admin is
// allowed to grant via a custom role. Drives the UI's permission picker.
type ListOrgAssignablePermissionsResponse struct {
	Permissions []*PermissionResponse `json:"permissions"`
}

// ListPermissionsRequest represents a request to list permissions
type ListPermissionsRequest struct {
	Resource string `query:"resource"`
	Action   string `query:"action"`
	Category string `query:"category"`
	Page     int    `query:"page"`
	PageSize int    `query:"page_size"`
}

// ListPermissionsResponse represents the response for listing permissions
type ListPermissionsResponse struct {
	Permissions []*PermissionResponse `json:"permissions"`
	Pagination  PaginationResponse    `json:"pagination"`
}

// CheckPermissionRequest represents a request to check permissions
type CheckPermissionRequest struct {
	Permission string `json:"permission" validate:"required"`
}

// CheckPermissionResponse represents the response for checking permissions
type CheckPermissionResponse struct {
	HasPermission bool `json:"has_permission"`
}
