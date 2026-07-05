package domain

import (
	"github.com/ven/auth/pkg/shared/models"
	"github.com/ven/auth/pkg/shared/types"
)

// Role extends BaseRole with auth-specific fields
type Role struct {
	models.BaseRole

	// Loaded associations
	Permissions []Permission `json:"permissions,omitempty" db:"-"`
}

// NewRole creates a new role
func NewRole(code, name, description string, roleType models.RoleType, isOrgRole bool) *Role {
	return &Role{
		BaseRole: models.BaseRole{
			BaseModel:   models.NewBaseModel(),
			Code:        code,
			Name:        name,
			Description: description,
			Type:        roleType,
			IsOrgRole:   isOrgRole,
		},
	}
}

// NewCustomRole creates a new custom organization role
func NewCustomRole(code, name, description string, orgID types.ID) *Role {
	role := NewRole(code, name, description, models.RoleTypeCustom, true)
	role.OrganizationID = &orgID
	return role
}

// HasPermission checks if the role has a specific permission
func (r *Role) HasPermission(permissionCode string) bool {
	for _, p := range r.Permissions {
		if p.Code == permissionCode {
			return true
		}
	}
	return false
}

// HasAnyPermission checks if the role has any of the specified permissions
func (r *Role) HasAnyPermission(permissionCodes ...string) bool {
	for _, code := range permissionCodes {
		if r.HasPermission(code) {
			return true
		}
	}
	return false
}

// HasAllPermissions checks if the role has all specified permissions
func (r *Role) HasAllPermissions(permissionCodes ...string) bool {
	for _, code := range permissionCodes {
		if !r.HasPermission(code) {
			return false
		}
	}
	return true
}

// Permission extends the base Permission model
type Permission struct {
	models.Permission
}

// NewPermission creates a new permission
func NewPermission(resource, action, name, description, category string) *Permission {
	return &Permission{
		Permission: models.Permission{
			BaseModel:   models.NewBaseModel(),
			Code:        models.PermissionCode(resource, action),
			Name:        name,
			Description: description,
			Resource:    resource,
			Action:      action,
			Category:    category,
		},
	}
}

// RolePermission links a role to a permission
type RolePermission struct {
	RoleID       types.ID `json:"role_id" db:"role_id"`
	PermissionID types.ID `json:"permission_id" db:"permission_id"`
}

// UserBaseRole links a user to their base role (outside any organization)
type UserBaseRole struct {
	models.BaseModel

	UserID     types.ID        `json:"user_id" db:"user_id"`
	RoleID     types.ID        `json:"role_id" db:"role_id"`
	AssignedAt types.Timestamp `json:"assigned_at" db:"assigned_at"`
	AssignedBy *types.ID       `json:"assigned_by,omitempty" db:"assigned_by"`
}

// NewUserBaseRole creates a new user base role assignment
func NewUserBaseRole(userID, roleID types.ID, assignedBy *types.ID) *UserBaseRole {
	return &UserBaseRole{
		BaseModel:  models.NewBaseModel(),
		UserID:     userID,
		RoleID:     roleID,
		AssignedAt: types.Now(),
		AssignedBy: assignedBy,
	}
}
