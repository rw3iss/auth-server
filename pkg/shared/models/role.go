package models

import (
	"github.com/ven/auth/pkg/shared/types"
)

// RoleType represents the type of role
type RoleType string

const (
	RoleTypeSystem RoleType = "system" // Built-in roles that cannot be modified
	RoleTypeCustom RoleType = "custom" // Custom roles created by organizations
)

// SystemRoleCode represents predefined system role identifiers
type SystemRoleCode string

const (
	// Platform-level roles (no organization context)
	RoleSystemAdmin SystemRoleCode = "system_admin"
	RoleSuperAdmin  SystemRoleCode = "super_admin" // cross-org data admin; not platform owner
	RoleBaseUser    SystemRoleCode = "base_user"

	// Organization-level roles
	RoleOrgAdmin   SystemRoleCode = "org_admin"
	RoleOrgManager SystemRoleCode = "org_manager"
	RoleOrgMember  SystemRoleCode = "org_member" // fallback role on AddMember when no specific role specified
	RoleSeller     SystemRoleCode = "seller"
	RoleBuyer      SystemRoleCode = "buyer"
)

// BaseRole represents a role that can be assigned to users
type BaseRole struct {
	BaseModel
	SoftDeletable

	Code        string       `json:"code" db:"code"`               // Unique identifier for the role
	Name        string       `json:"name" db:"name"`               // Human-readable name
	Description string       `json:"description" db:"description"` // Description of the role
	Type        RoleType     `json:"type" db:"type"`               // system or custom
	Level       int          `json:"level" db:"level"`             // Hierarchy level (lower = more powerful)
	IsOrgRole   bool         `json:"is_org_role" db:"is_org_role"` // Whether this role is organization-specific

	// For custom roles, this links to the organization that created it
	OrganizationID *types.ID `json:"organization_id,omitempty" db:"organization_id"`

	Metadata types.JSON `json:"metadata,omitempty" db:"metadata"`
}

// IsSystemRole checks if this is a system-defined role
func (r *BaseRole) IsSystemRole() bool {
	return r.Type == RoleTypeSystem
}

// CanBeModified checks if the role can be modified
func (r *BaseRole) CanBeModified() bool {
	return r.Type == RoleTypeCustom
}

// BaseRoleSummary provides a minimal view of role data
type BaseRoleSummary struct {
	ID          types.ID `json:"id"`
	Code        string   `json:"code"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Type        RoleType `json:"type"`
	IsOrgRole   bool     `json:"is_org_role"`
}

// ToSummary converts a BaseRole to BaseRoleSummary
func (r *BaseRole) ToSummary() BaseRoleSummary {
	return BaseRoleSummary{
		ID:          r.ID,
		Code:        r.Code,
		Name:        r.Name,
		Description: r.Description,
		Type:        r.Type,
		IsOrgRole:   r.IsOrgRole,
	}
}
