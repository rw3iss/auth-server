package service

import (
	"context"

	"github.com/ven/auth/internal/domain"
	"github.com/ven/auth/internal/repository"
	"github.com/ven/auth/pkg/shared/errors"
	"github.com/ven/auth/pkg/shared/models"
	"github.com/ven/auth/pkg/shared/types"
)

// RoleService handles role and permission management business logic
type RoleService struct {
	roleRepo repository.RoleRepository
	permRepo repository.PermissionRepository
	orgRepo  repository.OrganizationRepository
}

// NewRoleService creates a new role service
func NewRoleService(
	roleRepo repository.RoleRepository,
	permRepo repository.PermissionRepository,
	orgRepo repository.OrganizationRepository,
) *RoleService {
	return &RoleService{
		roleRepo: roleRepo,
		permRepo: permRepo,
		orgRepo:  orgRepo,
	}
}

// GetRole retrieves a role by ID
func (s *RoleService) GetRole(ctx context.Context, id types.ID) (*domain.Role, error) {
	role, err := s.roleRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Load permissions
	permissions, _ := s.roleRepo.GetPermissions(ctx, role.ID)
	role.Permissions = derefPermissions(permissions)

	return role, nil
}

// GetRoleByCode retrieves a role by code
func (s *RoleService) GetRoleByCode(ctx context.Context, code string) (*domain.Role, error) {
	role, err := s.roleRepo.GetByCode(ctx, code)
	if err != nil {
		return nil, err
	}

	// Load permissions
	permissions, _ := s.roleRepo.GetPermissions(ctx, role.ID)
	role.Permissions = derefPermissions(permissions)

	return role, nil
}

// CreateRoleInput contains input for creating a role
type CreateRoleInput struct {
	Code          string     `json:"code" validate:"required"`
	Name          string     `json:"name" validate:"required"`
	Description   string     `json:"description,omitempty"`
	Level         int        `json:"level,omitempty"`
	PermissionIDs []types.ID `json:"permission_ids,omitempty"`
}

// CreateCustomRole creates a custom role for an organization
func (s *RoleService) CreateCustomRole(ctx context.Context, orgID types.ID, input CreateRoleInput) (*domain.Role, error) {
	// Verify organization exists
	_, err := s.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		return nil, err
	}

	role := domain.NewCustomRole(input.Code, input.Name, input.Description, orgID)
	role.Level = input.Level

	if err := s.roleRepo.Create(ctx, role); err != nil {
		return nil, err
	}

	// Assign permissions
	if len(input.PermissionIDs) > 0 {
		if err := s.roleRepo.SetPermissions(ctx, role.ID, input.PermissionIDs); err != nil {
			return nil, err
		}
	}

	// Load permissions
	permissions, _ := s.roleRepo.GetPermissions(ctx, role.ID)
	role.Permissions = derefPermissions(permissions)

	return role, nil
}

// UpdateRoleInput contains input for updating a role
type UpdateRoleInput struct {
	Name          *string    `json:"name,omitempty"`
	Description   *string    `json:"description,omitempty"`
	Level         *int       `json:"level,omitempty"`
	PermissionIDs []types.ID `json:"permission_ids,omitempty"`
}

// UpdateRole updates a custom role
func (s *RoleService) UpdateRole(ctx context.Context, roleID types.ID, input UpdateRoleInput) (*domain.Role, error) {
	role, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		return nil, err
	}

	if role.Type == models.RoleTypeSystem {
		return nil, errors.CannotModifySystemRole()
	}

	if input.Name != nil {
		role.Name = *input.Name
	}
	if input.Description != nil {
		role.Description = *input.Description
	}
	if input.Level != nil {
		role.Level = *input.Level
	}

	if err := s.roleRepo.Update(ctx, role); err != nil {
		return nil, err
	}

	// Update permissions if provided
	if input.PermissionIDs != nil {
		if err := s.roleRepo.SetPermissions(ctx, role.ID, input.PermissionIDs); err != nil {
			return nil, err
		}
	}

	// Load updated permissions
	permissions, _ := s.roleRepo.GetPermissions(ctx, role.ID)
	role.Permissions = derefPermissions(permissions)

	return role, nil
}

// DeleteRole deletes a custom role
func (s *RoleService) DeleteRole(ctx context.Context, roleID types.ID) error {
	role, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		return err
	}

	if role.Type == models.RoleTypeSystem {
		return errors.CannotModifySystemRole()
	}

	return s.roleRepo.Delete(ctx, roleID)
}

// ListSystemRoles lists all system roles
func (s *RoleService) ListSystemRoles(ctx context.Context) ([]*domain.Role, error) {
	roles, err := s.roleRepo.ListSystemRoles(ctx)
	if err != nil {
		return nil, err
	}

	// Load permissions for each role
	for _, role := range roles {
		permissions, _ := s.roleRepo.GetPermissions(ctx, role.ID)
		role.Permissions = derefPermissions(permissions)
	}

	return roles, nil
}

// ListOrganizationRoles lists roles available for an organization
func (s *RoleService) ListOrganizationRoles(ctx context.Context, orgID types.ID) ([]*domain.Role, error) {
	roles, err := s.roleRepo.ListOrgRoles(ctx, orgID)
	if err != nil {
		return nil, err
	}

	// Load permissions for each role
	for _, role := range roles {
		permissions, _ := s.roleRepo.GetPermissions(ctx, role.ID)
		role.Permissions = derefPermissions(permissions)
	}

	return roles, nil
}

// ListRolesInput contains input for listing roles
type ListRolesInput struct {
	Type           *string
	IsOrgRole      *bool
	OrganizationID *types.ID
	Page           int
	PageSize       int
}

// ListRolesResult contains the result of listing roles
type ListRolesResult struct {
	Roles      []*domain.Role   `json:"roles"`
	Pagination types.Pagination `json:"pagination"`
}

// ListRoles lists roles with filtering
func (s *RoleService) ListRoles(ctx context.Context, input ListRolesInput) (*ListRolesResult, error) {
	pagination := types.DefaultPagination()
	if input.Page > 0 {
		pagination.Page = input.Page
	}
	if input.PageSize > 0 {
		pagination.PageSize = input.PageSize
	}

	filter := repository.RoleFilter{
		Type:           input.Type,
		IsOrgRole:      input.IsOrgRole,
		OrganizationID: input.OrganizationID,
		Pagination:     pagination,
	}

	roles, total, err := s.roleRepo.ListAll(ctx, filter)
	if err != nil {
		return nil, err
	}

	pagination.Total = total

	// Load permissions for each role
	for _, role := range roles {
		permissions, _ := s.roleRepo.GetPermissions(ctx, role.ID)
		role.Permissions = derefPermissions(permissions)
	}

	return &ListRolesResult{
		Roles:      roles,
		Pagination: pagination,
	}, nil
}

// AssignPermission assigns a permission to a role
func (s *RoleService) AssignPermission(ctx context.Context, roleID, permissionID types.ID) error {
	role, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		return err
	}

	if role.Type == models.RoleTypeSystem {
		return errors.CannotModifySystemRole()
	}

	return s.roleRepo.AssignPermission(ctx, roleID, permissionID)
}

// RemovePermission removes a permission from a role
func (s *RoleService) RemovePermission(ctx context.Context, roleID, permissionID types.ID) error {
	role, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		return err
	}

	if role.Type == models.RoleTypeSystem {
		return errors.CannotModifySystemRole()
	}

	return s.roleRepo.RemovePermission(ctx, roleID, permissionID)
}

// GetRolePermissions retrieves permissions for a role
func (s *RoleService) GetRolePermissions(ctx context.Context, roleID types.ID) ([]*domain.Permission, error) {
	return s.roleRepo.GetPermissions(ctx, roleID)
}

// GetPermission retrieves a permission by ID
func (s *RoleService) GetPermission(ctx context.Context, id types.ID) (*domain.Permission, error) {
	return s.permRepo.GetByID(ctx, id)
}

// GetPermissionByCode retrieves a permission by code
func (s *RoleService) GetPermissionByCode(ctx context.Context, code string) (*domain.Permission, error) {
	return s.permRepo.GetByCode(ctx, code)
}

// ListPermissionsInput contains input for listing permissions
type ListPermissionsInput struct {
	Resource *string
	Action   *string
	Category *string
	Page     int
	PageSize int
}

// ListPermissionsResult contains the result of listing permissions
type ListPermissionsResult struct {
	Permissions []*domain.Permission `json:"permissions"`
	Pagination  types.Pagination     `json:"pagination"`
}

// ListPermissions lists permissions with filtering
func (s *RoleService) ListPermissions(ctx context.Context, input ListPermissionsInput) (*ListPermissionsResult, error) {
	pagination := types.DefaultPagination()
	if input.Page > 0 {
		pagination.Page = input.Page
	}
	if input.PageSize > 0 {
		pagination.PageSize = input.PageSize
	}

	filter := repository.PermissionFilter{
		Resource:   input.Resource,
		Action:     input.Action,
		Category:   input.Category,
		Pagination: pagination,
	}

	permissions, total, err := s.permRepo.List(ctx, filter)
	if err != nil {
		return nil, err
	}

	pagination.Total = total

	return &ListPermissionsResult{
		Permissions: permissions,
		Pagination:  pagination,
	}, nil
}

// ListPermissionsByCategory lists permissions by category
func (s *RoleService) ListPermissionsByCategory(ctx context.Context, category string) ([]*domain.Permission, error) {
	return s.permRepo.ListByCategory(ctx, category)
}

// ListPermissionsByResource lists permissions by resource
func (s *RoleService) ListPermissionsByResource(ctx context.Context, resource string) ([]*domain.Permission, error) {
	return s.permRepo.ListByResource(ctx, resource)
}

// CheckPermission checks if a set of roles has a specific permission
func (s *RoleService) CheckPermission(ctx context.Context, roleIDs []types.ID, permissionCode string) (bool, error) {
	for _, roleID := range roleIDs {
		permissions, err := s.roleRepo.GetPermissions(ctx, roleID)
		if err != nil {
			continue
		}
		for _, perm := range permissions {
			if perm.Code == permissionCode {
				return true, nil
			}
		}
	}
	return false, nil
}

// GetAllPermissionsForRoles retrieves all permissions for a set of roles
func (s *RoleService) GetAllPermissionsForRoles(ctx context.Context, roleIDs []types.ID) ([]string, error) {
	permSet := make(map[string]bool)

	for _, roleID := range roleIDs {
		permissions, err := s.roleRepo.GetPermissions(ctx, roleID)
		if err != nil {
			continue
		}
		for _, perm := range permissions {
			permSet[perm.Code] = true
		}
	}

	result := make([]string, 0, len(permSet))
	for perm := range permSet {
		result = append(result, perm)
	}

	return result, nil
}

// CreateOrgRoleInput is the org-scoped variant of CreateRoleInput. Always
// produces an org-bound custom role; permissions are filtered against the
// org_assignable flag. AUDIT C3.
type CreateOrgRoleInput struct {
	Code            string   `json:"code" validate:"required"`
	Name            string   `json:"name" validate:"required"`
	Description     string   `json:"description,omitempty"`
	Level           int      `json:"level,omitempty"`
	PermissionCodes []string `json:"permission_codes,omitempty"`
}

// CreateOrgRole creates a custom role inside an organization with the
// org_assignable safety gate (AUDIT C3). Unlike CreateCustomRole — which is
// open to platform admins building any role — this path refuses to grant
// any permission that isn't flagged org_assignable. It also blocks code
// collisions with seeded system role codes so an org admin can't shadow a
// platform role.
func (s *RoleService) CreateOrgRole(ctx context.Context, orgID types.ID, input CreateOrgRoleInput) (*domain.Role, error) {
	if input.Code == "" || input.Name == "" {
		return nil, errors.InvalidInput("code", "code and name are required")
	}
	if isReservedOrgRoleCode(input.Code) {
		return nil, errors.InvalidInput("code", "role code conflicts with a reserved system role")
	}

	// Resolve permission codes → IDs. Empty list is allowed (an org can
	// pre-create an empty role and grant permissions later via Update).
	var permIDs []types.ID
	if len(input.PermissionCodes) > 0 {
		perms, err := s.permRepo.GetByCodes(ctx, input.PermissionCodes)
		if err != nil {
			return nil, err
		}
		if len(perms) != len(input.PermissionCodes) {
			return nil, errors.InvalidInput("permission_codes", "one or more permission codes do not exist")
		}
		permIDs = make([]types.ID, len(perms))
		for i, p := range perms {
			permIDs[i] = p.ID
		}
		// AUDIT C3 — verify every selected permission is org_assignable.
		rejected, err := s.permRepo.AllOrgAssignable(ctx, permIDs)
		if err != nil {
			return nil, err
		}
		if len(rejected) > 0 {
			return nil, errors.New(errors.ErrCodeForbidden, "one or more permissions are not assignable from a custom org role", 403)
		}
	}

	if _, err := s.orgRepo.GetByID(ctx, orgID); err != nil {
		return nil, err
	}

	role := domain.NewCustomRole(input.Code, input.Name, input.Description, orgID)
	role.Level = input.Level
	if err := s.roleRepo.Create(ctx, role); err != nil {
		return nil, err
	}
	if len(permIDs) > 0 {
		if err := s.roleRepo.SetPermissions(ctx, role.ID, permIDs); err != nil {
			return nil, err
		}
	}
	loaded, _ := s.roleRepo.GetPermissions(ctx, role.ID)
	role.Permissions = derefPermissions(loaded)
	return role, nil
}

// UpdateOrgRoleInput is the org-scoped variant. Same org_assignable gate as
// CreateOrgRole.
type UpdateOrgRoleInput struct {
	Name            *string  `json:"name,omitempty"`
	Description     *string  `json:"description,omitempty"`
	Level           *int     `json:"level,omitempty"`
	PermissionCodes []string `json:"permission_codes,omitempty"` // nil = leave unchanged; empty slice = clear all
}

// UpdateOrgRole updates a custom org role (AUDIT C3). Refuses to touch
// system roles or roles belonging to a different org than the path
// parameter — the caller's RequireOrgContext middleware can't alone protect
// against a malicious roleId from a different org.
func (s *RoleService) UpdateOrgRole(ctx context.Context, orgID, roleID types.ID, input UpdateOrgRoleInput) (*domain.Role, error) {
	role, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		return nil, err
	}
	if role.Type == models.RoleTypeSystem {
		return nil, errors.CannotModifySystemRole()
	}
	if role.OrganizationID == nil || *role.OrganizationID != orgID {
		return nil, errors.NotFound("role")
	}

	if input.Name != nil {
		role.Name = *input.Name
	}
	if input.Description != nil {
		role.Description = *input.Description
	}
	if input.Level != nil {
		role.Level = *input.Level
	}

	if err := s.roleRepo.Update(ctx, role); err != nil {
		return nil, err
	}

	if input.PermissionCodes != nil {
		var permIDs []types.ID
		if len(input.PermissionCodes) > 0 {
			perms, err := s.permRepo.GetByCodes(ctx, input.PermissionCodes)
			if err != nil {
				return nil, err
			}
			if len(perms) != len(input.PermissionCodes) {
				return nil, errors.InvalidInput("permission_codes", "one or more permission codes do not exist")
			}
			permIDs = make([]types.ID, len(perms))
			for i, p := range perms {
				permIDs[i] = p.ID
			}
			rejected, err := s.permRepo.AllOrgAssignable(ctx, permIDs)
			if err != nil {
				return nil, err
			}
			if len(rejected) > 0 {
				return nil, errors.New(errors.ErrCodeForbidden, "one or more permissions are not assignable from a custom org role", 403)
			}
		}
		if err := s.roleRepo.SetPermissions(ctx, role.ID, permIDs); err != nil {
			return nil, err
		}
	}

	loaded, _ := s.roleRepo.GetPermissions(ctx, role.ID)
	role.Permissions = derefPermissions(loaded)
	return role, nil
}

// DeleteOrgRole deletes a custom org role. AUDIT C3 — verifies org binding
// before delete so a malformed roleId from outside the caller's org can't
// be erased. System roles are refused (matches the existing DeleteRole
// shape).
func (s *RoleService) DeleteOrgRole(ctx context.Context, orgID, roleID types.ID) error {
	role, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		return err
	}
	if role.Type == models.RoleTypeSystem {
		return errors.CannotModifySystemRole()
	}
	if role.OrganizationID == nil || *role.OrganizationID != orgID {
		return errors.NotFound("role")
	}
	return s.roleRepo.Delete(ctx, roleID)
}

// ListOrgAssignablePermissions returns the catalog of permissions an org
// admin is allowed to grant via a custom role. AUDIT C3 — this is the UI's
// source for the "pick permissions" picker on the custom-role form.
func (s *RoleService) ListOrgAssignablePermissions(ctx context.Context) ([]*domain.Permission, error) {
	t := true
	pagination := types.DefaultPagination()
	pagination.PageSize = 500 // assignable catalog is small; one page is plenty
	perms, _, err := s.permRepo.List(ctx, repository.PermissionFilter{
		OrgAssignable: &t,
		Pagination:    pagination,
	})
	return perms, err
}

// isReservedOrgRoleCode protects against an org admin creating a custom
// role whose code shadows a seeded system role. We deny rather than allow
// because the unique index permits the collision (org-scoped roles share
// codes with platform roles), but downstream code that resolves role codes
// could pick up the wrong row in an unrelated context.
func isReservedOrgRoleCode(code string) bool {
	switch models.SystemRoleCode(code) {
	case models.RoleSystemAdmin, models.RoleSuperAdmin, models.RoleBaseUser,
		models.RoleOrgAdmin, models.RoleOrgManager, models.RoleOrgMember,
		models.RoleSeller, models.RoleBuyer:
		return true
	}
	return false
}

func derefPermissions(ptrs []*domain.Permission) []domain.Permission {
	result := make([]domain.Permission, len(ptrs))
	for i, p := range ptrs {
		result[i] = *p
	}
	return result
}
