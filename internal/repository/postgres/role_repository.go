package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/lib/pq"
	"github.com/rw3iss/auth/internal/domain"
	"github.com/rw3iss/auth/internal/repository"
	"github.com/rw3iss/auth/pkg/shared/errors"
	"github.com/rw3iss/auth/pkg/shared/models"
	"github.com/rw3iss/auth/pkg/shared/types"
)

// RoleRepository implements repository.RoleRepository
type RoleRepository struct {
	db *DB
}

// NewRoleRepository creates a new role repository
func NewRoleRepository(db *DB) *RoleRepository {
	return &RoleRepository{db: db}
}

// Create creates a new role
func (r *RoleRepository) Create(ctx context.Context, role *domain.Role) error {
	query := `
		INSERT INTO roles (
			id, code, name, description, type, level, is_org_role,
			organization_id, metadata, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`

	q := getQuerier(ctx, r.db)
	_, err := q.ExecContext(ctx, query,
		role.ID, role.Code, role.Name, role.Description, role.Type,
		role.Level, role.IsOrgRole, role.OrganizationID, role.Metadata,
		role.CreatedAt, role.UpdatedAt,
	)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return errors.Conflict(fmt.Sprintf("Role with code '%s' already exists", role.Code))
		}
		return fmt.Errorf("failed to create role: %w", err)
	}
	return nil
}

// GetByID retrieves a role by ID
func (r *RoleRepository) GetByID(ctx context.Context, id types.ID) (*domain.Role, error) {
	query := `
		SELECT id, code, name, description, type, level, is_org_role,
			organization_id, metadata, created_at, updated_at, deleted_at
		FROM roles WHERE id = $1 AND deleted_at IS NULL`

	role := &domain.Role{}
	q := getQuerier(ctx, r.db)
	err := q.GetContext(ctx, role, query, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.RoleNotFound()
		}
		return nil, fmt.Errorf("failed to get role: %w", err)
	}
	return role, nil
}

// GetByCode retrieves a role by code
func (r *RoleRepository) GetByCode(ctx context.Context, code string) (*domain.Role, error) {
	query := `
		SELECT id, code, name, description, type, level, is_org_role,
			organization_id, metadata, created_at, updated_at, deleted_at
		FROM roles WHERE code = $1 AND deleted_at IS NULL`

	role := &domain.Role{}
	q := getQuerier(ctx, r.db)
	err := q.GetContext(ctx, role, query, code)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.RoleNotFound()
		}
		return nil, fmt.Errorf("failed to get role by code: %w", err)
	}
	return role, nil
}

// Update updates a role
func (r *RoleRepository) Update(ctx context.Context, role *domain.Role) error {
	if role.Type == models.RoleTypeSystem {
		return errors.CannotModifySystemRole()
	}

	role.Touch()

	query := `
		UPDATE roles SET
			name = $2, description = $3, level = $4, metadata = $5, updated_at = $6
		WHERE id = $1 AND deleted_at IS NULL AND type = 'custom'`

	q := getQuerier(ctx, r.db)
	result, err := q.ExecContext(ctx, query,
		role.ID, role.Name, role.Description, role.Level, role.Metadata, role.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to update role: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.RoleNotFound()
	}
	return nil
}

// Delete soft deletes a role
func (r *RoleRepository) Delete(ctx context.Context, id types.ID) error {
	// Check if it's a system role
	role, err := r.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if role.Type == models.RoleTypeSystem {
		return errors.CannotModifySystemRole()
	}

	query := `UPDATE roles SET deleted_at = NOW(), updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL AND type = 'custom'`

	q := getQuerier(ctx, r.db)
	result, err := q.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.RoleNotFound()
	}
	return nil
}

// ListSystemRoles lists all system roles
func (r *RoleRepository) ListSystemRoles(ctx context.Context) ([]*domain.Role, error) {
	query := `
		SELECT id, code, name, description, type, level, is_org_role,
			organization_id, metadata, created_at, updated_at, deleted_at
		FROM roles WHERE type = 'system' AND deleted_at IS NULL
		ORDER BY level ASC`

	var roles []*domain.Role
	q := getQuerier(ctx, r.db)
	if err := q.SelectContext(ctx, &roles, query); err != nil {
		return nil, fmt.Errorf("failed to list system roles: %w", err)
	}
	return roles, nil
}

// ListOrgRoles lists roles for a specific organization
func (r *RoleRepository) ListOrgRoles(ctx context.Context, orgID types.ID) ([]*domain.Role, error) {
	query := `
		SELECT id, code, name, description, type, level, is_org_role,
			organization_id, metadata, created_at, updated_at, deleted_at
		FROM roles
		WHERE deleted_at IS NULL AND (
			(type = 'system' AND is_org_role = true) OR
			(type = 'custom' AND organization_id = $1)
		)
		ORDER BY level ASC, name ASC`

	var roles []*domain.Role
	q := getQuerier(ctx, r.db)
	if err := q.SelectContext(ctx, &roles, query, orgID); err != nil {
		return nil, fmt.Errorf("failed to list organization roles: %w", err)
	}
	return roles, nil
}

// ListAll lists all roles with filtering
func (r *RoleRepository) ListAll(ctx context.Context, filter repository.RoleFilter) ([]*domain.Role, int, error) {
	var conditions []string
	var args []interface{}
	argIndex := 1

	conditions = append(conditions, "deleted_at IS NULL")

	if filter.Type != nil {
		conditions = append(conditions, fmt.Sprintf("type = $%d", argIndex))
		args = append(args, *filter.Type)
		argIndex++
	}

	if filter.IsOrgRole != nil {
		conditions = append(conditions, fmt.Sprintf("is_org_role = $%d", argIndex))
		args = append(args, *filter.IsOrgRole)
		argIndex++
	}

	if filter.OrganizationID != nil {
		conditions = append(conditions, fmt.Sprintf("(organization_id = $%d OR organization_id IS NULL)", argIndex))
		args = append(args, *filter.OrganizationID)
		argIndex++
	}

	whereClause := strings.Join(conditions, " AND ")

	// Count query
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM roles WHERE %s", whereClause)
	var total int
	q := getQuerier(ctx, r.db)
	if err := q.GetContext(ctx, &total, countQuery, args...); err != nil {
		return nil, 0, fmt.Errorf("failed to count roles: %w", err)
	}

	// Data query
	query := fmt.Sprintf(`
		SELECT id, code, name, description, type, level, is_org_role,
			organization_id, metadata, created_at, updated_at, deleted_at
		FROM roles WHERE %s
		ORDER BY level ASC, name ASC
		LIMIT $%d OFFSET $%d`,
		whereClause, argIndex, argIndex+1)

	args = append(args, filter.Pagination.PageSize, filter.Pagination.Offset())

	var roles []*domain.Role
	if err := q.SelectContext(ctx, &roles, query, args...); err != nil {
		return nil, 0, fmt.Errorf("failed to list roles: %w", err)
	}

	return roles, total, nil
}

// AssignPermission assigns a permission to a role
func (r *RoleRepository) AssignPermission(ctx context.Context, roleID, permissionID types.ID) error {
	query := `
		INSERT INTO role_permissions (role_id, permission_id)
		VALUES ($1, $2)
		ON CONFLICT (role_id, permission_id) DO NOTHING`

	q := getQuerier(ctx, r.db)
	_, err := q.ExecContext(ctx, query, roleID, permissionID)
	if err != nil {
		return fmt.Errorf("failed to assign permission: %w", err)
	}
	return nil
}

// RemovePermission removes a permission from a role
func (r *RoleRepository) RemovePermission(ctx context.Context, roleID, permissionID types.ID) error {
	query := `DELETE FROM role_permissions WHERE role_id = $1 AND permission_id = $2`

	q := getQuerier(ctx, r.db)
	_, err := q.ExecContext(ctx, query, roleID, permissionID)
	if err != nil {
		return fmt.Errorf("failed to remove permission: %w", err)
	}
	return nil
}

// GetPermissions retrieves permissions assigned to a role
func (r *RoleRepository) GetPermissions(ctx context.Context, roleID types.ID) ([]*domain.Permission, error) {
	query := `
		SELECT p.id, p.code, p.name, p.description, p.resource, p.action, p.category,
			p.metadata, p.created_at, p.updated_at
		FROM permissions p
		INNER JOIN role_permissions rp ON p.id = rp.permission_id
		WHERE rp.role_id = $1`

	var permissions []*domain.Permission
	q := getQuerier(ctx, r.db)
	if err := q.SelectContext(ctx, &permissions, query, roleID); err != nil {
		return nil, fmt.Errorf("failed to get permissions: %w", err)
	}
	return permissions, nil
}

// GetPermissionsForRoles fetches the union of permissions across every role
// in the given list in a single query. Used by the login / refresh / SSO
// hot paths where the previous per-role loop triggered N queries per
// request — AUDIT 4.1.
func (r *RoleRepository) GetPermissionsForRoles(ctx context.Context, roleIDs []types.ID) ([]*domain.Permission, error) {
	if len(roleIDs) == 0 {
		return nil, nil
	}
	// pq's array binding lets us pass the slice directly. DISTINCT on the
	// permission row avoids duplicates when multiple roles share a perm
	// (e.g. org_admin + org_manager both granting the same perm).
	query := `
		SELECT DISTINCT p.id, p.code, p.name, p.description, p.resource, p.action, p.category,
			p.metadata, p.created_at, p.updated_at
		FROM permissions p
		INNER JOIN role_permissions rp ON p.id = rp.permission_id
		WHERE rp.role_id = ANY($1)`

	var permissions []*domain.Permission
	q := getQuerier(ctx, r.db)
	if err := q.SelectContext(ctx, &permissions, query, pq.Array(roleIDs)); err != nil {
		return nil, fmt.Errorf("failed to get permissions for roles: %w", err)
	}
	return permissions, nil
}

// SetPermissions replaces all permissions for a role
func (r *RoleRepository) SetPermissions(ctx context.Context, roleID types.ID, permissionIDs []types.ID) error {
	// Delete existing permissions
	deleteQuery := `DELETE FROM role_permissions WHERE role_id = $1`
	q := getQuerier(ctx, r.db)
	if _, err := q.ExecContext(ctx, deleteQuery, roleID); err != nil {
		return fmt.Errorf("failed to clear permissions: %w", err)
	}

	// Insert new permissions
	if len(permissionIDs) == 0 {
		return nil
	}

	insertQuery := `INSERT INTO role_permissions (role_id, permission_id) VALUES `
	var values []string
	var args []interface{}
	argIndex := 1

	for _, permID := range permissionIDs {
		values = append(values, fmt.Sprintf("($%d, $%d)", argIndex, argIndex+1))
		args = append(args, roleID, permID)
		argIndex += 2
	}

	insertQuery += strings.Join(values, ", ") + " ON CONFLICT (role_id, permission_id) DO NOTHING"
	if _, err := q.ExecContext(ctx, insertQuery, args...); err != nil {
		return fmt.Errorf("failed to set permissions: %w", err)
	}

	return nil
}
