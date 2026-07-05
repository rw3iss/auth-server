package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/ven/auth/internal/domain"
	"github.com/ven/auth/internal/repository"
	"github.com/ven/auth/pkg/shared/errors"
	"github.com/ven/auth/pkg/shared/types"
)

// PermissionRepository implements repository.PermissionRepository
type PermissionRepository struct {
	db *DB
}

// NewPermissionRepository creates a new permission repository
func NewPermissionRepository(db *DB) *PermissionRepository {
	return &PermissionRepository{db: db}
}

// Create creates a new permission
func (r *PermissionRepository) Create(ctx context.Context, permission *domain.Permission) error {
	if permission.Service == "" {
		permission.Service = "core"
	}
	query := `
		INSERT INTO permissions (
			id, code, name, description, resource, action, category, service, org_assignable, metadata, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`

	q := getQuerier(ctx, r.db)
	_, err := q.ExecContext(ctx, query,
		permission.ID, permission.Code, permission.Name, permission.Description,
		permission.Resource, permission.Action, permission.Category, permission.Service, permission.OrgAssignable, permission.Metadata,
		permission.CreatedAt, permission.UpdatedAt,
	)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return errors.Conflict(fmt.Sprintf("Permission with code '%s' already exists", permission.Code))
		}
		return fmt.Errorf("failed to create permission: %w", err)
	}
	return nil
}

// SyncForService reconciles the permission catalog for a given service.
//
// Declarative: the caller passes the full set of permissions the service claims
// to own. The repository:
//   1. Upserts every declared permission (INSERT ... ON CONFLICT (code) DO UPDATE).
//   2. Deletes rows where service = <service> AND code NOT IN (declared codes)
//      so removals in the manifest propagate.
//
// The global UNIQUE(code) constraint protects against two services claiming the
// same code — the second INSERT will update the first one's row (last writer
// wins on metadata), but the `service` column attribution will be overwritten.
// Consider this when naming permissions: use service-unique prefixes if in
// doubt. For the current platform the simple `resource:action` convention is
// sufficient.
//
// NOTE: role_permissions pointing at pruned rows are removed by the schema's
// ON DELETE CASCADE on role_permissions.permission_id — roles automatically
// lose access to removed perms. Make sure that's what you want before calling
// SyncForService with a shrunken list in production.
func (r *PermissionRepository) SyncForService(
	ctx context.Context,
	service string,
	perms []*domain.Permission,
) error {
	if service == "" {
		return fmt.Errorf("service is required")
	}

	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // no-op if committed

	// AUDIT C3: SyncForService now propagates org_assignable. Services that
	// declare a permission MUST set the flag deliberately (default false at
	// the column level keeps unflagged permissions reserved to platform
	// admins). ON CONFLICT preserves the latest service-declared value.
	upsert := `
		INSERT INTO permissions (
			id, code, name, description, resource, action, category, service, org_assignable, metadata, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (code) DO UPDATE SET
			name           = EXCLUDED.name,
			description    = EXCLUDED.description,
			resource       = EXCLUDED.resource,
			action         = EXCLUDED.action,
			category       = EXCLUDED.category,
			service        = EXCLUDED.service,
			org_assignable = EXCLUDED.org_assignable,
			metadata       = EXCLUDED.metadata,
			updated_at     = EXCLUDED.updated_at`

	codes := make([]string, 0, len(perms))
	for _, p := range perms {
		p.Service = service
		if _, err := tx.ExecContext(ctx, upsert,
			p.ID, p.Code, p.Name, p.Description,
			p.Resource, p.Action, p.Category, p.Service, p.OrgAssignable, p.Metadata,
			p.CreatedAt, p.UpdatedAt,
		); err != nil {
			return fmt.Errorf("upsert permission %q: %w", p.Code, err)
		}
		codes = append(codes, p.Code)
	}

	// Prune rows previously owned by this service that are no longer declared.
	if len(codes) == 0 {
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM permissions WHERE service = $1`, service,
		); err != nil {
			return fmt.Errorf("prune service %q: %w", service, err)
		}
	} else {
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM permissions WHERE service = $1 AND code != ALL($2)`,
			service, codes,
		); err != nil {
			return fmt.Errorf("prune service %q: %w", service, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// GetByID retrieves a permission by ID
func (r *PermissionRepository) GetByID(ctx context.Context, id types.ID) (*domain.Permission, error) {
	query := `
		SELECT id, code, name, description, resource, action, category, service, org_assignable, metadata, created_at, updated_at
		FROM permissions WHERE id = $1`

	permission := &domain.Permission{}
	q := getQuerier(ctx, r.db)
	err := q.GetContext(ctx, permission, query, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.NotFound("Permission")
		}
		return nil, fmt.Errorf("failed to get permission: %w", err)
	}
	return permission, nil
}

// GetByCode retrieves a permission by code
func (r *PermissionRepository) GetByCode(ctx context.Context, code string) (*domain.Permission, error) {
	query := `
		SELECT id, code, name, description, resource, action, category, service, org_assignable, metadata, created_at, updated_at
		FROM permissions WHERE code = $1`

	permission := &domain.Permission{}
	q := getQuerier(ctx, r.db)
	err := q.GetContext(ctx, permission, query, code)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.NotFound("Permission")
		}
		return nil, fmt.Errorf("failed to get permission by code: %w", err)
	}
	return permission, nil
}

// List lists permissions with filtering
func (r *PermissionRepository) List(ctx context.Context, filter repository.PermissionFilter) ([]*domain.Permission, int, error) {
	var conditions []string
	var args []interface{}
	argIndex := 1

	if filter.Resource != nil {
		conditions = append(conditions, fmt.Sprintf("resource = $%d", argIndex))
		args = append(args, *filter.Resource)
		argIndex++
	}

	if filter.Action != nil {
		conditions = append(conditions, fmt.Sprintf("action = $%d", argIndex))
		args = append(args, *filter.Action)
		argIndex++
	}

	if filter.Category != nil {
		conditions = append(conditions, fmt.Sprintf("category = $%d", argIndex))
		args = append(args, *filter.Category)
		argIndex++
	}

	if filter.OrgAssignable != nil {
		conditions = append(conditions, fmt.Sprintf("org_assignable = $%d", argIndex))
		args = append(args, *filter.OrgAssignable)
		argIndex++
	}

	whereClause := "1=1"
	if len(conditions) > 0 {
		whereClause = strings.Join(conditions, " AND ")
	}

	// Count query
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM permissions WHERE %s", whereClause)
	var total int
	q := getQuerier(ctx, r.db)
	if err := q.GetContext(ctx, &total, countQuery, args...); err != nil {
		return nil, 0, fmt.Errorf("failed to count permissions: %w", err)
	}

	// Data query
	query := fmt.Sprintf(`
		SELECT id, code, name, description, resource, action, category, service, org_assignable, metadata, created_at, updated_at
		FROM permissions WHERE %s
		ORDER BY category ASC, resource ASC, action ASC
		LIMIT $%d OFFSET $%d`,
		whereClause, argIndex, argIndex+1)

	args = append(args, filter.Pagination.PageSize, filter.Pagination.Offset())

	var permissions []*domain.Permission
	if err := q.SelectContext(ctx, &permissions, query, args...); err != nil {
		return nil, 0, fmt.Errorf("failed to list permissions: %w", err)
	}

	return permissions, total, nil
}

// ListByCategory lists permissions by category
func (r *PermissionRepository) ListByCategory(ctx context.Context, category string) ([]*domain.Permission, error) {
	query := `
		SELECT id, code, name, description, resource, action, category, service, org_assignable, metadata, created_at, updated_at
		FROM permissions WHERE category = $1
		ORDER BY resource ASC, action ASC`

	var permissions []*domain.Permission
	q := getQuerier(ctx, r.db)
	if err := q.SelectContext(ctx, &permissions, query, category); err != nil {
		return nil, fmt.Errorf("failed to list permissions by category: %w", err)
	}
	return permissions, nil
}

// ListByResource lists permissions by resource
func (r *PermissionRepository) ListByResource(ctx context.Context, resource string) ([]*domain.Permission, error) {
	query := `
		SELECT id, code, name, description, resource, action, category, service, org_assignable, metadata, created_at, updated_at
		FROM permissions WHERE resource = $1
		ORDER BY action ASC`

	var permissions []*domain.Permission
	q := getQuerier(ctx, r.db)
	if err := q.SelectContext(ctx, &permissions, query, resource); err != nil {
		return nil, fmt.Errorf("failed to list permissions by resource: %w", err)
	}
	return permissions, nil
}

// GetByIDs retrieves permissions by IDs
func (r *PermissionRepository) GetByIDs(ctx context.Context, ids []types.ID) ([]*domain.Permission, error) {
	if len(ids) == 0 {
		return []*domain.Permission{}, nil
	}

	query := `
		SELECT id, code, name, description, resource, action, category, service, org_assignable, metadata, created_at, updated_at
		FROM permissions WHERE id = ANY($1)`

	var permissions []*domain.Permission
	q := getQuerier(ctx, r.db)
	if err := q.SelectContext(ctx, &permissions, query, ids); err != nil {
		return nil, fmt.Errorf("failed to get permissions by IDs: %w", err)
	}
	return permissions, nil
}

// AllOrgAssignable returns the subset of supplied IDs that are NOT flagged
// org_assignable. The caller treats a non-empty result as a 403 — an org
// admin must not be able to grant platform-scoped permissions via a custom
// role. AUDIT C3.
//
// Returning the offending IDs (rather than a bare bool) lets the caller
// surface a useful error to the operator without revealing the full
// permission catalog.
func (r *PermissionRepository) AllOrgAssignable(ctx context.Context, ids []types.ID) ([]types.ID, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	query := `SELECT id FROM permissions WHERE id = ANY($1) AND org_assignable = FALSE`
	q := getQuerier(ctx, r.db)
	var rejected []types.ID
	if err := q.SelectContext(ctx, &rejected, query, ids); err != nil {
		return nil, fmt.Errorf("check org_assignable: %w", err)
	}
	return rejected, nil
}

// GetByCodes retrieves permissions by codes
func (r *PermissionRepository) GetByCodes(ctx context.Context, codes []string) ([]*domain.Permission, error) {
	if len(codes) == 0 {
		return []*domain.Permission{}, nil
	}

	query := `
		SELECT id, code, name, description, resource, action, category, service, org_assignable, metadata, created_at, updated_at
		FROM permissions WHERE code = ANY($1)`

	var permissions []*domain.Permission
	q := getQuerier(ctx, r.db)
	if err := q.SelectContext(ctx, &permissions, query, codes); err != nil {
		return nil, fmt.Errorf("failed to get permissions by codes: %w", err)
	}
	return permissions, nil
}
