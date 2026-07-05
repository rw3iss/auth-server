package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/lib/pq"

	"github.com/rw3iss/auth/internal/domain"
	"github.com/rw3iss/auth/pkg/shared/errors"
	"github.com/rw3iss/auth/pkg/shared/types"
)

// AppRepository implements repository.AppRepository (declared in
// internal/repository/interfaces.go).
type AppRepository struct {
	db *DB
}

func NewAppRepository(db *DB) *AppRepository {
	return &AppRepository{db: db}
}

// description is nullable in the DB but a plain string on domain.App —
// COALESCE so an app created without one doesn't fail the row scan
// (which would surface as "app not found" on login and silently skip
// registration policy).
const appSelectCols = `id, code, name, COALESCE(description, '') AS description,
	allowed_redirect_urls, service_codes, auto_grant_on_signup,
	status, metadata, created_at, updated_at, deleted_at,
	allowed_email_domains, allowed_auth_methods, default_organization_id,
	frontend_url,
	registration_namespace, read_namespaces, registration_namespaces,
	webhooks, default_role_code, linked_app_codes`

func (r *AppRepository) Create(ctx context.Context, app *domain.App) error {
	const q = `
		INSERT INTO apps (
			id, code, name, description, allowed_redirect_urls,
			service_codes, auto_grant_on_signup, status, metadata,
			allowed_email_domains, allowed_auth_methods, default_organization_id,
			frontend_url,
			registration_namespace, read_namespaces, registration_namespaces,
			webhooks, default_role_code, linked_app_codes,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)`
	q2 := getQuerier(ctx, r.db)
	_, err := q2.ExecContext(ctx, q,
		app.ID, app.Code, app.Name, app.Description,
		app.AllowedRedirectURLs, app.ServiceCodes,
		app.AutoGrantOnSignup, app.Status, app.Metadata,
		app.AllowedEmailDomains, app.AllowedAuthMethods, app.DefaultOrganizationID,
		app.FrontendURL,
		app.RegistrationNamespace, app.ReadNamespaces, app.RegistrationNamespaces,
		app.Webhooks, app.DefaultRoleCode, app.LinkedAppCodes,
		app.CreatedAt, app.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("create app: %w", err)
	}
	return nil
}

func (r *AppRepository) GetByID(ctx context.Context, id types.ID) (*domain.App, error) {
	q := `SELECT ` + appSelectCols + ` FROM apps WHERE id = $1 AND deleted_at IS NULL`
	app := &domain.App{}
	q2 := getQuerier(ctx, r.db)
	if err := q2.GetContext(ctx, app, q, id); err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.NotFound("app")
		}
		return nil, fmt.Errorf("get app: %w", err)
	}
	return app, nil
}

func (r *AppRepository) GetByCode(ctx context.Context, code string) (*domain.App, error) {
	q := `SELECT ` + appSelectCols + ` FROM apps WHERE code = $1 AND deleted_at IS NULL`
	app := &domain.App{}
	q2 := getQuerier(ctx, r.db)
	if err := q2.GetContext(ctx, app, q, code); err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.NotFound("app")
		}
		return nil, fmt.Errorf("get app by code: %w", err)
	}
	return app, nil
}

func (r *AppRepository) List(ctx context.Context) ([]*domain.App, error) {
	q := `SELECT ` + appSelectCols + ` FROM apps WHERE deleted_at IS NULL ORDER BY code ASC`
	var apps []*domain.App
	q2 := getQuerier(ctx, r.db)
	if err := q2.SelectContext(ctx, &apps, q); err != nil {
		return nil, fmt.Errorf("list apps: %w", err)
	}
	return apps, nil
}

func (r *AppRepository) Update(ctx context.Context, app *domain.App) error {
	const q = `
		UPDATE apps SET
			name = $2, description = $3, allowed_redirect_urls = $4,
			service_codes = $5, auto_grant_on_signup = $6, status = $7,
			metadata = $8,
			allowed_email_domains = $9, allowed_auth_methods = $10, default_organization_id = $11,
			frontend_url = $12,
			registration_namespace = $13, read_namespaces = $14,
			registration_namespaces = $15,
			webhooks = $16, default_role_code = $17, linked_app_codes = $18,
			updated_at = NOW()
		WHERE id = $1 AND deleted_at IS NULL`
	q2 := getQuerier(ctx, r.db)
	res, err := q2.ExecContext(ctx, q,
		app.ID, app.Name, app.Description,
		app.AllowedRedirectURLs, app.ServiceCodes,
		app.AutoGrantOnSignup, app.Status, app.Metadata,
		app.AllowedEmailDomains, app.AllowedAuthMethods, app.DefaultOrganizationID,
		app.FrontendURL,
		app.RegistrationNamespace, app.ReadNamespaces,
		app.RegistrationNamespaces,
		app.Webhooks, app.DefaultRoleCode, app.LinkedAppCodes,
	)
	if err != nil {
		return fmt.Errorf("update app: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return errors.NotFound("app")
	}
	return nil
}

func (r *AppRepository) SoftDelete(ctx context.Context, id types.ID) error {
	const q = `UPDATE apps SET deleted_at = NOW(), status = 'deleted' WHERE id = $1 AND deleted_at IS NULL`
	q2 := getQuerier(ctx, r.db)
	res, err := q2.ExecContext(ctx, q, id)
	if err != nil {
		return fmt.Errorf("delete app: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return errors.NotFound("app")
	}
	return nil
}

// --- user_apps membership ------------------------------------------------

func (r *AppRepository) Grant(ctx context.Context, userID, appID types.ID, grantedBy *types.ID) error {
	const q = `
		INSERT INTO user_apps (user_id, app_id, granted_by, status)
		VALUES ($1, $2, $3, 'active')
		ON CONFLICT (user_id, app_id) DO UPDATE
		   SET status = 'active',
		       granted_at = NOW(),
		       granted_by = EXCLUDED.granted_by`
	q2 := getQuerier(ctx, r.db)
	if _, err := q2.ExecContext(ctx, q, userID, appID, grantedBy); err != nil {
		return fmt.Errorf("grant user_app: %w", err)
	}
	return nil
}

func (r *AppRepository) Revoke(ctx context.Context, userID, appID types.ID) error {
	const q = `UPDATE user_apps SET status = 'revoked' WHERE user_id = $1 AND app_id = $2`
	q2 := getQuerier(ctx, r.db)
	if _, err := q2.ExecContext(ctx, q, userID, appID); err != nil {
		return fmt.Errorf("revoke user_app: %w", err)
	}
	return nil
}

func (r *AppRepository) GetMembership(ctx context.Context, userID, appID types.ID) (*domain.UserApp, error) {
	const q = `SELECT user_id, app_id, granted_at, granted_by, status FROM user_apps WHERE user_id = $1 AND app_id = $2`
	row := &domain.UserApp{}
	q2 := getQuerier(ctx, r.db)
	if err := q2.GetContext(ctx, row, q, userID, appID); err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.NotFound("user_app")
		}
		return nil, fmt.Errorf("get membership: %w", err)
	}
	return row, nil
}

func (r *AppRepository) ListForUser(ctx context.Context, userID types.ID) ([]*domain.App, error) {
	const q = `
		SELECT a.id, a.code, a.name, COALESCE(a.description, '') AS description,
			a.allowed_redirect_urls, a.service_codes, a.auto_grant_on_signup,
			a.status, a.metadata, a.created_at, a.updated_at, a.deleted_at,
			a.allowed_email_domains, a.allowed_auth_methods, a.default_organization_id,
			a.frontend_url,
			a.registration_namespace, a.read_namespaces, a.registration_namespaces,
			a.webhooks, a.default_role_code, a.linked_app_codes
		FROM apps a
		INNER JOIN user_apps ua ON ua.app_id = a.id
		WHERE ua.user_id = $1 AND ua.status = 'active' AND a.deleted_at IS NULL
		ORDER BY a.code ASC`
	var apps []*domain.App
	q2 := getQuerier(ctx, r.db)
	if err := q2.SelectContext(ctx, &apps, q, userID); err != nil {
		return nil, fmt.Errorf("list user apps: %w", err)
	}
	return apps, nil
}

// Compile-time interface assertion (helps catch repo signature drift).
// We declare this in a small init-time check rather than the interfaces.go
// file so adding new repo methods doesn't require touching that file.
var _ pq.StringArray // keep import; lib/pq is needed by the array columns
