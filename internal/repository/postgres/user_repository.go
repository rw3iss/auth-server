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
	"github.com/rw3iss/auth/pkg/shared/types"
)

// userSortAllowlist enumerates the columns we accept in ORDER BY for the
// admin users-list endpoint. AUDIT 1.21: any column not in this list falls
// back to the default in resolveSort, closing the SQL injection vector.
var userSortAllowlist = []string{
	"created_at", "updated_at", "email", "first_name", "last_name",
	"display_name", "status", "last_login_at",
}

// UserRepository implements repository.UserRepository
type UserRepository struct {
	db *DB
}

// NewUserRepository creates a new user repository
func NewUserRepository(db *DB) *UserRepository {
	return &UserRepository{db: db}
}

// Create creates a new user
func (r *UserRepository) Create(ctx context.Context, user *domain.User) error {
	query := `
		INSERT INTO users (
			id, email, email_verified, phone, phone_verified,
			first_name, last_name, display_name, avatar_url, status,
			password_hash, auth_provider, provider_user_id,
			two_factor_enabled, two_factor_secret, two_factor_confirmed_at, failed_login_attempts,
			locked_until, last_password_change, metadata,
			created_at, updated_at, namespace
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
			$11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23
		)`

	ns := user.Namespace
	if ns == "" {
		ns = domain.DefaultNamespace
	}
	q := getQuerier(ctx, r.db)
	_, err := q.ExecContext(ctx, query,
		user.ID, user.Email, user.EmailVerified, user.Phone, user.PhoneVerified,
		user.FirstName, user.LastName, user.DisplayName, user.AvatarURL, user.Status,
		user.PasswordHash, user.AuthProvider, user.ProviderUserID,
		user.TwoFactorEnabled, user.TwoFactorSecret, NullTime(user.TwoFactorConfirmedAt), user.FailedLoginAttempts,
		NullTime(user.LockedUntil), NullTime(user.LastPasswordChange), user.Metadata,
		user.CreatedAt, user.UpdatedAt, ns,
	)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return errors.UserAlreadyExists(string(user.Email))
		}
		return fmt.Errorf("failed to create user: %w", err)
	}
	return nil
}

// GetByID retrieves a user by ID
func (r *UserRepository) GetByID(ctx context.Context, id types.ID) (*domain.User, error) {
	query := `
		SELECT id, email, email_verified, COALESCE(phone, '') AS phone, phone_verified,
			first_name, last_name, COALESCE(display_name, '') AS display_name, COALESCE(avatar_url, '') AS avatar_url, status,
			COALESCE(password_hash, '') AS password_hash, auth_provider, COALESCE(provider_user_id, '') AS provider_user_id,
			two_factor_enabled, COALESCE(two_factor_secret, '') AS two_factor_secret, two_factor_confirmed_at, failed_login_attempts,
			locked_until, last_password_change, last_login_at, password_reset_at,
			metadata, created_at, updated_at, deleted_at, namespace
		FROM users WHERE id = $1 AND deleted_at IS NULL`

	user := &domain.User{}
	q := getQuerier(ctx, r.db)
	err := q.GetContext(ctx, user, query, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.UserNotFound()
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return user, nil
}

// GetByEmail retrieves a user by email from the DEFAULT namespace.
//
// Migration 017: email is unique per (namespace, email), so a bare
// email can match multiple pools. This legacy/global accessor resolves
// the `default` pool only — the population that predates user pools and
// the flows still scoped to it (SSO upsert, password-reset-request,
// check-email). Namespace-aware auth uses GetByEmailInNamespaces.
func (r *UserRepository) GetByEmail(ctx context.Context, email types.Email) (*domain.User, error) {
	query := `
		SELECT id, email, email_verified, COALESCE(phone, '') AS phone, phone_verified,
			first_name, last_name, COALESCE(display_name, '') AS display_name, COALESCE(avatar_url, '') AS avatar_url, status,
			COALESCE(password_hash, '') AS password_hash, auth_provider, COALESCE(provider_user_id, '') AS provider_user_id,
			two_factor_enabled, COALESCE(two_factor_secret, '') AS two_factor_secret, two_factor_confirmed_at, failed_login_attempts,
			locked_until, last_password_change, last_login_at, password_reset_at,
			metadata, created_at, updated_at, deleted_at, namespace
		FROM users WHERE LOWER(email) = LOWER($1) AND namespace = $2 AND deleted_at IS NULL`

	user := &domain.User{}
	q := getQuerier(ctx, r.db)
	err := q.GetContext(ctx, user, query, email, domain.DefaultNamespace)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.UserNotFound()
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}
	return user, nil
}

// GetByEmailInNamespaces resolves a user by email within a set of user
// pools (migrations 017 + 018 / docs/USER_POOLS.md). Used by login +
// register to authenticate against an app's read namespaces. A user
// matches when their HOME namespace (users.namespace) OR any
// user_namespaces membership intersects the set. When the email
// exists in more than one readable pool, the home-namespace match
// earliest in `namespaces` wins (callers pass write namespaces first),
// then the oldest account — fully deterministic.
func (r *UserRepository) GetByEmailInNamespaces(ctx context.Context, email types.Email, namespaces []string) (*domain.User, error) {
	if len(namespaces) == 0 {
		namespaces = []string{domain.DefaultNamespace}
	}
	query := `
		SELECT id, email, email_verified, COALESCE(phone, '') AS phone, phone_verified,
			first_name, last_name, COALESCE(display_name, '') AS display_name, COALESCE(avatar_url, '') AS avatar_url, status,
			COALESCE(password_hash, '') AS password_hash, auth_provider, COALESCE(provider_user_id, '') AS provider_user_id,
			two_factor_enabled, COALESCE(two_factor_secret, '') AS two_factor_secret, two_factor_confirmed_at, failed_login_attempts,
			locked_until, last_password_change, last_login_at, password_reset_at,
			metadata, created_at, updated_at, deleted_at, namespace
		FROM users u
		WHERE LOWER(u.email) = LOWER($1) AND u.deleted_at IS NULL
		  AND (u.namespace = ANY($2)
		       OR EXISTS (SELECT 1 FROM user_namespaces un
		                  WHERE un.user_id = u.id AND un.namespace = ANY($2)))
		ORDER BY array_position($2::text[], u.namespace) ASC NULLS LAST, u.created_at ASC
		LIMIT 1`

	user := &domain.User{}
	q := getQuerier(ctx, r.db)
	err := q.GetContext(ctx, user, query, email, pq.Array(namespaces))
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.UserNotFound()
		}
		return nil, fmt.Errorf("failed to get user by email in namespaces: %w", err)
	}
	return user, nil
}

// AddUserToNamespaces tags a user as a member of additional pools
// beyond their home namespace (migration 018). Idempotent — existing
// memberships are skipped. The home namespace itself needs no row
// (lookups match home OR membership), but inserting it is harmless.
func (r *UserRepository) AddUserToNamespaces(ctx context.Context, userID types.ID, namespaces []string) error {
	if len(namespaces) == 0 {
		return nil
	}
	const query = `
		INSERT INTO user_namespaces (user_id, namespace)
		SELECT $1, unnest($2::text[])
		ON CONFLICT (user_id, namespace) DO NOTHING`
	q := getQuerier(ctx, r.db)
	if _, err := q.ExecContext(ctx, query, userID, pq.Array(namespaces)); err != nil {
		return fmt.Errorf("failed to add user namespaces: %w", err)
	}
	return nil
}

// GetUserNamespaces returns every pool a user belongs to: their home
// namespace first, then membership rows (sorted). Migration 018.
func (r *UserRepository) GetUserNamespaces(ctx context.Context, userID types.ID) ([]string, error) {
	const query = `
		SELECT ns FROM (
			SELECT namespace AS ns, 0 AS ord FROM users WHERE id = $1
			UNION
			SELECT namespace AS ns, 1 AS ord FROM user_namespaces WHERE user_id = $1
		) t
		GROUP BY ns ORDER BY MIN(ord), ns`
	var out []string
	q := getQuerier(ctx, r.db)
	if err := q.SelectContext(ctx, &out, query, userID); err != nil {
		return nil, fmt.Errorf("failed to get user namespaces: %w", err)
	}
	return out, nil
}

// RemoveUserFromNamespace deletes a pool tag. Idempotent — removing a
// tag the user doesn't hold is a no-op. The home pool lives in
// users.namespace and is never touched here.
func (r *UserRepository) RemoveUserFromNamespace(ctx context.Context, userID types.ID, namespace string) error {
	const query = `DELETE FROM user_namespaces WHERE user_id = $1 AND namespace = $2`
	q := getQuerier(ctx, r.db)
	if _, err := q.ExecContext(ctx, query, userID, namespace); err != nil {
		return fmt.Errorf("failed to remove user namespace: %w", err)
	}
	return nil
}

// SetHomeNamespace moves a user's home pool. Email is unique per
// (namespace, email) — a unique-violation on the target pool surfaces
// as Conflict so admins get an actionable message instead of a 500.
// A tag row matching the new home pool is redundant and cleaned up.
func (r *UserRepository) SetHomeNamespace(ctx context.Context, userID types.ID, namespace string) error {
	q := getQuerier(ctx, r.db)
	res, err := q.ExecContext(ctx,
		`UPDATE users SET namespace = $2, updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL`,
		userID, namespace)
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			return errors.Conflict("a user with this email already exists in pool '" + namespace + "'")
		}
		return fmt.Errorf("failed to set home namespace: %w", err)
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return errors.UserNotFound()
	}
	_, err = q.ExecContext(ctx,
		`DELETE FROM user_namespaces WHERE user_id = $1 AND namespace = $2`,
		userID, namespace)
	if err != nil {
		return fmt.Errorf("failed to clean redundant namespace tag: %w", err)
	}
	return nil
}

// ListNamespaces aggregates every known pool with user counts and the
// app codes whose pool config references it. FULL OUTER JOIN so pools
// that exist only in app configs (zero users) still appear — the admin
// UI flags those as empty.
func (r *UserRepository) ListNamespaces(ctx context.Context) ([]*repository.NamespaceInfo, error) {
	const query = `
		WITH user_pools AS (
			SELECT u.namespace AS ns, u.id AS user_id, TRUE AS is_home
			FROM users u WHERE u.deleted_at IS NULL
			UNION ALL
			SELECT un.namespace, un.user_id, FALSE
			FROM user_namespaces un
			JOIN users u ON u.id = un.user_id AND u.deleted_at IS NULL
		),
		counts AS (
			SELECT ns,
				COUNT(DISTINCT user_id)                          AS user_count,
				COUNT(DISTINCT user_id) FILTER (WHERE is_home)   AS home_count,
				COUNT(DISTINCT user_id) FILTER (WHERE NOT is_home) AS tag_count
			FROM user_pools GROUP BY ns
		),
		app_pools AS (
			SELECT ns, array_agg(DISTINCT code ORDER BY code) AS app_codes FROM (
				SELECT registration_namespace AS ns, code FROM apps
					WHERE deleted_at IS NULL AND registration_namespace IS NOT NULL
				UNION
				SELECT unnest(registration_namespaces), code FROM apps WHERE deleted_at IS NULL
				UNION
				SELECT unnest(read_namespaces), code FROM apps WHERE deleted_at IS NULL
			) a WHERE ns <> '' GROUP BY ns
		)
		SELECT COALESCE(c.ns, a.ns)        AS namespace,
			COALESCE(c.user_count, 0)      AS user_count,
			COALESCE(c.home_count, 0)      AS home_count,
			COALESCE(c.tag_count, 0)       AS tag_count,
			COALESCE(a.app_codes, '{}')    AS app_codes
		FROM counts c
		FULL OUTER JOIN app_pools a ON a.ns = c.ns
		ORDER BY 1`
	var out []*repository.NamespaceInfo
	q := getQuerier(ctx, r.db)
	if err := q.SelectContext(ctx, &out, query); err != nil {
		return nil, fmt.Errorf("failed to list namespaces: %w", err)
	}
	return out, nil
}

// Update updates a user
func (r *UserRepository) Update(ctx context.Context, user *domain.User) error {
	user.Touch()

	query := `
		UPDATE users SET
			email = $2, email_verified = $3, phone = $4, phone_verified = $5,
			first_name = $6, last_name = $7, display_name = $8, avatar_url = $9,
			status = $10, password_hash = $11, auth_provider = $12, provider_user_id = $13,
			two_factor_enabled = $14, two_factor_secret = $15, two_factor_confirmed_at = $16,
			failed_login_attempts = $17,
			locked_until = $18, last_password_change = $19, last_login_at = $20,
			password_reset_at = $21, metadata = $22, updated_at = $23
		WHERE id = $1 AND deleted_at IS NULL`

	q := getQuerier(ctx, r.db)
	result, err := q.ExecContext(ctx, query,
		user.ID, user.Email, user.EmailVerified, user.Phone, user.PhoneVerified,
		user.FirstName, user.LastName, user.DisplayName, user.AvatarURL,
		user.Status, user.PasswordHash, user.AuthProvider, user.ProviderUserID,
		user.TwoFactorEnabled, user.TwoFactorSecret, NullTime(user.TwoFactorConfirmedAt),
		user.FailedLoginAttempts,
		NullTime(user.LockedUntil), NullTime(user.LastPasswordChange),
		NullTime(user.LastLoginAt), NullTime(user.PasswordResetAt),
		user.Metadata, user.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.UserNotFound()
	}
	return nil
}

// Delete soft deletes a user
func (r *UserRepository) Delete(ctx context.Context, id types.ID) error {
	query := `UPDATE users SET deleted_at = NOW(), updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL`

	q := getQuerier(ctx, r.db)
	result, err := q.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.UserNotFound()
	}
	return nil
}

// HardDelete physically removes the user row (AUDIT C8). Migration 011
// relaxed the audit-preserving FKs to ON DELETE SET NULL so historical
// audit_log / invitation rows survive with NULL pointers. CASCADE FKs on
// refresh_tokens / sessions / org memberships / user_base_roles /
// password_reset_tokens / email_verification_tokens / user_auth_providers
// / user_apps remove the dependent rows automatically.
//
// Caller MUST verify the user does not own an organization before invoking
// this — organizations.owner_id has NO action FK, so a hard-delete with
// owned orgs surfaces a 23503 foreign-key violation from Postgres.
func (r *UserRepository) HardDelete(ctx context.Context, id types.ID) error {
	q := getQuerier(ctx, r.db)
	result, err := q.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("failed to hard-delete user: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.UserNotFound()
	}
	return nil
}

// CountOwnedOrganizations returns the number of organizations where this
// user is recorded as the owner. Used as a pre-flight check before
// HardDelete so the caller can return a clean 409 / explanatory error
// rather than a raw Postgres FK-violation error.
func (r *UserRepository) CountOwnedOrganizations(ctx context.Context, id types.ID) (int, error) {
	q := getQuerier(ctx, r.db)
	var count int
	err := q.GetContext(ctx, &count, `SELECT COUNT(*) FROM organizations WHERE owner_id = $1 AND deleted_at IS NULL`, id)
	if err != nil {
		return 0, fmt.Errorf("count owned orgs: %w", err)
	}
	return count, nil
}

// List lists users with filtering
func (r *UserRepository) List(ctx context.Context, filter repository.UserFilter) ([]*domain.User, int, error) {
	var conditions []string
	var args []interface{}
	argIndex := 1

	conditions = append(conditions, "deleted_at IS NULL")

	if filter.Status != nil {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIndex))
		args = append(args, *filter.Status)
		argIndex++
	}

	if filter.EmailVerified != nil {
		conditions = append(conditions, fmt.Sprintf("email_verified = $%d", argIndex))
		args = append(args, *filter.EmailVerified)
		argIndex++
	}

	if filter.AuthProvider != nil {
		conditions = append(conditions, fmt.Sprintf("auth_provider = $%d", argIndex))
		args = append(args, *filter.AuthProvider)
		argIndex++
	}

	// Membership filters. These were silently dropped pre-2026-06-10
	// (the handler parsed organization_id but nothing applied it; the
	// /admin/users page appeared to ignore its filters entirely).
	if filter.OrganizationID != nil {
		conditions = append(conditions, fmt.Sprintf(
			"id IN (SELECT user_id FROM organization_members WHERE organization_id = $%d AND status = 'active')", argIndex))
		args = append(args, *filter.OrganizationID)
		argIndex++
	}

	if filter.AppID != nil {
		conditions = append(conditions, fmt.Sprintf(
			"id IN (SELECT user_id FROM user_apps WHERE app_id = $%d AND status = 'active')", argIndex))
		args = append(args, *filter.AppID)
		argIndex++
	}

	whereClause := strings.Join(conditions, " AND ")

	// Count query
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM users WHERE %s", whereClause)
	var total int
	q := getQuerier(ctx, r.db)
	if err := q.GetContext(ctx, &total, countQuery, args...); err != nil {
		return nil, 0, fmt.Errorf("failed to count users: %w", err)
	}

	// AUDIT 1.21: validate sort_by against an allowlist before interpolating
	// into the ORDER BY clause. Anything else falls back to created_at.
	sortBy, sortOrd := resolveSort(filter.SortBy, "created_at", string(filter.SortOrder), userSortAllowlist)

	query := fmt.Sprintf(`
		SELECT id, email, email_verified, COALESCE(phone, '') AS phone, phone_verified,
			first_name, last_name, COALESCE(display_name, '') AS display_name, COALESCE(avatar_url, '') AS avatar_url, status,
			COALESCE(password_hash, '') AS password_hash, auth_provider, COALESCE(provider_user_id, '') AS provider_user_id,
			two_factor_enabled, COALESCE(two_factor_secret, '') AS two_factor_secret, two_factor_confirmed_at, failed_login_attempts,
			locked_until, last_password_change, last_login_at, password_reset_at,
			metadata, created_at, updated_at, deleted_at, namespace
		FROM users WHERE %s
		ORDER BY %s %s
		LIMIT $%d OFFSET $%d`,
		whereClause, sortBy, sortOrd, argIndex, argIndex+1)

	args = append(args, filter.Pagination.PageSize, filter.Pagination.Offset())

	var users []*domain.User
	if err := q.SelectContext(ctx, &users, query, args...); err != nil {
		return nil, 0, fmt.Errorf("failed to list users: %w", err)
	}

	return users, total, nil
}

// Search searches for users
func (r *UserRepository) Search(ctx context.Context, query string, pagination types.Pagination) ([]*domain.User, int, error) {
	searchQuery := "%" + strings.ToLower(query) + "%"

	countSQL := `
		SELECT COUNT(*) FROM users
		WHERE deleted_at IS NULL AND (
			LOWER(email) LIKE $1 OR
			LOWER(first_name) LIKE $1 OR
			LOWER(last_name) LIKE $1 OR
			LOWER(display_name) LIKE $1
		)`

	var total int
	q := getQuerier(ctx, r.db)
	if err := q.GetContext(ctx, &total, countSQL, searchQuery); err != nil {
		return nil, 0, fmt.Errorf("failed to count search results: %w", err)
	}

	dataSQL := `
		SELECT id, email, email_verified, COALESCE(phone, '') AS phone, phone_verified,
			first_name, last_name, COALESCE(display_name, '') AS display_name, COALESCE(avatar_url, '') AS avatar_url, status,
			auth_provider, created_at, updated_at
		FROM users
		WHERE deleted_at IS NULL AND (
			LOWER(email) LIKE $1 OR
			LOWER(first_name) LIKE $1 OR
			LOWER(last_name) LIKE $1 OR
			LOWER(display_name) LIKE $1
		)
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3`

	var users []*domain.User
	if err := q.SelectContext(ctx, &users, dataSQL, searchQuery, pagination.PageSize, pagination.Offset()); err != nil {
		return nil, 0, fmt.Errorf("failed to search users: %w", err)
	}

	return users, total, nil
}

// Lookup resolves a batch of users by email and/or id in a single round-trip.
//
// Implementation uses `LOWER(email) = ANY($1::text[]) OR id = ANY($2::uuid[])`
// so a single query handles both inputs without dynamic SQL assembly (no
// injection surface). Either array may be empty; if both are empty we
// short-circuit without touching the DB. Soft-deleted users are excluded
// to keep the contract identical to GetByID / GetByEmail.
//
// Case-insensitivity: this codebase doesn't install the citext extension
// (migration 001 only adds uuid-ossp), so we can't rely on a citext column
// type. We normalise both sides instead — the caller normalises input
// emails via service.AuthService.NormalizeEmail (lowercase), and the SQL
// applies LOWER() to the stored column. Cheap; the users table is small
// enough that the sequential LOWER() per row is negligible against the
// bulk-lookup workload (admin tooling, ≤ 200 keys per call).
//
// Output is a flat []*domain.User. Duplicates across the two inputs (an
// email and id pointing at the same row) collapse — we rely on the natural
// uniqueness of the user PK for that, not application-level dedup.
func (r *UserRepository) Lookup(ctx context.Context, emails []types.Email, ids []types.ID) ([]*domain.User, error) {
	if len(emails) == 0 && len(ids) == 0 {
		return []*domain.User{}, nil
	}

	// Postgres array binding via lib/pq is awkward when one side is
	// empty; we bind an empty slice as `'{}'::type[]` which makes
	// `ANY(empty)` evaluate to false — so the combined predicate just
	// reduces to the non-empty side.
	emailStrs := make([]string, len(emails))
	for i, e := range emails {
		emailStrs[i] = strings.ToLower(string(e))
	}
	idStrs := make([]string, len(ids))
	for i, id := range ids {
		idStrs[i] = id.String()
	}

	query := `
		SELECT id, email, email_verified, COALESCE(phone, '') AS phone, phone_verified,
			first_name, last_name, COALESCE(display_name, '') AS display_name, COALESCE(avatar_url, '') AS avatar_url, status,
			COALESCE(password_hash, '') AS password_hash, auth_provider, COALESCE(provider_user_id, '') AS provider_user_id,
			two_factor_enabled, COALESCE(two_factor_secret, '') AS two_factor_secret, two_factor_confirmed_at, failed_login_attempts,
			locked_until, last_password_change, last_login_at, password_reset_at,
			metadata, created_at, updated_at, deleted_at, namespace
		FROM users
		WHERE deleted_at IS NULL
		  AND (LOWER(email) = ANY($1::text[]) OR id = ANY($2::uuid[]))
		ORDER BY created_at DESC`

	var users []*domain.User
	q := getQuerier(ctx, r.db)
	err := q.SelectContext(ctx, &users, query, pqStringArray(emailStrs), pqStringArray(idStrs))
	if err != nil {
		return nil, fmt.Errorf("failed to lookup users: %w", err)
	}
	return users, nil
}

// pqStringArray formats a Go slice as a Postgres-array literal. Defined
// inline so we don't pull lib/pq's Array helper into this file's import
// surface — the same string form `'{"a","b"}'` works with sqlx through
// CITEXT[] / UUID[] casts.
func pqStringArray(items []string) interface{} {
	if len(items) == 0 {
		return "{}"
	}
	// Escape per Postgres array literal rules: " → \" , \ → \\.
	escaped := make([]string, len(items))
	for i, s := range items {
		s = strings.ReplaceAll(s, `\`, `\\`)
		s = strings.ReplaceAll(s, `"`, `\"`)
		escaped[i] = `"` + s + `"`
	}
	return "{" + strings.Join(escaped, ",") + "}"
}

// GetByProviderID retrieves a user by SSO provider and provider user ID
func (r *UserRepository) GetByProviderID(ctx context.Context, provider types.AuthProvider, providerUserID string) (*domain.User, error) {
	query := `
		SELECT u.id, u.email, u.email_verified, COALESCE(u.phone, '') AS phone, u.phone_verified,
			u.first_name, u.last_name, COALESCE(u.display_name, '') AS display_name, COALESCE(u.avatar_url, '') AS avatar_url, u.status,
			COALESCE(u.password_hash, '') AS password_hash, u.auth_provider, COALESCE(u.provider_user_id, '') AS provider_user_id,
			u.two_factor_enabled, COALESCE(u.two_factor_secret, '') AS two_factor_secret, u.two_factor_confirmed_at, u.failed_login_attempts,
			u.locked_until, u.last_password_change, u.last_login_at, u.password_reset_at,
			u.metadata, u.created_at, u.updated_at, u.deleted_at
		FROM users u
		INNER JOIN user_auth_providers uap ON u.id = uap.user_id
		WHERE uap.provider = $1 AND uap.provider_user_id = $2 AND u.deleted_at IS NULL`

	user := &domain.User{}
	q := getQuerier(ctx, r.db)
	err := q.GetContext(ctx, user, query, provider, providerUserID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.UserNotFound()
		}
		return nil, fmt.Errorf("failed to get user by provider: %w", err)
	}
	return user, nil
}

// LinkProvider links an authentication provider to a user
func (r *UserRepository) LinkProvider(ctx context.Context, link *domain.UserAuthProvider) error {
	query := `
		INSERT INTO user_auth_providers (
			id, user_id, provider, provider_user_id,
			access_token, refresh_token, token_expiry, provider_data,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (user_id, provider) DO UPDATE SET
			provider_user_id = EXCLUDED.provider_user_id,
			access_token = EXCLUDED.access_token,
			refresh_token = EXCLUDED.refresh_token,
			token_expiry = EXCLUDED.token_expiry,
			provider_data = EXCLUDED.provider_data,
			updated_at = EXCLUDED.updated_at`

	q := getQuerier(ctx, r.db)
	_, err := q.ExecContext(ctx, query,
		link.ID, link.UserID, link.Provider, link.ProviderUserID,
		link.AccessToken, link.RefreshToken, NullTime(link.TokenExpiry), link.ProviderData,
		link.CreatedAt, link.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to link provider: %w", err)
	}
	return nil
}

// UnlinkProvider removes an authentication provider link
func (r *UserRepository) UnlinkProvider(ctx context.Context, userID types.ID, provider types.AuthProvider) error {
	query := `DELETE FROM user_auth_providers WHERE user_id = $1 AND provider = $2`

	q := getQuerier(ctx, r.db)
	_, err := q.ExecContext(ctx, query, userID, provider)
	if err != nil {
		return fmt.Errorf("failed to unlink provider: %w", err)
	}
	return nil
}

// GetUserProviders retrieves all authentication providers for a user
func (r *UserRepository) GetUserProviders(ctx context.Context, userID types.ID) ([]*domain.UserAuthProvider, error) {
	query := `
		SELECT id, user_id, provider, provider_user_id, token_expiry, created_at, updated_at
		FROM user_auth_providers WHERE user_id = $1`

	var providers []*domain.UserAuthProvider
	q := getQuerier(ctx, r.db)
	if err := q.SelectContext(ctx, &providers, query, userID); err != nil {
		return nil, fmt.Errorf("failed to get user providers: %w", err)
	}
	return providers, nil
}

// GetBaseRoles retrieves base roles assigned to a user
func (r *UserRepository) GetBaseRoles(ctx context.Context, userID types.ID) ([]*domain.Role, error) {
	query := `
		SELECT r.id, r.code, r.name, r.description, r.type, r.level, r.is_org_role,
			r.organization_id, r.metadata, r.created_at, r.updated_at, r.deleted_at
		FROM roles r
		INNER JOIN user_base_roles ubr ON r.id = ubr.role_id
		WHERE ubr.user_id = $1 AND r.deleted_at IS NULL`

	var roles []*domain.Role
	q := getQuerier(ctx, r.db)
	if err := q.SelectContext(ctx, &roles, query, userID); err != nil {
		return nil, fmt.Errorf("failed to get base roles: %w", err)
	}
	return roles, nil
}

// GetBaseRolesByUserIDs fetches base roles for a batch of user IDs
// in a single round-trip. Backs /admin/users list, where we want
// every row to carry its assigned roles without an N+1 fan-out.
//
// Returns a map keyed by user ID; users with no base roles are
// present with an empty slice so callers can render "(none)" without
// distinguishing between "no roles" and "user not in map".
func (r *UserRepository) GetBaseRolesByUserIDs(ctx context.Context, userIDs []types.ID) (map[types.ID][]*domain.Role, error) {
	out := make(map[types.ID][]*domain.Role, len(userIDs))
	for _, id := range userIDs {
		out[id] = nil
	}
	if len(userIDs) == 0 {
		return out, nil
	}

	// Wrap the UUID slice in pq.Array so lib/pq can bind it to the
	// ANY($1) clause — bare []types.ID won't marshal correctly.
	// Matches the fix from commit 3842122 (`fix(org members): wrap
	// UUID array in pq.Array for ANY($1) bind`).
	ids := make([]string, len(userIDs))
	for i, id := range userIDs {
		ids[i] = id.String()
	}

	// Slim row — only the columns the /admin/users response needs.
	// (GetBaseRoles fetches the full BaseRole; this lighter shape
	// keeps the bulk path cheap and avoids hauling nullable timestamps.)
	type row struct {
		UserID types.ID `db:"user_id"`
		ID     types.ID `db:"id"`
		Code   string   `db:"code"`
		Name   string   `db:"name"`
		Level  int      `db:"level"`
	}

	query := `
		SELECT ubr.user_id, r.id, r.code, r.name, r.level
		FROM roles r
		INNER JOIN user_base_roles ubr ON r.id = ubr.role_id
		WHERE ubr.user_id = ANY($1) AND r.deleted_at IS NULL
		ORDER BY r.level ASC, r.code ASC`

	var rows []row
	q := getQuerier(ctx, r.db)
	if err := q.SelectContext(ctx, &rows, query, pq.Array(ids)); err != nil {
		return nil, fmt.Errorf("failed to get base roles by user ids: %w", err)
	}

	for _, rr := range rows {
		role := &domain.Role{}
		role.ID = rr.ID
		role.Code = rr.Code
		role.Name = rr.Name
		role.Level = rr.Level
		out[rr.UserID] = append(out[rr.UserID], role)
	}

	return out, nil
}

// AssignBaseRole assigns a base role to a user
func (r *UserRepository) AssignBaseRole(ctx context.Context, assignment *domain.UserBaseRole) error {
	query := `
		INSERT INTO user_base_roles (id, user_id, role_id, assigned_at, assigned_by, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (user_id, role_id) DO NOTHING`

	q := getQuerier(ctx, r.db)
	_, err := q.ExecContext(ctx, query,
		assignment.ID, assignment.UserID, assignment.RoleID,
		assignment.AssignedAt, assignment.AssignedBy, assignment.CreatedAt, assignment.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to assign base role: %w", err)
	}
	return nil
}

// RemoveBaseRole removes a base role from a user
func (r *UserRepository) RemoveBaseRole(ctx context.Context, userID, roleID types.ID) error {
	query := `DELETE FROM user_base_roles WHERE user_id = $1 AND role_id = $2`

	q := getQuerier(ctx, r.db)
	_, err := q.ExecContext(ctx, query, userID, roleID)
	if err != nil {
		return fmt.Errorf("failed to remove base role: %w", err)
	}
	return nil
}

// GetOrganizations retrieves organization memberships for a user
func (r *UserRepository) GetOrganizations(ctx context.Context, userID types.ID) ([]*domain.OrganizationMembership, error) {
	query := `
		SELECT om.id, om.user_id, om.organization_id, om.status, om.joined_at,
			om.invited_by, om.created_at, om.updated_at, om.deleted_at
		FROM organization_members om
		WHERE om.user_id = $1 AND om.deleted_at IS NULL AND om.status = 'active'`

	var memberships []*domain.OrganizationMembership
	q := getQuerier(ctx, r.db)
	if err := q.SelectContext(ctx, &memberships, query, userID); err != nil {
		return nil, fmt.Errorf("failed to get organizations: %w", err)
	}

	// Load organization details. COALESCE the nullable string columns
	// (logo_url) so sqlx doesn't choke on NULL → string scan — earlier
	// this was failing silently inside the `if err == nil` branch and
	// every membership ended up with `Organization = nil`, which
	// surfaced as `"organization": null` in the API response.
	//
	// Also load each membership's org-scoped roles (same join as
	// OrganizationRepository.GetMemberRoles). Without this, memberships
	// came back with an empty Roles slice, so admin UIs fell back to the
	// default `org_member` label and never reflected a role change made
	// via SetMemberRoles.
	roleQuery := `
		SELECT r.id, r.code, r.name, r.description, r.type, r.level, r.is_org_role,
			r.organization_id, r.metadata, r.created_at, r.updated_at, r.deleted_at
		FROM roles r
		INNER JOIN organization_member_roles omr ON r.id = omr.role_id
		WHERE omr.membership_id = $1 AND r.deleted_at IS NULL`
	for _, m := range memberships {
		org := &domain.Organization{}
		orgQuery := `SELECT id, name, slug, COALESCE(logo_url, '') AS logo_url, status FROM organizations WHERE id = $1`
		if err := q.GetContext(ctx, org, orgQuery, m.OrganizationID); err == nil {
			m.Organization = org
		}

		var roles []*domain.Role
		if err := q.SelectContext(ctx, &roles, roleQuery, m.ID); err == nil {
			m.Roles = make([]domain.Role, len(roles))
			for i := range roles {
				m.Roles[i] = *roles[i]
			}
		}
	}

	return memberships, nil
}
