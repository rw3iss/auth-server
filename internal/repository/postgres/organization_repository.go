package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/lib/pq"

	"github.com/ven/auth/internal/domain"
	"github.com/ven/auth/internal/repository"
	"github.com/ven/auth/pkg/shared/errors"
	"github.com/ven/auth/pkg/shared/types"
)

// orgSortAllowlist enumerates ORDER BY columns we accept on /admin/organizations.
// AUDIT 1.21: any column not in this list falls back to the default in
// resolveSort.
var orgSortAllowlist = []string{
	"created_at", "updated_at", "name", "slug", "status", "plan",
}

// memberSortAllowlist enumerates ORDER BY columns for /admin/organizations/{id}/members.
var memberSortAllowlist = []string{
	"joined_at", "created_at", "updated_at", "status",
}

// orgSelectCols centralises the column list for SELECTs against the
// organizations table. Nullable string columns get COALESCE(…, '') so
// sqlx can scan straight into the non-pointer string fields on
// domain.Organization / models.BaseOrganization — without this, a row
// with a NULL `logo_url` (or any of the address / contact / sso-provider
// columns) raises "converting NULL to string is unsupported" and 500s
// the request. Cheaper than retrofitting every consumer of the struct
// to handle sql.NullString.
//
// `sso_config`, `settings`, `metadata` are jsonb — already nil-safe in
// types.JSON's Scan. `plan_expiry` is a nullable timestamp — pointer
// in the struct, also fine. We only wrap the plain-string columns.
const orgSelectCols = `id, name, slug,
	COALESCE(description, '')   AS description,
	COALESCE(logo_url, '')      AS logo_url,
	COALESCE(website, '')       AS website,
	status,
	COALESCE(contact_email, '') AS contact_email,
	COALESCE(contact_phone, '') AS contact_phone,
	COALESCE(address, '')       AS address,
	COALESCE(city, '')          AS city,
	COALESCE(state, '')         AS state,
	COALESCE(country, '')       AS country,
	COALESCE(postal_code, '')   AS postal_code,
	owner_id, sso_enabled,
	COALESCE(sso_provider, '')  AS sso_provider,
	COALESCE(plan, '')          AS plan,
	plan_expiry,
	settings, metadata,
	created_at, updated_at, deleted_at`

// OrganizationRepository implements repository.OrganizationRepository
type OrganizationRepository struct {
	db *DB
}

// NewOrganizationRepository creates a new organization repository
func NewOrganizationRepository(db *DB) *OrganizationRepository {
	return &OrganizationRepository{db: db}
}

// Create creates a new organization
func (r *OrganizationRepository) Create(ctx context.Context, org *domain.Organization) error {
	query := `
		INSERT INTO organizations (
			id, name, slug, description, logo_url, website, status,
			contact_email, contact_phone, address, city, state, country, postal_code,
			owner_id, sso_enabled, sso_provider, sso_config, plan, plan_expiry,
			settings, metadata, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
			$15, $16, $17, $18, $19, $20, $21, $22, $23, $24
		)`

	q := getQuerier(ctx, r.db)
	_, err := q.ExecContext(ctx, query,
		org.ID, org.Name, org.Slug, org.Description, org.LogoURL, org.Website, org.Status,
		org.ContactEmail, org.ContactPhone, org.Address, org.City, org.State, org.Country, org.PostalCode,
		org.OwnerID, org.SSOEnabled, org.SSOProvider, org.SSOConfig, org.Plan, NullTime(org.PlanExpiry),
		org.Settings, org.Metadata, org.CreatedAt, org.UpdatedAt,
	)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return errors.OrgAlreadyExists(org.Name)
		}
		return fmt.Errorf("failed to create organization: %w", err)
	}
	return nil
}

// GetByID retrieves an organization by ID
func (r *OrganizationRepository) GetByID(ctx context.Context, id types.ID) (*domain.Organization, error) {
	query := `
		SELECT ` + orgSelectCols + `
		FROM organizations WHERE id = $1 AND deleted_at IS NULL`

	org := &domain.Organization{}
	q := getQuerier(ctx, r.db)
	err := q.GetContext(ctx, org, query, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.OrgNotFound()
		}
		return nil, fmt.Errorf("failed to get organization: %w", err)
	}
	return org, nil
}

// GetBySlug retrieves an organization by slug
func (r *OrganizationRepository) GetBySlug(ctx context.Context, slug string) (*domain.Organization, error) {
	query := `
		SELECT ` + orgSelectCols + `
		FROM organizations WHERE slug = $1 AND deleted_at IS NULL`

	org := &domain.Organization{}
	q := getQuerier(ctx, r.db)
	err := q.GetContext(ctx, org, query, slug)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.OrgNotFound()
		}
		return nil, fmt.Errorf("failed to get organization by slug: %w", err)
	}
	return org, nil
}

// Update updates an organization
func (r *OrganizationRepository) Update(ctx context.Context, org *domain.Organization) error {
	org.Touch()

	query := `
		UPDATE organizations SET
			name = $2, slug = $3, description = $4, logo_url = $5, website = $6, status = $7,
			contact_email = $8, contact_phone = $9, address = $10, city = $11, state = $12,
			country = $13, postal_code = $14, owner_id = $15, sso_enabled = $16,
			sso_provider = $17, sso_config = $18, plan = $19, plan_expiry = $20,
			settings = $21, metadata = $22, updated_at = $23
		WHERE id = $1 AND deleted_at IS NULL`

	q := getQuerier(ctx, r.db)
	result, err := q.ExecContext(ctx, query,
		org.ID, org.Name, org.Slug, org.Description, org.LogoURL, org.Website, org.Status,
		org.ContactEmail, org.ContactPhone, org.Address, org.City, org.State,
		org.Country, org.PostalCode, org.OwnerID, org.SSOEnabled,
		org.SSOProvider, org.SSOConfig, org.Plan, NullTime(org.PlanExpiry),
		org.Settings, org.Metadata, org.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to update organization: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.OrgNotFound()
	}
	return nil
}

// Delete soft deletes an organization
func (r *OrganizationRepository) Delete(ctx context.Context, id types.ID) error {
	query := `UPDATE organizations SET deleted_at = NOW(), updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL`

	q := getQuerier(ctx, r.db)
	result, err := q.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete organization: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.OrgNotFound()
	}
	return nil
}

// List lists organizations with filtering
func (r *OrganizationRepository) List(ctx context.Context, filter repository.OrganizationFilter) ([]*domain.Organization, int, error) {
	var conditions []string
	var args []interface{}
	argIndex := 1

	conditions = append(conditions, "deleted_at IS NULL")

	if filter.Status != nil {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIndex))
		args = append(args, *filter.Status)
		argIndex++
	}

	if filter.OwnerID != nil {
		conditions = append(conditions, fmt.Sprintf("owner_id = $%d", argIndex))
		args = append(args, *filter.OwnerID)
		argIndex++
	}

	whereClause := strings.Join(conditions, " AND ")

	// Count query
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM organizations WHERE %s", whereClause)
	var total int
	q := getQuerier(ctx, r.db)
	if err := q.GetContext(ctx, &total, countQuery, args...); err != nil {
		return nil, 0, fmt.Errorf("failed to count organizations: %w", err)
	}

	// AUDIT 1.21: validate sort_by against an allowlist before interpolating
	// into the ORDER BY clause.
	sortBy, sortOrd := resolveSort(filter.SortBy, "created_at", string(filter.SortOrder), orgSortAllowlist)

	query := fmt.Sprintf(`
		SELECT `+orgSelectCols+`
		FROM organizations WHERE %s
		ORDER BY %s %s
		LIMIT $%d OFFSET $%d`,
		whereClause, sortBy, sortOrd, argIndex, argIndex+1)

	args = append(args, filter.Pagination.PageSize, filter.Pagination.Offset())

	var orgs []*domain.Organization
	if err := q.SelectContext(ctx, &orgs, query, args...); err != nil {
		return nil, 0, fmt.Errorf("failed to list organizations: %w", err)
	}

	return orgs, total, nil
}

// AddMember adds a member to an organization
func (r *OrganizationRepository) AddMember(ctx context.Context, membership *domain.OrganizationMembership) error {
	query := `
		INSERT INTO organization_members (
			id, user_id, organization_id, status, joined_at, invited_by,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (user_id, organization_id) WHERE deleted_at IS NULL DO UPDATE SET
			status = EXCLUDED.status,
			updated_at = EXCLUDED.updated_at`

	q := getQuerier(ctx, r.db)
	_, err := q.ExecContext(ctx, query,
		membership.ID, membership.UserID, membership.OrganizationID,
		membership.Status, membership.JoinedAt, membership.InvitedBy,
		membership.CreatedAt, membership.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to add member: %w", err)
	}
	return nil
}

// GetMembership retrieves a membership by user and organization
func (r *OrganizationRepository) GetMembership(ctx context.Context, userID, orgID types.ID) (*domain.OrganizationMembership, error) {
	query := `
		SELECT id, user_id, organization_id, status, joined_at, invited_by,
			created_at, updated_at, deleted_at
		FROM organization_members
		WHERE user_id = $1 AND organization_id = $2 AND deleted_at IS NULL`

	membership := &domain.OrganizationMembership{}
	q := getQuerier(ctx, r.db)
	err := q.GetContext(ctx, membership, query, userID, orgID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.NotOrgMember()
		}
		return nil, fmt.Errorf("failed to get membership: %w", err)
	}
	return membership, nil
}

// UpdateMembership updates a membership
func (r *OrganizationRepository) UpdateMembership(ctx context.Context, membership *domain.OrganizationMembership) error {
	membership.Touch()

	query := `
		UPDATE organization_members SET
			status = $2, updated_at = $3
		WHERE id = $1 AND deleted_at IS NULL`

	q := getQuerier(ctx, r.db)
	result, err := q.ExecContext(ctx, query, membership.ID, membership.Status, membership.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to update membership: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.NotOrgMember()
	}
	return nil
}

// RemoveMember removes a member from an organization
func (r *OrganizationRepository) RemoveMember(ctx context.Context, userID, orgID types.ID) error {
	query := `
		UPDATE organization_members SET
			status = 'removed', deleted_at = NOW(), updated_at = NOW()
		WHERE user_id = $1 AND organization_id = $2 AND deleted_at IS NULL`

	q := getQuerier(ctx, r.db)
	result, err := q.ExecContext(ctx, query, userID, orgID)
	if err != nil {
		return fmt.Errorf("failed to remove member: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.NotOrgMember()
	}
	return nil
}

// ListMembers lists members of an organization
func (r *OrganizationRepository) ListMembers(ctx context.Context, orgID types.ID, filter repository.MemberFilter) ([]*domain.OrganizationMembership, int, error) {
	var conditions []string
	var args []interface{}
	argIndex := 1

	conditions = append(conditions, fmt.Sprintf("organization_id = $%d", argIndex))
	args = append(args, orgID)
	argIndex++

	conditions = append(conditions, "deleted_at IS NULL")

	if filter.Status != nil {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIndex))
		args = append(args, *filter.Status)
		argIndex++
	}

	whereClause := strings.Join(conditions, " AND ")

	// Count query
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM organization_members WHERE %s", whereClause)
	var total int
	q := getQuerier(ctx, r.db)
	if err := q.GetContext(ctx, &total, countQuery, args...); err != nil {
		return nil, 0, fmt.Errorf("failed to count members: %w", err)
	}

	// AUDIT 1.21: validate member-list sort_by against an allowlist.
	sortBy, sortOrd := resolveSort(filter.SortBy, "joined_at", string(filter.SortOrder), memberSortAllowlist)

	query := fmt.Sprintf(`
		SELECT id, user_id, organization_id, status, joined_at, invited_by,
			created_at, updated_at, deleted_at
		FROM organization_members WHERE %s
		ORDER BY %s %s
		LIMIT $%d OFFSET $%d`,
		whereClause, sortBy, sortOrd, argIndex, argIndex+1)

	args = append(args, filter.Pagination.PageSize, filter.Pagination.Offset())

	var memberships []*domain.OrganizationMembership
	if err := q.SelectContext(ctx, &memberships, query, args...); err != nil {
		return nil, 0, fmt.Errorf("failed to list members: %w", err)
	}

	// Load user details for each membership
	for _, m := range memberships {
		user := &domain.User{}
		userQuery := `SELECT id, email, first_name, last_name, COALESCE(display_name, '') AS display_name, COALESCE(avatar_url, '') AS avatar_url, status FROM users WHERE id = $1`
		if err := q.GetContext(ctx, user, userQuery, m.UserID); err == nil {
			m.User = user
		}
	}

	return memberships, total, nil
}

// AssignMemberRole assigns a role to a member
func (r *OrganizationRepository) AssignMemberRole(ctx context.Context, assignment *domain.OrganizationMemberRole) error {
	query := `
		INSERT INTO organization_member_roles (id, membership_id, role_id, assigned_by, assigned_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (membership_id, role_id) DO NOTHING`

	q := getQuerier(ctx, r.db)
	_, err := q.ExecContext(ctx, query,
		assignment.ID, assignment.MembershipID, assignment.RoleID,
		assignment.AssignedBy, assignment.AssignedAt, assignment.CreatedAt, assignment.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to assign member role: %w", err)
	}
	return nil
}

// RemoveMemberRole removes a role from a member
func (r *OrganizationRepository) RemoveMemberRole(ctx context.Context, membershipID, roleID types.ID) error {
	query := `DELETE FROM organization_member_roles WHERE membership_id = $1 AND role_id = $2`

	q := getQuerier(ctx, r.db)
	_, err := q.ExecContext(ctx, query, membershipID, roleID)
	if err != nil {
		return fmt.Errorf("failed to remove member role: %w", err)
	}
	return nil
}

// GetMemberRoles retrieves roles assigned to a membership
func (r *OrganizationRepository) GetMemberRoles(ctx context.Context, membershipID types.ID) ([]*domain.Role, error) {
	query := `
		SELECT r.id, r.code, r.name, r.description, r.type, r.level, r.is_org_role,
			r.organization_id, r.metadata, r.created_at, r.updated_at, r.deleted_at
		FROM roles r
		INNER JOIN organization_member_roles omr ON r.id = omr.role_id
		WHERE omr.membership_id = $1 AND r.deleted_at IS NULL`

	var roles []*domain.Role
	q := getQuerier(ctx, r.db)
	if err := q.SelectContext(ctx, &roles, query, membershipID); err != nil {
		return nil, fmt.Errorf("failed to get member roles: %w", err)
	}
	return roles, nil
}

// memberRoleRow is the row shape for GetMemberRolesBatch — every column
// from `roles` plus the `membership_id` we join on, so the caller can
// fan out into a map[membershipID][]*Role.
type memberRoleRow struct {
	MembershipID types.ID `db:"membership_id"`
	domain.Role
}

// GetMemberRolesBatch returns the roles for every supplied membership in a
// single query. AUDIT 4.2: ListMembers previously looped over members and
// called GetMemberRoles per row, producing N+1 queries that scale linearly
// with org size. This batched fetch collapses the workload into one trip.
//
// The result is keyed by membership_id; absent keys map to an empty
// (`nil`) slice — caller's `for _, m := range members { m.Roles =
// rolesByMembership[m.ID] }` reads naturally.
func (r *OrganizationRepository) GetMemberRolesBatch(
	ctx context.Context,
	membershipIDs []types.ID,
) (map[types.ID][]*domain.Role, error) {
	out := make(map[types.ID][]*domain.Role, len(membershipIDs))
	if len(membershipIDs) == 0 {
		return out, nil
	}
	query := `
		SELECT omr.membership_id,
			r.id, r.code, r.name, r.description, r.type, r.level, r.is_org_role,
			r.organization_id, r.metadata, r.created_at, r.updated_at, r.deleted_at
		FROM roles r
		INNER JOIN organization_member_roles omr ON r.id = omr.role_id
		WHERE omr.membership_id = ANY($1) AND r.deleted_at IS NULL`

	// pq doesn't accept []uuid.UUID directly — driver returns
	// "unsupported type []uuid.UUID, a slice of array" without the
	// pq.Array wrapper. Convert to a string slice for the bind value
	// (Postgres's `uuid = ANY($1)` happily coerces text).
	ids := make([]string, len(membershipIDs))
	for i, id := range membershipIDs {
		ids[i] = id.String()
	}
	var rows []memberRoleRow
	q := getQuerier(ctx, r.db)
	if err := q.SelectContext(ctx, &rows, query, pq.Array(ids)); err != nil {
		return nil, fmt.Errorf("failed to batch-get member roles: %w", err)
	}
	for i := range rows {
		// Copy the embedded Role into a stable pointer per row; the slice
		// must not share storage across iterations.
		role := rows[i].Role
		out[rows[i].MembershipID] = append(out[rows[i].MembershipID], &role)
	}
	return out, nil
}
