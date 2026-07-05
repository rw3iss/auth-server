package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/rw3iss/auth/internal/domain"
	"github.com/rw3iss/auth/internal/repository"
	"github.com/rw3iss/auth/pkg/shared/errors"
	"github.com/rw3iss/auth/pkg/shared/types"
)

// InvitationRepository implements repository.InvitationRepository
type InvitationRepository struct {
	db *DB
}

// NewInvitationRepository creates a new invitation repository
func NewInvitationRepository(db *DB) *InvitationRepository {
	return &InvitationRepository{db: db}
}

// Create creates a new invitation
func (r *InvitationRepository) Create(ctx context.Context, invitation *domain.Invitation) error {
	query := `
		INSERT INTO invitations (
			id, organization_id, email, code, token, invited_by,
			expires_at, status, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	q := getQuerier(ctx, r.db)
	_, err := q.ExecContext(ctx, query,
		invitation.ID, invitation.OrganizationID, invitation.Email, invitation.Code,
		invitation.Token, invitation.InvitedBy, invitation.ExpiresAt, invitation.Status,
		invitation.CreatedAt, invitation.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create invitation: %w", err)
	}

	// Add invitation roles
	for _, roleID := range invitation.RoleIDs {
		if err := r.AddRole(ctx, invitation.ID, roleID); err != nil {
			return err
		}
	}

	return nil
}

// GetByID retrieves an invitation by ID
func (r *InvitationRepository) GetByID(ctx context.Context, id types.ID) (*domain.Invitation, error) {
	query := `
		SELECT id, organization_id, email, code, token, invited_by,
			expires_at, status, accepted_at, accepted_by, created_at, updated_at
		FROM invitations WHERE id = $1`

	invitation := &domain.Invitation{}
	q := getQuerier(ctx, r.db)
	err := q.GetContext(ctx, invitation, query, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.InviteNotFound()
		}
		return nil, fmt.Errorf("failed to get invitation: %w", err)
	}

	// Load roles
	roleIDs, err := r.GetRoles(ctx, id)
	if err != nil {
		return nil, err
	}
	invitation.RoleIDs = roleIDs

	return invitation, nil
}

// GetByCode retrieves an invitation by code
func (r *InvitationRepository) GetByCode(ctx context.Context, code string) (*domain.Invitation, error) {
	query := `
		SELECT id, organization_id, email, code, token, invited_by,
			expires_at, status, accepted_at, accepted_by, created_at, updated_at
		FROM invitations WHERE code = $1`

	invitation := &domain.Invitation{}
	q := getQuerier(ctx, r.db)
	err := q.GetContext(ctx, invitation, query, code)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.InviteNotFound()
		}
		return nil, fmt.Errorf("failed to get invitation by code: %w", err)
	}

	// Load roles
	roleIDs, err := r.GetRoles(ctx, invitation.ID)
	if err != nil {
		return nil, err
	}
	invitation.RoleIDs = roleIDs

	return invitation, nil
}

// GetByToken retrieves an invitation by token
func (r *InvitationRepository) GetByToken(ctx context.Context, token string) (*domain.Invitation, error) {
	query := `
		SELECT id, organization_id, email, code, token, invited_by,
			expires_at, status, accepted_at, accepted_by, created_at, updated_at
		FROM invitations WHERE token = $1`

	invitation := &domain.Invitation{}
	q := getQuerier(ctx, r.db)
	err := q.GetContext(ctx, invitation, query, token)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.InviteNotFound()
		}
		return nil, fmt.Errorf("failed to get invitation by token: %w", err)
	}

	// Load roles
	roleIDs, err := r.GetRoles(ctx, invitation.ID)
	if err != nil {
		return nil, err
	}
	invitation.RoleIDs = roleIDs

	return invitation, nil
}

// Update updates an invitation
func (r *InvitationRepository) Update(ctx context.Context, invitation *domain.Invitation) error {
	invitation.Touch()

	query := `
		UPDATE invitations SET
			status = $2, accepted_at = $3, accepted_by = $4, updated_at = $5
		WHERE id = $1`

	q := getQuerier(ctx, r.db)
	result, err := q.ExecContext(ctx, query,
		invitation.ID, invitation.Status, NullTime(invitation.AcceptedAt),
		invitation.AcceptedBy, invitation.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to update invitation: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.InviteNotFound()
	}
	return nil
}

// Delete deletes an invitation
func (r *InvitationRepository) Delete(ctx context.Context, id types.ID) error {
	// Delete invitation roles first
	deleteRolesQuery := `DELETE FROM invitation_roles WHERE invitation_id = $1`
	q := getQuerier(ctx, r.db)
	if _, err := q.ExecContext(ctx, deleteRolesQuery, id); err != nil {
		return fmt.Errorf("failed to delete invitation roles: %w", err)
	}

	// Delete invitation
	query := `DELETE FROM invitations WHERE id = $1`
	result, err := q.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete invitation: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.InviteNotFound()
	}
	return nil
}

// ListByOrganization lists invitations for an organization
func (r *InvitationRepository) ListByOrganization(ctx context.Context, orgID types.ID, filter repository.InvitationFilter) ([]*domain.Invitation, int, error) {
	var conditions []string
	var args []interface{}
	argIndex := 1

	conditions = append(conditions, fmt.Sprintf("organization_id = $%d", argIndex))
	args = append(args, orgID)
	argIndex++

	if filter.Status != nil {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIndex))
		args = append(args, *filter.Status)
		argIndex++
	}

	if filter.Email != nil {
		conditions = append(conditions, fmt.Sprintf("LOWER(email) = LOWER($%d)", argIndex))
		args = append(args, *filter.Email)
		argIndex++
	}

	whereClause := strings.Join(conditions, " AND ")

	// Count query
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM invitations WHERE %s", whereClause)
	var total int
	q := getQuerier(ctx, r.db)
	if err := q.GetContext(ctx, &total, countQuery, args...); err != nil {
		return nil, 0, fmt.Errorf("failed to count invitations: %w", err)
	}

	// Data query
	query := fmt.Sprintf(`
		SELECT id, organization_id, email, code, invited_by,
			expires_at, status, accepted_at, accepted_by, created_at, updated_at
		FROM invitations WHERE %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`,
		whereClause, argIndex, argIndex+1)

	args = append(args, filter.Pagination.PageSize, filter.Pagination.Offset())

	var invitations []*domain.Invitation
	if err := q.SelectContext(ctx, &invitations, query, args...); err != nil {
		return nil, 0, fmt.Errorf("failed to list invitations: %w", err)
	}

	return invitations, total, nil
}

// ListByEmail lists invitations for an email
func (r *InvitationRepository) ListByEmail(ctx context.Context, email types.Email) ([]*domain.Invitation, error) {
	query := `
		SELECT id, organization_id, email, code, invited_by,
			expires_at, status, accepted_at, accepted_by, created_at, updated_at
		FROM invitations WHERE LOWER(email) = LOWER($1) AND status = 'pending'
		ORDER BY created_at DESC`

	var invitations []*domain.Invitation
	q := getQuerier(ctx, r.db)
	if err := q.SelectContext(ctx, &invitations, query, email); err != nil {
		return nil, fmt.Errorf("failed to list invitations by email: %w", err)
	}
	return invitations, nil
}

// AddRole adds a role to an invitation
func (r *InvitationRepository) AddRole(ctx context.Context, invitationID, roleID types.ID) error {
	query := `
		INSERT INTO invitation_roles (invitation_id, role_id)
		VALUES ($1, $2)
		ON CONFLICT (invitation_id, role_id) DO NOTHING`

	q := getQuerier(ctx, r.db)
	_, err := q.ExecContext(ctx, query, invitationID, roleID)
	if err != nil {
		return fmt.Errorf("failed to add invitation role: %w", err)
	}
	return nil
}

// RemoveRole removes a role from an invitation
func (r *InvitationRepository) RemoveRole(ctx context.Context, invitationID, roleID types.ID) error {
	query := `DELETE FROM invitation_roles WHERE invitation_id = $1 AND role_id = $2`

	q := getQuerier(ctx, r.db)
	_, err := q.ExecContext(ctx, query, invitationID, roleID)
	if err != nil {
		return fmt.Errorf("failed to remove invitation role: %w", err)
	}
	return nil
}

// GetRoles retrieves role IDs for an invitation
func (r *InvitationRepository) GetRoles(ctx context.Context, invitationID types.ID) ([]types.ID, error) {
	query := `SELECT role_id FROM invitation_roles WHERE invitation_id = $1`

	var roleIDs []types.ID
	q := getQuerier(ctx, r.db)
	if err := q.SelectContext(ctx, &roleIDs, query, invitationID); err != nil {
		return nil, fmt.Errorf("failed to get invitation roles: %w", err)
	}
	return roleIDs, nil
}
