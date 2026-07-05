package service

import (
	"context"

	"github.com/rw3iss/auth/internal/config"
	"github.com/rw3iss/auth/internal/domain"
	"github.com/rw3iss/auth/internal/repository"
	"github.com/rw3iss/auth/pkg/shared/errors"
	"github.com/rw3iss/auth/pkg/shared/models"
	"github.com/rw3iss/auth/pkg/shared/types"
	"github.com/rw3iss/auth/pkg/shared/utils"
)

// OrganizationService handles organization management business logic
type OrganizationService struct {
	cfg          *config.Config
	orgRepo      repository.OrganizationRepository
	userRepo     repository.UserRepository
	roleRepo     repository.RoleRepository
	inviteRepo   repository.InvitationRepository
	txManager    repository.TransactionManager
	emailService EmailService
}

// NewOrganizationService creates a new organization service
func NewOrganizationService(
	cfg *config.Config,
	orgRepo repository.OrganizationRepository,
	userRepo repository.UserRepository,
	roleRepo repository.RoleRepository,
	inviteRepo repository.InvitationRepository,
	txManager repository.TransactionManager,
	emailService EmailService,
) *OrganizationService {
	return &OrganizationService{
		cfg:          cfg,
		orgRepo:      orgRepo,
		userRepo:     userRepo,
		roleRepo:     roleRepo,
		inviteRepo:   inviteRepo,
		txManager:    txManager,
		emailService: emailService,
	}
}

// CreateOrganizationInput contains input for creating an organization
type CreateOrganizationInput struct {
	Name         string `json:"name" validate:"required"`
	Description  string `json:"description,omitempty"`
	Website      string `json:"website,omitempty"`
	ContactEmail string `json:"contact_email,omitempty"`
	ContactPhone string `json:"contact_phone,omitempty"`
	Address      string `json:"address,omitempty"`
	City         string `json:"city,omitempty"`
	State        string `json:"state,omitempty"`
	Country      string `json:"country,omitempty"`
	PostalCode   string `json:"postal_code,omitempty"`
}

// CreateOrganization creates a new organization
func (s *OrganizationService) CreateOrganization(ctx context.Context, ownerID types.ID, input CreateOrganizationInput) (*domain.Organization, error) {
	slug := utils.Slugify(input.Name)

	// Check if slug is unique
	_, err := s.orgRepo.GetBySlug(ctx, slug)
	if err == nil {
		return nil, errors.OrgAlreadyExists(input.Name)
	}

	org := domain.NewOrganization(input.Name, slug, ownerID)
	org.Description = input.Description
	org.Website = input.Website
	org.ContactEmail = types.Email(input.ContactEmail)
	org.ContactPhone = types.PhoneNumber(input.ContactPhone)
	org.Address = input.Address
	org.City = input.City
	org.State = input.State
	org.Country = input.Country
	org.PostalCode = input.PostalCode

	err = s.txManager.WithTransaction(ctx, func(ctx context.Context) error {
		if err := s.orgRepo.Create(ctx, org); err != nil {
			return err
		}

		// Add owner as member with admin role
		membership := domain.NewOrganizationMembership(ownerID, org.ID)
		if err := s.orgRepo.AddMember(ctx, membership); err != nil {
			return err
		}

		// Assign org admin role
		adminRole, err := s.roleRepo.GetByCode(ctx, string(models.RoleOrgAdmin))
		if err != nil {
			return err
		}

		roleAssign := domain.NewOrganizationMemberRole(membership.ID, adminRole.ID, ownerID)
		return s.orgRepo.AssignMemberRole(ctx, roleAssign)
	})

	if err != nil {
		return nil, err
	}

	return org, nil
}

// GetOrganization retrieves an organization by ID
func (s *OrganizationService) GetOrganization(ctx context.Context, id types.ID) (*domain.Organization, error) {
	return s.orgRepo.GetByID(ctx, id)
}

// GetOrganizationBySlug retrieves an organization by slug
func (s *OrganizationService) GetOrganizationBySlug(ctx context.Context, slug string) (*domain.Organization, error) {
	return s.orgRepo.GetBySlug(ctx, slug)
}

// UpdateOrganizationInput contains input for updating an organization
type UpdateOrganizationInput struct {
	Name         *string `json:"name,omitempty"`
	Description  *string `json:"description,omitempty"`
	LogoURL      *string `json:"logo_url,omitempty"`
	Website      *string `json:"website,omitempty"`
	ContactEmail *string `json:"contact_email,omitempty"`
	ContactPhone *string `json:"contact_phone,omitempty"`
	Address      *string `json:"address,omitempty"`
	City         *string `json:"city,omitempty"`
	State        *string `json:"state,omitempty"`
	Country      *string `json:"country,omitempty"`
	PostalCode   *string `json:"postal_code,omitempty"`
}

// UpdateOrganization updates an organization
func (s *OrganizationService) UpdateOrganization(ctx context.Context, id types.ID, input UpdateOrganizationInput) (*domain.Organization, error) {
	org, err := s.orgRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if input.Name != nil {
		org.Name = *input.Name
		org.Slug = utils.Slugify(*input.Name)
	}
	if input.Description != nil {
		org.Description = *input.Description
	}
	if input.LogoURL != nil {
		org.LogoURL = *input.LogoURL
	}
	if input.Website != nil {
		org.Website = *input.Website
	}
	if input.ContactEmail != nil {
		org.ContactEmail = types.Email(*input.ContactEmail)
	}
	if input.ContactPhone != nil {
		org.ContactPhone = types.PhoneNumber(*input.ContactPhone)
	}
	if input.Address != nil {
		org.Address = *input.Address
	}
	if input.City != nil {
		org.City = *input.City
	}
	if input.State != nil {
		org.State = *input.State
	}
	if input.Country != nil {
		org.Country = *input.Country
	}
	if input.PostalCode != nil {
		org.PostalCode = *input.PostalCode
	}

	if err := s.orgRepo.Update(ctx, org); err != nil {
		return nil, err
	}

	return org, nil
}

// ListOrganizationsInput contains input for listing organizations
type ListOrganizationsInput struct {
	Status    *types.OrganizationStatus
	OwnerID   *types.ID
	Page      int
	PageSize  int
	SortBy    string
	SortOrder types.SortOrder
}

// ListOrganizationsResult contains the result of listing organizations
type ListOrganizationsResult struct {
	Organizations []*domain.Organization `json:"organizations"`
	Pagination    types.Pagination       `json:"pagination"`
}

// ListOrganizations lists organizations
func (s *OrganizationService) ListOrganizations(ctx context.Context, input ListOrganizationsInput) (*ListOrganizationsResult, error) {
	pagination := types.DefaultPagination()
	if input.Page > 0 {
		pagination.Page = input.Page
	}
	if input.PageSize > 0 {
		pagination.PageSize = input.PageSize
	}

	filter := repository.OrganizationFilter{
		Status:     input.Status,
		OwnerID:    input.OwnerID,
		Pagination: pagination,
		SortBy:     input.SortBy,
		SortOrder:  input.SortOrder,
	}

	orgs, total, err := s.orgRepo.List(ctx, filter)
	if err != nil {
		return nil, err
	}

	pagination.Total = total

	return &ListOrganizationsResult{
		Organizations: orgs,
		Pagination:    pagination,
	}, nil
}

// DeleteOrganization soft deletes an organization
func (s *OrganizationService) DeleteOrganization(ctx context.Context, id types.ID) error {
	return s.orgRepo.Delete(ctx, id)
}

// AddMember adds a member to an organization
func (s *OrganizationService) AddMember(ctx context.Context, orgID, userID types.ID, roleIDs []types.ID, invitedBy types.ID) error {
	// Verify user exists
	_, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	// Verify organization exists
	_, err = s.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		return err
	}

	return s.txManager.WithTransaction(ctx, func(ctx context.Context) error {
		membership := domain.NewOrganizationMembership(userID, orgID)
		membership.InvitedBy = &invitedBy

		if err := s.orgRepo.AddMember(ctx, membership); err != nil {
			return err
		}

		// Assign roles. When the caller didn't specify any, fall back to
		// `org_member` so the membership row is never a "shell" with no
		// org-scoped permissions on the JWT. Explicit roles always win.
		if len(roleIDs) == 0 {
			fallbackRole, ferr := s.roleRepo.GetByCode(ctx, string(models.RoleOrgMember))
			if ferr == nil {
				roleIDs = []types.ID{fallbackRole.ID}
			}
		}
		for _, roleID := range roleIDs {
			roleAssign := domain.NewOrganizationMemberRole(membership.ID, roleID, invitedBy)
			if err := s.orgRepo.AssignMemberRole(ctx, roleAssign); err != nil {
				return err
			}
		}

		return nil
	})
}

// RemoveMember removes a member from an organization
func (s *OrganizationService) RemoveMember(ctx context.Context, orgID, userID types.ID) error {
	// Check if user is the owner
	org, err := s.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		return err
	}

	if org.OwnerID == userID {
		return errors.ValidationError("Cannot remove organization owner")
	}

	return s.orgRepo.RemoveMember(ctx, userID, orgID)
}

// ListMembersInput contains input for listing members
type ListMembersInput struct {
	Status    *domain.MembershipStatus
	RoleID    *types.ID
	Page      int
	PageSize  int
	SortBy    string
	SortOrder types.SortOrder
}

// ListMembersResult contains the result of listing members
type ListMembersResult struct {
	Members    []*domain.OrganizationMembership `json:"members"`
	Pagination types.Pagination                  `json:"pagination"`
}

// ListMembers lists members of an organization
func (s *OrganizationService) ListMembers(ctx context.Context, orgID types.ID, input ListMembersInput) (*ListMembersResult, error) {
	pagination := types.DefaultPagination()
	if input.Page > 0 {
		pagination.Page = input.Page
	}
	if input.PageSize > 0 {
		pagination.PageSize = input.PageSize
	}

	filter := repository.MemberFilter{
		Status:     input.Status,
		RoleID:     input.RoleID,
		Pagination: pagination,
		SortBy:     input.SortBy,
		SortOrder:  input.SortOrder,
	}

	members, total, err := s.orgRepo.ListMembers(ctx, orgID, filter)
	if err != nil {
		return nil, err
	}

	pagination.Total = total

	// AUDIT 4.2: batched role fetch instead of N+1. One SQL trip for
	// every membership_id on the page; an empty result silently leaves
	// member.Roles as a nil slice (semantically equivalent to the old
	// "no roles assigned" branch).
	if len(members) > 0 {
		ids := make([]types.ID, len(members))
		for i, m := range members {
			ids[i] = m.ID
		}
		rolesByMembership, batchErr := s.orgRepo.GetMemberRolesBatch(ctx, ids)
		if batchErr != nil {
			return nil, batchErr
		}
		for _, member := range members {
			member.Roles = derefRoles(rolesByMembership[member.ID])
		}
	}

	return &ListMembersResult{
		Members:    members,
		Pagination: pagination,
	}, nil
}

// GetMembership retrieves a membership
func (s *OrganizationService) GetMembership(ctx context.Context, userID, orgID types.ID) (*domain.OrganizationMembership, error) {
	membership, err := s.orgRepo.GetMembership(ctx, userID, orgID)
	if err != nil {
		return nil, err
	}

	// Load roles
	roles, _ := s.orgRepo.GetMemberRoles(ctx, membership.ID)
	membership.Roles = derefRoles(roles)

	return membership, nil
}

func derefRoles(ptrs []*domain.Role) []domain.Role {
	result := make([]domain.Role, len(ptrs))
	for i, p := range ptrs {
		result[i] = *p
	}
	return result
}

// AssignMemberRole assigns a role to a member
func (s *OrganizationService) AssignMemberRole(ctx context.Context, userID, orgID, roleID, assignedBy types.ID) error {
	membership, err := s.orgRepo.GetMembership(ctx, userID, orgID)
	if err != nil {
		return err
	}

	// Verify role is valid for this organization
	role, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		return err
	}

	if !role.IsOrgRole {
		return errors.ValidationError("Cannot assign base role as organization role")
	}

	if role.OrganizationID != nil && *role.OrganizationID != orgID {
		return errors.ValidationError("Role does not belong to this organization")
	}

	roleAssign := domain.NewOrganizationMemberRole(membership.ID, roleID, assignedBy)
	return s.orgRepo.AssignMemberRole(ctx, roleAssign)
}

// RemoveMemberRole removes a role from a member
func (s *OrganizationService) RemoveMemberRole(ctx context.Context, userID, orgID, roleID types.ID) error {
	membership, err := s.orgRepo.GetMembership(ctx, userID, orgID)
	if err != nil {
		return err
	}

	return s.orgRepo.RemoveMemberRole(ctx, membership.ID, roleID)
}

// SetMemberRoles replaces a member's organization-role set with the
// given role codes (set semantics: roles not listed are removed, new
// ones assigned). Backs PUT /admin/organizations/{orgId}/members/{userId}/roles
// — e.g. swapping the org_admin from one member to another.
//
// Every code must resolve to an org-scoped role (seeded `is_org_role`
// roles like org_admin/org_manager/seller/buyer/org_member, or a
// custom role belonging to this org). Base/platform roles are
// rejected — those are managed via PUT /admin/users/{id}/roles.
//
// Changes take effect on the member's next token issue/refresh (same
// propagation model as SetUserRoles).
func (s *OrganizationService) SetMemberRoles(ctx context.Context, userID, orgID types.ID, roleCodes []string, assignedBy types.ID) (*domain.OrganizationMembership, error) {
	membership, err := s.orgRepo.GetMembership(ctx, userID, orgID)
	if err != nil {
		return nil, err
	}

	// Resolve + validate targets first — reject the whole request on
	// any bad code so we never half-apply a role swap.
	targets := make(map[types.ID]bool, len(roleCodes))
	for _, code := range roleCodes {
		role, err := s.roleRepo.GetByCode(ctx, code)
		if err != nil {
			return nil, errors.ValidationError("Unknown role code: " + code)
		}
		if !role.IsOrgRole {
			return nil, errors.ValidationError("Role is not an organization role: " + code)
		}
		if role.OrganizationID != nil && *role.OrganizationID != orgID {
			return nil, errors.ValidationError("Role does not belong to this organization: " + code)
		}
		targets[role.ID] = true
	}

	current, err := s.orgRepo.GetMemberRoles(ctx, membership.ID)
	if err != nil {
		return nil, err
	}
	currentIDs := make(map[types.ID]bool, len(current))
	for _, r := range current {
		currentIDs[r.ID] = true
	}

	// Remove roles no longer in the set.
	for _, r := range current {
		if !targets[r.ID] {
			if err := s.orgRepo.RemoveMemberRole(ctx, membership.ID, r.ID); err != nil {
				return nil, err
			}
		}
	}
	// Assign the new ones.
	for roleID := range targets {
		if !currentIDs[roleID] {
			roleAssign := domain.NewOrganizationMemberRole(membership.ID, roleID, assignedBy)
			if err := s.orgRepo.AssignMemberRole(ctx, roleAssign); err != nil {
				return nil, err
			}
		}
	}

	// Return the refreshed membership (roles reloaded).
	return s.GetMembership(ctx, userID, orgID)
}

// CreateInvitationInput contains input for creating an invitation
type CreateInvitationInput struct {
	Email   string     `json:"email" validate:"required,email"`
	RoleIDs []types.ID `json:"role_ids"`
}

// CreateInvitation creates an invitation to join an organization
func (s *OrganizationService) CreateInvitation(ctx context.Context, orgID, invitedBy types.ID, input CreateInvitationInput) (*domain.Invitation, error) {
	email := types.Email(utils.NormalizeEmail(input.Email))

	// Generate invite code and token
	code, err := utils.GenerateInviteCode()
	if err != nil {
		return nil, errors.Internal("Failed to generate invite code")
	}

	token, err := utils.GenerateRandomString(64)
	if err != nil {
		return nil, errors.Internal("Failed to generate invite token")
	}

	expiresAt := types.Now().Add(s.cfg.Auth.InvitationExpiry)

	invitation := &domain.Invitation{
		BaseModel:      models.NewBaseModel(),
		OrganizationID: orgID,
		Email:          email,
		Code:           code,
		Token:          token,
		RoleIDs:        input.RoleIDs,
		InvitedBy:      invitedBy,
		ExpiresAt:      expiresAt,
		Status:         domain.InvitationStatusPending,
	}

	if err := s.inviteRepo.Create(ctx, invitation); err != nil {
		return nil, err
	}

	// Send invitation email
	if s.emailService != nil {
		org, _ := s.orgRepo.GetByID(ctx, orgID)
		inviter, _ := s.userRepo.GetByID(ctx, invitedBy)

		orgName := ""
		inviterName := ""
		if org != nil {
			orgName = org.Name
		}
		if inviter != nil {
			inviterName = inviter.FullName()
		}

		// Invitations have no inherent app context — the invitee might
		// not even have an account yet, and an org can span multiple
		// apps. Pass "" to use the CLIENT_URL fallback. If we later
		// want per-app-themed accept pages, add app_code to the
		// invitation DTO + persist on the row.
		_ = s.emailService.SendInvitationEmail(ctx, "", string(email), orgName, inviterName, code, token)
	}

	return invitation, nil
}

// GetInvitation retrieves an invitation by ID
func (s *OrganizationService) GetInvitation(ctx context.Context, id types.ID) (*domain.Invitation, error) {
	return s.inviteRepo.GetByID(ctx, id)
}

// GetInvitationByCode retrieves an invitation by code
func (s *OrganizationService) GetInvitationByCode(ctx context.Context, code string) (*domain.Invitation, error) {
	return s.inviteRepo.GetByCode(ctx, code)
}

// ListInvitationsInput contains input for listing invitations
type ListInvitationsInput struct {
	Status   *domain.InvitationStatus
	Page     int
	PageSize int
}

// ListInvitationsResult contains the result of listing invitations
type ListInvitationsResult struct {
	Invitations []*domain.Invitation `json:"invitations"`
	Pagination  types.Pagination     `json:"pagination"`
}

// ListInvitations lists invitations for an organization
func (s *OrganizationService) ListInvitations(ctx context.Context, orgID types.ID, input ListInvitationsInput) (*ListInvitationsResult, error) {
	pagination := types.DefaultPagination()
	if input.Page > 0 {
		pagination.Page = input.Page
	}
	if input.PageSize > 0 {
		pagination.PageSize = input.PageSize
	}

	filter := repository.InvitationFilter{
		Status:     input.Status,
		Pagination: pagination,
	}

	invitations, total, err := s.inviteRepo.ListByOrganization(ctx, orgID, filter)
	if err != nil {
		return nil, err
	}

	pagination.Total = total

	return &ListInvitationsResult{
		Invitations: invitations,
		Pagination:  pagination,
	}, nil
}

// RevokeInvitation revokes an invitation
func (s *OrganizationService) RevokeInvitation(ctx context.Context, invitationID types.ID) error {
	invitation, err := s.inviteRepo.GetByID(ctx, invitationID)
	if err != nil {
		return err
	}

	invitation.Status = domain.InvitationStatusRevoked
	return s.inviteRepo.Update(ctx, invitation)
}

// AcceptInvitation accepts an invitation
func (s *OrganizationService) AcceptInvitation(ctx context.Context, userID types.ID, code string) (*domain.Organization, error) {
	invitation, err := s.inviteRepo.GetByCode(ctx, code)
	if err != nil {
		return nil, err
	}

	if !invitation.IsValid() {
		if invitation.Status != domain.InvitationStatusPending {
			return nil, errors.InviteAlreadyUsed()
		}
		return nil, errors.InviteExpired()
	}

	var org *domain.Organization

	err = s.txManager.WithTransaction(ctx, func(ctx context.Context) error {
		org, err = s.orgRepo.GetByID(ctx, invitation.OrganizationID)
		if err != nil {
			return err
		}

		// Create membership
		membership := domain.NewOrganizationMembership(userID, org.ID)
		membership.InvitedBy = &invitation.InvitedBy
		if err := s.orgRepo.AddMember(ctx, membership); err != nil {
			return err
		}

		// Assign roles — fall back to org_member when the invitation
		// didn't specify any (defensive: invitations created by future
		// org-admin UIs shouldn't be able to short-circuit role
		// assignment to "no roles," but if they do, this keeps the
		// resulting membership functional).
		roleIDs := invitation.RoleIDs
		if len(roleIDs) == 0 {
			fallbackRole, ferr := s.roleRepo.GetByCode(ctx, string(models.RoleOrgMember))
			if ferr == nil {
				roleIDs = []types.ID{fallbackRole.ID}
			}
		}
		for _, roleID := range roleIDs {
			roleAssign := domain.NewOrganizationMemberRole(membership.ID, roleID, invitation.InvitedBy)
			if err := s.orgRepo.AssignMemberRole(ctx, roleAssign); err != nil {
				return err
			}
		}

		// Mark invitation as accepted
		invitation.Accept(userID)
		return s.inviteRepo.Update(ctx, invitation)
	})

	if err != nil {
		return nil, err
	}

	return org, nil
}

// GetPendingInvitations retrieves pending invitations for an email
func (s *OrganizationService) GetPendingInvitations(ctx context.Context, email string) ([]*domain.Invitation, error) {
	return s.inviteRepo.ListByEmail(ctx, types.Email(utils.NormalizeEmail(email)))
}

// AcceptInvitationByID accepts an invitation by id for an authenticated
// invitee. The caller's email must match the invitation's `email` —
// otherwise this returns NotFound (constant-time shape; never reveals
// that a different user's invitation exists at this id).
//
// Backs POST /me/invitations/{id}/accept. The anonymous "register +
// accept via code" path stays on AcceptInvitation(ctx, userID, code).
func (s *OrganizationService) AcceptInvitationByID(ctx context.Context, userID types.ID, invitationID types.ID, userEmail types.Email) (*domain.Organization, error) {
	invitation, err := s.inviteRepo.GetByID(ctx, invitationID)
	if err != nil {
		return nil, err
	}
	if invitation.Email != userEmail {
		// Constant-time shape — same NotFound the repo would return for a
		// missing id, so a fishing user can't enumerate other people's
		// invitations.
		return nil, errors.NotFound("invitation")
	}
	return s.AcceptInvitation(ctx, userID, invitation.Code)
}

// DeclineInvitationByID marks an invitation as declined. Same caller-
// email check as AcceptInvitationByID; same NotFound-on-mismatch shape.
func (s *OrganizationService) DeclineInvitationByID(ctx context.Context, invitationID types.ID, userEmail types.Email) error {
	invitation, err := s.inviteRepo.GetByID(ctx, invitationID)
	if err != nil {
		return err
	}
	if invitation.Email != userEmail {
		return errors.NotFound("invitation")
	}
	if invitation.Status != domain.InvitationStatusPending {
		return errors.InviteAlreadyUsed()
	}
	invitation.Status = domain.InvitationStatusDeclined
	return s.inviteRepo.Update(ctx, invitation)
}

// TransferOwnership transfers organization ownership
func (s *OrganizationService) TransferOwnership(ctx context.Context, orgID, currentOwnerID, newOwnerID types.ID) error {
	org, err := s.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		return err
	}

	if org.OwnerID != currentOwnerID {
		return errors.Forbidden("Only the owner can transfer ownership")
	}

	// Verify new owner is a member
	_, err = s.orgRepo.GetMembership(ctx, newOwnerID, orgID)
	if err != nil {
		return errors.NotOrgMember()
	}

	org.OwnerID = newOwnerID
	return s.orgRepo.Update(ctx, org)
}

// ExpireInvitations marks expired invitations
func (s *OrganizationService) ExpireInvitations(ctx context.Context) error {
	// This would typically be run as a background job
	// Implementation depends on your specific needs
	return nil
}

// UpdateMemberStatus updates a member's status
func (s *OrganizationService) UpdateMemberStatus(ctx context.Context, userID, orgID types.ID, status domain.MembershipStatus) error {
	membership, err := s.orgRepo.GetMembership(ctx, userID, orgID)
	if err != nil {
		return err
	}

	// Don't allow suspending the owner
	org, err := s.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		return err
	}

	if org.OwnerID == userID && status == domain.MembershipStatusSuspended {
		return errors.ValidationError("Cannot suspend organization owner")
	}

	membership.Status = status
	return s.orgRepo.UpdateMembership(ctx, membership)
}
