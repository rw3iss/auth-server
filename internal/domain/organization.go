package domain

import (
	"github.com/rw3iss/auth/pkg/shared/models"
	"github.com/rw3iss/auth/pkg/shared/types"
)

// Organization extends BaseOrganization with auth-specific fields
type Organization struct {
	models.BaseOrganization

	// Owner of the organization
	OwnerID types.ID `json:"owner_id" db:"owner_id"`

	// SSO configuration for the organization
	SSOEnabled   bool            `json:"sso_enabled" db:"sso_enabled"`
	SSOProvider  string          `json:"sso_provider,omitempty" db:"sso_provider"`
	SSOConfig    types.JSON      `json:"-" db:"sso_config"`

	// Subscription/billing info (for future use)
	Plan         string          `json:"plan,omitempty" db:"plan"`
	PlanExpiry   *types.Timestamp `json:"plan_expiry,omitempty" db:"plan_expiry"`

	// Loaded associations
	Members      []OrganizationMembership `json:"members,omitempty" db:"-"`
	CustomRoles  []Role                   `json:"custom_roles,omitempty" db:"-"`
}

// NewOrganization creates a new Organization
func NewOrganization(name, slug string, ownerID types.ID) *Organization {
	return &Organization{
		BaseOrganization: models.BaseOrganization{
			BaseModel: models.NewBaseModel(),
			Name:      name,
			Slug:      slug,
			Status:    types.OrgStatusActive,
		},
		OwnerID: ownerID,
		Plan:    "free",
	}
}

// OrganizationMembership represents a user's membership in an organization
type OrganizationMembership struct {
	models.BaseModel
	models.SoftDeletable

	UserID         types.ID         `json:"user_id" db:"user_id"`
	OrganizationID types.ID         `json:"organization_id" db:"organization_id"`
	Status         MembershipStatus `json:"status" db:"status"`
	JoinedAt       types.Timestamp  `json:"joined_at" db:"joined_at"`
	InvitedBy      *types.ID        `json:"invited_by,omitempty" db:"invited_by"`

	// Loaded associations
	User         *User         `json:"user,omitempty" db:"-"`
	Organization *Organization `json:"organization,omitempty" db:"-"`
	Roles        []Role        `json:"roles,omitempty" db:"-"`
}

// MembershipStatus represents the status of an organization membership
type MembershipStatus string

const (
	MembershipStatusPending  MembershipStatus = "pending"
	MembershipStatusActive   MembershipStatus = "active"
	MembershipStatusSuspended MembershipStatus = "suspended"
	MembershipStatusRemoved  MembershipStatus = "removed"
)

// NewOrganizationMembership creates a new membership
func NewOrganizationMembership(userID, orgID types.ID) *OrganizationMembership {
	return &OrganizationMembership{
		BaseModel:      models.NewBaseModel(),
		UserID:         userID,
		OrganizationID: orgID,
		Status:         MembershipStatusActive,
		JoinedAt:       types.Now(),
	}
}

// IsActive checks if the membership is active
func (m *OrganizationMembership) IsActive() bool {
	return m.Status == MembershipStatusActive && !m.IsDeleted()
}

// OrganizationMemberRole links a membership to a role
type OrganizationMemberRole struct {
	models.BaseModel

	MembershipID types.ID `json:"membership_id" db:"membership_id"`
	RoleID       types.ID `json:"role_id" db:"role_id"`
	AssignedBy   types.ID `json:"assigned_by" db:"assigned_by"`
	AssignedAt   types.Timestamp `json:"assigned_at" db:"assigned_at"`
}

// NewOrganizationMemberRole creates a new member-role assignment
func NewOrganizationMemberRole(membershipID, roleID, assignedBy types.ID) *OrganizationMemberRole {
	return &OrganizationMemberRole{
		BaseModel:    models.NewBaseModel(),
		MembershipID: membershipID,
		RoleID:       roleID,
		AssignedBy:   assignedBy,
		AssignedAt:   types.Now(),
	}
}

// Invitation represents an invitation to join an organization
type Invitation struct {
	models.BaseModel

	OrganizationID types.ID          `json:"organization_id" db:"organization_id"`
	Email          types.Email       `json:"email" db:"email"`
	Code           string            `json:"code" db:"code"`
	Token          string            `json:"-" db:"token"`
	RoleIDs        []types.ID        `json:"role_ids" db:"-"` // Roles to assign on acceptance
	InvitedBy      types.ID          `json:"invited_by" db:"invited_by"`
	ExpiresAt      types.Timestamp   `json:"expires_at" db:"expires_at"`
	Status         InvitationStatus  `json:"status" db:"status"`
	AcceptedAt     *types.Timestamp  `json:"accepted_at,omitempty" db:"accepted_at"`
	AcceptedBy     *types.ID         `json:"accepted_by,omitempty" db:"accepted_by"`

	// Loaded associations
	Organization *Organization `json:"organization,omitempty" db:"-"`
	InvitedByUser *User        `json:"invited_by_user,omitempty" db:"-"`
}

// InvitationStatus represents the status of an invitation
type InvitationStatus string

const (
	InvitationStatusPending  InvitationStatus = "pending"
	InvitationStatusAccepted InvitationStatus = "accepted"
	InvitationStatusDeclined InvitationStatus = "declined"
	InvitationStatusExpired  InvitationStatus = "expired"
	InvitationStatusRevoked  InvitationStatus = "revoked"
)

// IsValid checks if the invitation is valid and can be used
func (i *Invitation) IsValid() bool {
	return i.Status == InvitationStatusPending && types.Now().Before(i.ExpiresAt)
}

// Accept marks the invitation as accepted
func (i *Invitation) Accept(userID types.ID) {
	i.Status = InvitationStatusAccepted
	now := types.Now()
	i.AcceptedAt = &now
	i.AcceptedBy = &userID
}

// InvitationRole links an invitation to roles that will be assigned
type InvitationRole struct {
	InvitationID types.ID `json:"invitation_id" db:"invitation_id"`
	RoleID       types.ID `json:"role_id" db:"role_id"`
}
