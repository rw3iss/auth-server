package dto

import (
	"github.com/ven/auth/internal/domain"
)

// OrganizationResponse represents an organization in API responses
type OrganizationResponse struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Slug         string `json:"slug"`
	Description  string `json:"description,omitempty"`
	LogoURL      string `json:"logo_url,omitempty"`
	Website      string `json:"website,omitempty"`
	Status       string `json:"status"`
	ContactEmail string `json:"contact_email,omitempty"`
	ContactPhone string `json:"contact_phone,omitempty"`
	Address      string `json:"address,omitempty"`
	City         string `json:"city,omitempty"`
	State        string `json:"state,omitempty"`
	Country      string `json:"country,omitempty"`
	PostalCode   string `json:"postal_code,omitempty"`
	OwnerID      string `json:"owner_id"`
	Plan         string `json:"plan,omitempty"`
	SSOEnabled   bool   `json:"sso_enabled"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
}

// ToOrganizationResponse converts a domain organization to response
func ToOrganizationResponse(org *domain.Organization) *OrganizationResponse {
	return &OrganizationResponse{
		ID:           org.ID.String(),
		Name:         org.Name,
		Slug:         org.Slug,
		Description:  org.Description,
		LogoURL:      org.LogoURL,
		Website:      org.Website,
		Status:       string(org.Status),
		ContactEmail: string(org.ContactEmail),
		ContactPhone: string(org.ContactPhone),
		Address:      org.Address,
		City:         org.City,
		State:        org.State,
		Country:      org.Country,
		PostalCode:   org.PostalCode,
		OwnerID:      org.OwnerID.String(),
		Plan:         org.Plan,
		SSOEnabled:   org.SSOEnabled,
		CreatedAt:    org.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:    org.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
}

// CreateOrganizationRequest represents a request to create an organization
type CreateOrganizationRequest struct {
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

// UpdateOrganizationRequest represents a request to update an organization
type UpdateOrganizationRequest struct {
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

// ListOrganizationsRequest represents a request to list organizations
type ListOrganizationsRequest struct {
	Status    string `query:"status"`
	Page      int    `query:"page"`
	PageSize  int    `query:"page_size"`
	SortBy    string `query:"sort_by"`
	SortOrder string `query:"sort_order"`
}

// ListOrganizationsResponse represents the response for listing organizations
type ListOrganizationsResponse struct {
	Organizations []*OrganizationResponse `json:"organizations"`
	Pagination    PaginationResponse      `json:"pagination"`
}

// MemberResponse represents a member in API responses
type MemberResponse struct {
	ID             string          `json:"id"`
	UserID         string          `json:"user_id"`
	OrganizationID string          `json:"organization_id"`
	Status         string          `json:"status"`
	JoinedAt       string          `json:"joined_at"`
	User           *UserResponse   `json:"user,omitempty"`
	Roles          []*RoleResponse `json:"roles,omitempty"`
}

// ToMemberResponse converts a domain membership to response
func ToMemberResponse(membership *domain.OrganizationMembership) *MemberResponse {
	resp := &MemberResponse{
		ID:             membership.ID.String(),
		UserID:         membership.UserID.String(),
		OrganizationID: membership.OrganizationID.String(),
		Status:         string(membership.Status),
		JoinedAt:       membership.JoinedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	if membership.User != nil {
		resp.User = ToUserResponse(membership.User)
	}

	if len(membership.Roles) > 0 {
		resp.Roles = make([]*RoleResponse, len(membership.Roles))
		for i, role := range membership.Roles {
			resp.Roles[i] = ToRoleResponse(&role)
		}
	}

	return resp
}

// ListMembersRequest represents a request to list members
type ListMembersRequest struct {
	Status   string `query:"status"`
	RoleID   string `query:"role_id"`
	Page     int    `query:"page"`
	PageSize int    `query:"page_size"`
	SortBy   string `query:"sort_by"`
	SortOrder string `query:"sort_order"`
}

// ListMembersResponse represents the response for listing members
type ListMembersResponse struct {
	Members    []*MemberResponse  `json:"members"`
	Pagination PaginationResponse `json:"pagination"`
}

// AddMemberRequest represents a request to add a member
type AddMemberRequest struct {
	UserID  string   `json:"user_id" validate:"required"`
	RoleIDs []string `json:"role_ids"`
}

// AssignRoleRequest represents a request to assign a role to a member
type AssignRoleRequest struct {
	RoleID string `json:"role_id" validate:"required"`
}

// InvitationResponse represents an invitation in API responses
type InvitationResponse struct {
	ID             string   `json:"id"`
	OrganizationID string   `json:"organization_id"`
	Email          string   `json:"email"`
	Code           string   `json:"code"`
	Status         string   `json:"status"`
	RoleIDs        []string `json:"role_ids,omitempty"`
	InvitedBy      string   `json:"invited_by"`
	ExpiresAt      string   `json:"expires_at"`
	AcceptedAt     string   `json:"accepted_at,omitempty"`
	CreatedAt      string   `json:"created_at"`
}

// ToInvitationResponse converts a domain invitation to response
func ToInvitationResponse(invitation *domain.Invitation) *InvitationResponse {
	resp := &InvitationResponse{
		ID:             invitation.ID.String(),
		OrganizationID: invitation.OrganizationID.String(),
		Email:          string(invitation.Email),
		Code:           invitation.Code,
		Status:         string(invitation.Status),
		InvitedBy:      invitation.InvitedBy.String(),
		ExpiresAt:      invitation.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
		CreatedAt:      invitation.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	if len(invitation.RoleIDs) > 0 {
		resp.RoleIDs = make([]string, len(invitation.RoleIDs))
		for i, id := range invitation.RoleIDs {
			resp.RoleIDs[i] = id.String()
		}
	}

	if invitation.AcceptedAt != nil {
		resp.AcceptedAt = invitation.AcceptedAt.Format("2006-01-02T15:04:05Z07:00")
	}

	return resp
}

// CreateInvitationRequest represents a request to create an invitation
type CreateInvitationRequest struct {
	Email   string   `json:"email" validate:"required,email"`
	RoleIDs []string `json:"role_ids"`
}

// ListInvitationsRequest represents a request to list invitations
type ListInvitationsRequest struct {
	Status   string `query:"status"`
	Page     int    `query:"page"`
	PageSize int    `query:"page_size"`
}

// ListInvitationsResponse represents the response for listing invitations
type ListInvitationsResponse struct {
	Invitations []*InvitationResponse `json:"invitations"`
	Pagination  PaginationResponse    `json:"pagination"`
}

// AcceptInvitationRequest represents a request to accept an invitation
type AcceptInvitationRequest struct {
	Code string `json:"code" validate:"required"`
}

// TransferOwnershipRequest represents a request to transfer ownership
type TransferOwnershipRequest struct {
	NewOwnerID string `json:"new_owner_id" validate:"required"`
}
