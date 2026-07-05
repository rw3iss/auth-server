package models

import (
	"github.com/rw3iss/auth/pkg/shared/types"
)

// BaseOrganization represents an organization/tenant in the platform
type BaseOrganization struct {
	BaseModel
	SoftDeletable

	Name        string                 `json:"name" db:"name"`
	Slug        string                 `json:"slug" db:"slug"` // URL-friendly identifier
	Description string                 `json:"description,omitempty" db:"description"`
	LogoURL     string                 `json:"logo_url,omitempty" db:"logo_url"`
	Website     string                 `json:"website,omitempty" db:"website"`
	Status      types.OrganizationStatus `json:"status" db:"status"`

	// Contact information
	ContactEmail types.Email      `json:"contact_email,omitempty" db:"contact_email"`
	ContactPhone types.PhoneNumber `json:"contact_phone,omitempty" db:"contact_phone"`

	// Address information
	Address    string `json:"address,omitempty" db:"address"`
	City       string `json:"city,omitempty" db:"city"`
	State      string `json:"state,omitempty" db:"state"`
	Country    string `json:"country,omitempty" db:"country"`
	PostalCode string `json:"postal_code,omitempty" db:"postal_code"`

	// Settings
	Settings types.JSON `json:"settings,omitempty" db:"settings"`
	Metadata types.JSON `json:"metadata,omitempty" db:"metadata"`
}

// IsActive checks if the organization is active
func (o *BaseOrganization) IsActive() bool {
	return o.Status == types.OrgStatusActive && !o.IsDeleted()
}

// BaseOrganizationSummary provides a minimal view of organization data
type BaseOrganizationSummary struct {
	ID      types.ID                 `json:"id"`
	Name    string                   `json:"name"`
	Slug    string                   `json:"slug"`
	LogoURL string                   `json:"logo_url,omitempty"`
	Status  types.OrganizationStatus `json:"status"`
}

// ToSummary converts a BaseOrganization to BaseOrganizationSummary
func (o *BaseOrganization) ToSummary() BaseOrganizationSummary {
	return BaseOrganizationSummary{
		ID:      o.ID,
		Name:    o.Name,
		Slug:    o.Slug,
		LogoURL: o.LogoURL,
		Status:  o.Status,
	}
}
