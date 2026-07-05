package models

import (
	"github.com/ven/auth/pkg/shared/types"
)

// Permission represents an action that can be performed in the system
type Permission struct {
	BaseModel

	Code        string `json:"code" db:"code"`               // Unique identifier (e.g., "auctions:create")
	Name        string `json:"name" db:"name"`               // Human-readable name
	Description string `json:"description" db:"description"` // Description of what this permission allows
	Resource    string `json:"resource" db:"resource"`       // The resource this permission applies to
	Action      string `json:"action" db:"action"`           // The action (create, read, update, delete, etc.)
	Category    string `json:"category" db:"category"`       // Category for grouping permissions
	Service     string `json:"service" db:"service"`         // Owning service (e.g., "release-manager"); "core" = auth-server

	// OrgAssignable controls whether an org admin can grant this permission
	// via a custom role at /orgs/{orgId}/roles (AUDIT C3). System-level
	// permissions (organizations:delete, users:impersonate, …) remain
	// reserved to system_admin / super_admin even within a custom role.
	OrgAssignable bool `json:"org_assignable" db:"org_assignable"`

	Metadata types.JSON `json:"metadata,omitempty" db:"metadata"`
}

// PermissionCode generates the standard permission code format
func PermissionCode(resource, action string) string {
	return resource + ":" + action
}

// PermissionSummary provides a minimal view of permission data
type PermissionSummary struct {
	ID       types.ID `json:"id"`
	Code     string   `json:"code"`
	Name     string   `json:"name"`
	Resource string   `json:"resource"`
	Action   string   `json:"action"`
}

// ToSummary converts a Permission to PermissionSummary
func (p *Permission) ToSummary() PermissionSummary {
	return PermissionSummary{
		ID:       p.ID,
		Code:     p.Code,
		Name:     p.Name,
		Resource: p.Resource,
		Action:   p.Action,
	}
}

// Resource constants for the auction platform
const (
	ResourceUsers        = "users"
	ResourceOrganizations = "organizations"
	ResourceRoles        = "roles"
	ResourcePermissions  = "permissions"
	ResourceAuctions     = "auctions"
	ResourceBids         = "bids"
	ResourceItems        = "items"
	ResourceInvitations  = "invitations"
	ResourceSettings     = "settings"
	ResourceReports      = "reports"
)

// Action constants
const (
	ActionCreate  = "create"
	ActionRead    = "read"
	ActionUpdate  = "update"
	ActionDelete  = "delete"
	ActionList    = "list"
	ActionManage  = "manage"  // Full control
	ActionApprove = "approve"
	ActionReject  = "reject"
	ActionInvite  = "invite"
	ActionAssign  = "assign"
)

// Predefined permission codes for the auction platform
var (
	// User permissions
	PermUsersCreate  = PermissionCode(ResourceUsers, ActionCreate)
	PermUsersRead    = PermissionCode(ResourceUsers, ActionRead)
	PermUsersUpdate  = PermissionCode(ResourceUsers, ActionUpdate)
	PermUsersDelete  = PermissionCode(ResourceUsers, ActionDelete)
	PermUsersList    = PermissionCode(ResourceUsers, ActionList)
	PermUsersManage  = PermissionCode(ResourceUsers, ActionManage)
	PermUsersInvite  = PermissionCode(ResourceUsers, ActionInvite)

	// Organization permissions
	PermOrgsCreate  = PermissionCode(ResourceOrganizations, ActionCreate)
	PermOrgsRead    = PermissionCode(ResourceOrganizations, ActionRead)
	PermOrgsUpdate  = PermissionCode(ResourceOrganizations, ActionUpdate)
	PermOrgsDelete  = PermissionCode(ResourceOrganizations, ActionDelete)
	PermOrgsList    = PermissionCode(ResourceOrganizations, ActionList)
	PermOrgsManage  = PermissionCode(ResourceOrganizations, ActionManage)

	// Role permissions
	PermRolesCreate = PermissionCode(ResourceRoles, ActionCreate)
	PermRolesRead   = PermissionCode(ResourceRoles, ActionRead)
	PermRolesUpdate = PermissionCode(ResourceRoles, ActionUpdate)
	PermRolesDelete = PermissionCode(ResourceRoles, ActionDelete)
	PermRolesList   = PermissionCode(ResourceRoles, ActionList)
	PermRolesAssign = PermissionCode(ResourceRoles, ActionAssign)

	// Permission permissions
	PermPermissionsRead = PermissionCode(ResourcePermissions, ActionRead)
	PermPermissionsList = PermissionCode(ResourcePermissions, ActionList)

	// Auction permissions
	PermAuctionsCreate  = PermissionCode(ResourceAuctions, ActionCreate)
	PermAuctionsRead    = PermissionCode(ResourceAuctions, ActionRead)
	PermAuctionsUpdate  = PermissionCode(ResourceAuctions, ActionUpdate)
	PermAuctionsDelete  = PermissionCode(ResourceAuctions, ActionDelete)
	PermAuctionsList    = PermissionCode(ResourceAuctions, ActionList)
	PermAuctionsManage  = PermissionCode(ResourceAuctions, ActionManage)
	PermAuctionsApprove = PermissionCode(ResourceAuctions, ActionApprove)

	// Bid permissions
	PermBidsCreate = PermissionCode(ResourceBids, ActionCreate)
	PermBidsRead   = PermissionCode(ResourceBids, ActionRead)
	PermBidsList   = PermissionCode(ResourceBids, ActionList)

	// Item permissions
	PermItemsCreate = PermissionCode(ResourceItems, ActionCreate)
	PermItemsRead   = PermissionCode(ResourceItems, ActionRead)
	PermItemsUpdate = PermissionCode(ResourceItems, ActionUpdate)
	PermItemsDelete = PermissionCode(ResourceItems, ActionDelete)
	PermItemsList   = PermissionCode(ResourceItems, ActionList)

	// Invitation permissions
	PermInvitationsCreate = PermissionCode(ResourceInvitations, ActionCreate)
	PermInvitationsRead   = PermissionCode(ResourceInvitations, ActionRead)
	PermInvitationsDelete = PermissionCode(ResourceInvitations, ActionDelete)
	PermInvitationsList   = PermissionCode(ResourceInvitations, ActionList)

	// Settings permissions
	PermSettingsRead   = PermissionCode(ResourceSettings, ActionRead)
	PermSettingsUpdate = PermissionCode(ResourceSettings, ActionUpdate)

	// Reports permissions
	PermReportsRead = PermissionCode(ResourceReports, ActionRead)
	PermReportsList = PermissionCode(ResourceReports, ActionList)
)
