// Package repository provides data access interfaces and implementations
package repository

import (
	"context"

	"github.com/lib/pq"

	"github.com/rw3iss/auth/internal/domain"
	"github.com/rw3iss/auth/pkg/shared/types"
)

// UserRepository defines the interface for user data access
type UserRepository interface {
	// CRUD operations
	Create(ctx context.Context, user *domain.User) error
	GetByID(ctx context.Context, id types.ID) (*domain.User, error)
	GetByEmail(ctx context.Context, email types.Email) (*domain.User, error)
	// GetByEmailInNamespaces resolves a user by email within a set of
	// user pools (migration 017 / docs/USER_POOLS.md). Used by login +
	// register to authenticate against an app's read namespaces. Earliest
	// matching namespace in the slice wins, then oldest account.
	GetByEmailInNamespaces(ctx context.Context, email types.Email, namespaces []string) (*domain.User, error)
	// AddUserToNamespaces tags a user into additional pools beyond the
	// home namespace (migration 018). Idempotent.
	AddUserToNamespaces(ctx context.Context, userID types.ID, namespaces []string) error
	// GetUserNamespaces lists every pool a user belongs to (home first).
	GetUserNamespaces(ctx context.Context, userID types.ID) ([]string, error)
	// RemoveUserFromNamespace deletes a pool tag (user_namespaces row).
	// The home pool (users.namespace) is untouched — callers reject
	// removing it at the service layer.
	RemoveUserFromNamespace(ctx context.Context, userID types.ID, namespace string) error
	// SetHomeNamespace moves a user's home pool (users.namespace).
	// Returns Conflict when another user already holds the same email in
	// the target pool (per-(namespace,email) uniqueness, migration 017).
	// Any tag row matching the new home pool is cleaned up.
	SetHomeNamespace(ctx context.Context, userID types.ID, namespace string) error
	// ListNamespaces aggregates every known pool: pools holding users
	// (home or tag) plus pools referenced by app configs, with user
	// counts and the referencing app codes. Powers GET /admin/namespaces.
	ListNamespaces(ctx context.Context) ([]*NamespaceInfo, error)
	Update(ctx context.Context, user *domain.User) error
	Delete(ctx context.Context, id types.ID) error
	// HardDelete physically removes the user row. Audit-preserving FKs are
	// SET NULL by migration 011; CASCADE FKs clean up dependents. AUDIT C8.
	HardDelete(ctx context.Context, id types.ID) error
	// CountOwnedOrganizations returns the number of orgs where this user
	// is owner. Used as a pre-flight check for HardDelete — the owner FK
	// has no ON DELETE action so a hard-delete with owned orgs would
	// surface a raw FK-violation error.
	CountOwnedOrganizations(ctx context.Context, id types.ID) (int, error)

	// Listing and search
	List(ctx context.Context, filter UserFilter) ([]*domain.User, int, error)
	Search(ctx context.Context, query string, pagination types.Pagination) ([]*domain.User, int, error)
	// Lookup resolves a batch of users by email and/or id in a single round-trip.
	// Either slice may be empty; both empty returns an empty result. The
	// returned slice preserves caller order intent only as best-effort —
	// duplicates across emails+ids collapse to a single row. Soft-deleted
	// users are excluded.
	//
	// Backs POST /admin/users/lookup (replaces the awkward
	// check-email + list-and-filter back-office workflow). See
	// AUTH-PHP-LARAVEL-DESIGN.md §5.
	Lookup(ctx context.Context, emails []types.Email, ids []types.ID) ([]*domain.User, error)

	// Authentication provider links
	GetByProviderID(ctx context.Context, provider types.AuthProvider, providerUserID string) (*domain.User, error)
	LinkProvider(ctx context.Context, link *domain.UserAuthProvider) error
	UnlinkProvider(ctx context.Context, userID types.ID, provider types.AuthProvider) error
	GetUserProviders(ctx context.Context, userID types.ID) ([]*domain.UserAuthProvider, error)

	// Base role management
	GetBaseRoles(ctx context.Context, userID types.ID) ([]*domain.Role, error)
	// GetBaseRolesByUserIDs fetches base roles for multiple users in
	// one round-trip. Result is keyed by user id; users with no base
	// roles are present in the map with an empty slice. Used by
	// /admin/users to attach roles to every row in a list response
	// without an N-query fan-out.
	GetBaseRolesByUserIDs(ctx context.Context, userIDs []types.ID) (map[types.ID][]*domain.Role, error)
	AssignBaseRole(ctx context.Context, assignment *domain.UserBaseRole) error
	RemoveBaseRole(ctx context.Context, userID, roleID types.ID) error

	// Organization memberships
	GetOrganizations(ctx context.Context, userID types.ID) ([]*domain.OrganizationMembership, error)
}

// M2MClientRepository is the data-access contract for the OAuth2
// client_credentials registry (POST /oauth/token consumers). One row
// per registered machine consumer.
//
// The hot path is GetByClientID — every /oauth/token grant reads one
// row keyed on the operator-chosen client_id. The list / create /
// revoke methods are admin-only and tolerate non-indexed scans.
type M2MClientRepository interface {
	// Create inserts a new client. Caller must hash the secret before
	// passing (the repo never sees plaintext). Returns
	// shared/errors.InvalidInput on client_id collision.
	Create(ctx context.Context, c *domain.M2MClient) error

	// GetByID resolves by UUID primary key (admin paths). Returns
	// shared/errors.NotFound when absent.
	GetByID(ctx context.Context, id types.ID) (*domain.M2MClient, error)

	// GetByClientID is the grant hot path — keyed on the operator's
	// client_id string. Filters out revoked rows; the service decides
	// whether to honor disabled status. Returns NotFound when missing
	// or revoked (same shape — prevents enumeration).
	GetByClientID(ctx context.Context, clientID string) (*domain.M2MClient, error)

	// List returns every non-revoked client. No pagination — M2M
	// inventories are intentionally small.
	List(ctx context.Context) ([]*domain.M2MClient, error)

	// Revoke soft-revokes a client. Idempotent.
	Revoke(ctx context.Context, id types.ID) error

	// StampLastUsed updates last_used_at on successful grant. Service
	// layer logs failures but doesn't fail the grant (token already
	// minted; this is bookkeeping).
	StampLastUsed(ctx context.Context, id types.ID) error
}

// UserFilter defines filtering options for user listing
type UserFilter struct {
	Status        *types.UserStatus
	EmailVerified *bool
	AuthProvider  *types.AuthProvider
	// OrganizationID restricts to active members of one organization.
	OrganizationID *types.ID
	// AppID restricts to users with an active user_apps membership in
	// one app (i.e. they have actually entered the app — NOT merely
	// "the app's pools would accept them").
	AppID      *types.ID
	Pagination types.Pagination
	SortBy     string
	SortOrder  types.SortOrder
}

// NamespaceInfo is one aggregated user-pool row for GET /admin/namespaces.
// Pools are virtual (no pools table) — a pool "exists" because a user
// lives in it (home), is tagged into it, or an app's pool config
// references it. UserCount counts distinct non-deleted users matching
// home OR tag; a pool with UserCount 0 is referenced by app config only.
type NamespaceInfo struct {
	Namespace string         `db:"namespace" json:"namespace"`
	UserCount int            `db:"user_count" json:"user_count"`
	HomeCount int            `db:"home_count" json:"home_count"`
	TagCount  int            `db:"tag_count" json:"tag_count"`
	AppCodes  pq.StringArray `db:"app_codes" json:"app_codes"`
}

// OrganizationRepository defines the interface for organization data access
type OrganizationRepository interface {
	// CRUD operations
	Create(ctx context.Context, org *domain.Organization) error
	GetByID(ctx context.Context, id types.ID) (*domain.Organization, error)
	GetBySlug(ctx context.Context, slug string) (*domain.Organization, error)
	Update(ctx context.Context, org *domain.Organization) error
	Delete(ctx context.Context, id types.ID) error

	// Listing
	List(ctx context.Context, filter OrganizationFilter) ([]*domain.Organization, int, error)

	// Membership management
	AddMember(ctx context.Context, membership *domain.OrganizationMembership) error
	GetMembership(ctx context.Context, userID, orgID types.ID) (*domain.OrganizationMembership, error)
	UpdateMembership(ctx context.Context, membership *domain.OrganizationMembership) error
	RemoveMember(ctx context.Context, userID, orgID types.ID) error
	ListMembers(ctx context.Context, orgID types.ID, filter MemberFilter) ([]*domain.OrganizationMembership, int, error)

	// Member role management
	AssignMemberRole(ctx context.Context, assignment *domain.OrganizationMemberRole) error
	RemoveMemberRole(ctx context.Context, membershipID, roleID types.ID) error
	GetMemberRoles(ctx context.Context, membershipID types.ID) ([]*domain.Role, error)
	// GetMemberRolesBatch returns the roles for every supplied membership
	// in a single query (AUDIT 4.2). Used by ListMembers to avoid the
	// per-row N+1 loop.
	GetMemberRolesBatch(ctx context.Context, membershipIDs []types.ID) (map[types.ID][]*domain.Role, error)
}

// OrganizationFilter defines filtering options for organization listing
type OrganizationFilter struct {
	Status     *types.OrganizationStatus
	OwnerID    *types.ID
	Pagination types.Pagination
	SortBy     string
	SortOrder  types.SortOrder
}

// MemberFilter defines filtering options for member listing
type MemberFilter struct {
	Status     *domain.MembershipStatus
	RoleID     *types.ID
	Pagination types.Pagination
	SortBy     string
	SortOrder  types.SortOrder
}

// RoleRepository defines the interface for role data access
type RoleRepository interface {
	// CRUD operations
	Create(ctx context.Context, role *domain.Role) error
	GetByID(ctx context.Context, id types.ID) (*domain.Role, error)
	GetByCode(ctx context.Context, code string) (*domain.Role, error)
	Update(ctx context.Context, role *domain.Role) error
	Delete(ctx context.Context, id types.ID) error

	// Listing
	ListSystemRoles(ctx context.Context) ([]*domain.Role, error)
	ListOrgRoles(ctx context.Context, orgID types.ID) ([]*domain.Role, error)
	ListAll(ctx context.Context, filter RoleFilter) ([]*domain.Role, int, error)

	// Permission management
	AssignPermission(ctx context.Context, roleID, permissionID types.ID) error
	RemovePermission(ctx context.Context, roleID, permissionID types.ID) error
	GetPermissions(ctx context.Context, roleID types.ID) ([]*domain.Permission, error)
	// GetPermissionsForRoles batches the per-role permission fetch so login /
	// refresh / SSO don't fan out one query per role. AUDIT 4.1. Returns a
	// distinct slice of permissions across all listed roles.
	GetPermissionsForRoles(ctx context.Context, roleIDs []types.ID) ([]*domain.Permission, error)
	SetPermissions(ctx context.Context, roleID types.ID, permissionIDs []types.ID) error
}

// RoleFilter defines filtering options for role listing
type RoleFilter struct {
	Type           *string
	IsOrgRole      *bool
	OrganizationID *types.ID
	Pagination     types.Pagination
}

// PermissionRepository defines the interface for permission data access
type PermissionRepository interface {
	// CRUD operations
	Create(ctx context.Context, permission *domain.Permission) error
	GetByID(ctx context.Context, id types.ID) (*domain.Permission, error)
	GetByCode(ctx context.Context, code string) (*domain.Permission, error)

	// Listing
	List(ctx context.Context, filter PermissionFilter) ([]*domain.Permission, int, error)
	ListByCategory(ctx context.Context, category string) ([]*domain.Permission, error)
	ListByResource(ctx context.Context, resource string) ([]*domain.Permission, error)

	// Bulk operations
	GetByIDs(ctx context.Context, ids []types.ID) ([]*domain.Permission, error)
	GetByCodes(ctx context.Context, codes []string) ([]*domain.Permission, error)
	// Service-scoped lookups. Codes are unique per (service, code) since migration 026, so anything
	// acting on behalf of one service must resolve through these rather than the ambiguous GetByCode.
	GetByServiceCode(ctx context.Context, service, code string) (*domain.Permission, error)
	GetByCodesForServices(ctx context.Context, codes, services []string) ([]*domain.Permission, error)

	// AllOrgAssignable returns IDs from the input set that are NOT
	// org_assignable. Empty result means every supplied ID is safe for an
	// org admin to grant via a custom role. AUDIT C3.
	AllOrgAssignable(ctx context.Context, ids []types.ID) ([]types.ID, error)

	// Service-scoped reconciliation (declarative upsert + prune)
	SyncForService(ctx context.Context, service string, perms []*domain.Permission) error
}

// PermissionFilter defines filtering options for permission listing
type PermissionFilter struct {
	Resource *string
	Action   *string
	Category *string
	// OrgAssignable, when non-nil, narrows to permissions where the flag
	// matches (AUDIT C3). Used by the org-self-service surface to list the
	// permission catalog an org admin is allowed to grant.
	OrgAssignable *bool
	Pagination    types.Pagination
}

// InvitationRepository defines the interface for invitation data access
type InvitationRepository interface {
	// CRUD operations
	Create(ctx context.Context, invitation *domain.Invitation) error
	GetByID(ctx context.Context, id types.ID) (*domain.Invitation, error)
	GetByCode(ctx context.Context, code string) (*domain.Invitation, error)
	GetByToken(ctx context.Context, token string) (*domain.Invitation, error)
	Update(ctx context.Context, invitation *domain.Invitation) error
	Delete(ctx context.Context, id types.ID) error

	// Listing
	ListByOrganization(ctx context.Context, orgID types.ID, filter InvitationFilter) ([]*domain.Invitation, int, error)
	ListByEmail(ctx context.Context, email types.Email) ([]*domain.Invitation, error)

	// Invitation roles
	AddRole(ctx context.Context, invitationID, roleID types.ID) error
	RemoveRole(ctx context.Context, invitationID, roleID types.ID) error
	GetRoles(ctx context.Context, invitationID types.ID) ([]types.ID, error)
}

// InvitationFilter defines filtering options for invitation listing
type InvitationFilter struct {
	Status     *domain.InvitationStatus
	Email      *types.Email
	Pagination types.Pagination
}

// TokenRepository defines the interface for token data access
type TokenRepository interface {
	// Refresh tokens
	CreateRefreshToken(ctx context.Context, token *domain.RefreshToken) error
	GetRefreshToken(ctx context.Context, tokenHash string) (*domain.RefreshToken, error)
	GetRefreshTokenByID(ctx context.Context, id types.ID) (*domain.RefreshToken, error)
	UpdateRefreshToken(ctx context.Context, token *domain.RefreshToken) error
	RevokeRefreshToken(ctx context.Context, id types.ID, reason string) error
	// RevokeRefreshTokenFamily revokes every live row sharing the given
	// family_id. Returns the number of rows updated. AUDIT 1.9: used when a
	// revoked refresh token is presented again (reuse → presumed theft).
	RevokeRefreshTokenFamily(ctx context.Context, familyID types.ID, reason string) (int, error)
	RevokeAllUserTokens(ctx context.Context, userID types.ID, reason string) error
	RevokeUserOrgTokens(ctx context.Context, userID, orgID types.ID, reason string) error
	ListUserRefreshTokens(ctx context.Context, userID types.ID) ([]*domain.RefreshToken, error)
	CleanupExpiredTokens(ctx context.Context) (int, error)

	// Password reset tokens
	CreatePasswordResetToken(ctx context.Context, token *domain.PasswordResetToken) error
	GetPasswordResetToken(ctx context.Context, tokenHash string) (*domain.PasswordResetToken, error)
	// GetPasswordResetTokenByID is the lookup keyed by the JWT `jti` (the
	// stored row's id). Used by the single-use enforcement in
	// AuthService.ResetPassword — see AUDIT 1.1.
	GetPasswordResetTokenByID(ctx context.Context, id types.ID) (*domain.PasswordResetToken, error)
	MarkPasswordResetTokenUsed(ctx context.Context, id types.ID) error
	InvalidateUserPasswordResetTokens(ctx context.Context, userID types.ID) error

	// Email verification tokens
	CreateEmailVerificationToken(ctx context.Context, token *domain.EmailVerificationToken) error
	GetEmailVerificationToken(ctx context.Context, tokenHash string) (*domain.EmailVerificationToken, error)
	// GetEmailVerificationTokenByID is the lookup keyed by the JWT `jti`.
	// Used by single-use enforcement in AuthService.VerifyEmail — AUDIT 1.2.
	GetEmailVerificationTokenByID(ctx context.Context, id types.ID) (*domain.EmailVerificationToken, error)
	MarkEmailVerificationTokenUsed(ctx context.Context, id types.ID) error
	InvalidateUserEmailVerificationTokens(ctx context.Context, userID types.ID) error

	// Sessions
	CreateSession(ctx context.Context, session *domain.Session) error
	GetSession(ctx context.Context, id types.ID) (*domain.Session, error)
	UpdateSession(ctx context.Context, session *domain.Session) error
	TerminateSession(ctx context.Context, id types.ID) error
	TerminateAllUserSessions(ctx context.Context, userID types.ID) error
	ListUserSessions(ctx context.Context, userID types.ID) ([]*domain.Session, error)
}

// AppRepository persists consuming-app definitions and the user_apps
// membership table. AUDIT 8.3-8.7 / docs/APP_REGISTRATION.md.
type AppRepository interface {
	Create(ctx context.Context, app *domain.App) error
	GetByID(ctx context.Context, id types.ID) (*domain.App, error)
	GetByCode(ctx context.Context, code string) (*domain.App, error)
	List(ctx context.Context) ([]*domain.App, error)
	Update(ctx context.Context, app *domain.App) error
	SoftDelete(ctx context.Context, id types.ID) error

	// user_apps
	Grant(ctx context.Context, userID, appID types.ID, grantedBy *types.ID) error
	Revoke(ctx context.Context, userID, appID types.ID) error
	GetMembership(ctx context.Context, userID, appID types.ID) (*domain.UserApp, error)
	ListForUser(ctx context.Context, userID types.ID) ([]*domain.App, error)
}

// Transaction represents a database transaction
type Transaction interface {
	Commit() error
	Rollback() error
}

// TransactionManager manages database transactions
type TransactionManager interface {
	Begin(ctx context.Context) (Transaction, error)
	WithTransaction(ctx context.Context, fn func(ctx context.Context) error) error
}
