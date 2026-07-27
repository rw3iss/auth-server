package service

import (
	"context"
	"strings"

	"github.com/rw3iss/auth/internal/domain"
	"github.com/rw3iss/auth/internal/repository"
	"github.com/rw3iss/auth/pkg/shared/errors"
	"github.com/rw3iss/auth/pkg/shared/types"
	"github.com/rw3iss/auth/pkg/shared/utils"
)

// UserService handles user management business logic
type UserService struct {
	userRepo  repository.UserRepository
	orgRepo   repository.OrganizationRepository
	roleRepo  repository.RoleRepository
	txManager repository.TransactionManager
}

// NewUserService creates a new user service
func NewUserService(
	userRepo repository.UserRepository,
	orgRepo repository.OrganizationRepository,
	roleRepo repository.RoleRepository,
	txManager repository.TransactionManager,
) *UserService {
	return &UserService{
		userRepo:  userRepo,
		orgRepo:   orgRepo,
		roleRepo:  roleRepo,
		txManager: txManager,
	}
}

// GetUser retrieves a user by ID
func (s *UserService) GetUser(ctx context.Context, id types.ID) (*domain.User, error) {
	return s.userRepo.GetByID(ctx, id)
}

// GetUserByEmail retrieves a user by email
func (s *UserService) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	return s.userRepo.GetByEmail(ctx, types.Email(utils.NormalizeEmail(email)))
}

// UpdateUserInput contains input for updating a user
type UpdateUserInput struct {
	FirstName   *string `json:"first_name,omitempty"`
	LastName    *string `json:"last_name,omitempty"`
	DisplayName *string `json:"display_name,omitempty"`
	Phone       *string `json:"phone,omitempty"`
	AvatarURL   *string `json:"avatar_url,omitempty"`
	// DefaultColorMode sets the user's preferred UI/email theme
	// ("dark"|"light"); invalid values coerce to "dark". Migration 021.
	DefaultColorMode *string `json:"default_color_mode,omitempty"`
}

// UpdateUser updates a user's profile
func (s *UserService) UpdateUser(ctx context.Context, userID types.ID, input UpdateUserInput) (*domain.User, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	if input.FirstName != nil {
		user.FirstName = *input.FirstName
	}
	if input.LastName != nil {
		user.LastName = *input.LastName
	}
	if input.DisplayName != nil {
		user.DisplayName = *input.DisplayName
	}
	if input.Phone != nil {
		user.Phone = types.PhoneNumber(*input.Phone)
	}
	if input.AvatarURL != nil {
		user.AvatarURL = *input.AvatarURL
	}
	if input.DefaultColorMode != nil {
		user.DefaultColorMode = domain.NormalizeColorMode(*input.DefaultColorMode)
	}

	if err := s.userRepo.Update(ctx, user); err != nil {
		return nil, err
	}

	return user, nil
}

// ListUsersInput contains input for listing users
type ListUsersInput struct {
	Status         *types.UserStatus
	EmailVerified  *bool
	AuthProvider   *types.AuthProvider
	OrganizationID *types.ID
	AppID          *types.ID
	Page           int
	PageSize       int
	SortBy         string
	SortOrder      types.SortOrder
}

// ListUsersResult contains the result of listing users
type ListUsersResult struct {
	Users      []*domain.User   `json:"users"`
	Pagination types.Pagination `json:"pagination"`
}

// ListUsers lists users with filtering
func (s *UserService) ListUsers(ctx context.Context, input ListUsersInput) (*ListUsersResult, error) {
	pagination := types.DefaultPagination()
	if input.Page > 0 {
		pagination.Page = input.Page
	}
	if input.PageSize > 0 {
		pagination.PageSize = input.PageSize
	}

	filter := repository.UserFilter{
		Status:         input.Status,
		EmailVerified:  input.EmailVerified,
		AuthProvider:   input.AuthProvider,
		OrganizationID: input.OrganizationID,
		AppID:          input.AppID,
		Pagination:     pagination,
		SortBy:         input.SortBy,
		SortOrder:      input.SortOrder,
	}

	users, total, err := s.userRepo.List(ctx, filter)
	if err != nil {
		return nil, err
	}

	pagination.Total = total

	return &ListUsersResult{
		Users:      users,
		Pagination: pagination,
	}, nil
}

// SearchUsers searches for users
func (s *UserService) SearchUsers(ctx context.Context, query string, page, pageSize int) (*ListUsersResult, error) {
	pagination := types.DefaultPagination()
	if page > 0 {
		pagination.Page = page
	}
	if pageSize > 0 {
		pagination.PageSize = pageSize
	}

	users, total, err := s.userRepo.Search(ctx, query, pagination)
	if err != nil {
		return nil, err
	}

	pagination.Total = total

	return &ListUsersResult{
		Users:      users,
		Pagination: pagination,
	}, nil
}

// SuspendUser suspends a user account
func (s *UserService) SuspendUser(ctx context.Context, userID types.ID) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	user.Suspend()
	return s.userRepo.Update(ctx, user)
}

// ActivateUser activates a user account
func (s *UserService) ActivateUser(ctx context.Context, userID types.ID) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	user.Activate()
	return s.userRepo.Update(ctx, user)
}

// DeleteUser soft deletes a user
func (s *UserService) DeleteUser(ctx context.Context, userID types.ID) error {
	return s.userRepo.Delete(ctx, userID)
}

// ResetLockout clears a user's failed-login counter + lock so an admin can
// unlock an account that was locked out by too many bad password attempts.
func (s *UserService) ResetLockout(ctx context.Context, userID types.ID) (*domain.User, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	user.ResetFailedLogin()
	if err := s.userRepo.Update(ctx, user); err != nil {
		return nil, err
	}
	return user, nil
}

// LookupUsersInput is the request envelope for bulk user lookup.
//
// At least one of Emails or IDs must be non-empty. Both may be present;
// the result is the union of matches (soft-deleted users excluded).
//
// Caps enforced by the service to keep abuse limited:
//   - max 200 entries across both slices combined
//   - duplicates within each slice are silently deduped before query
type LookupUsersInput struct {
	Emails []types.Email
	IDs    []types.ID
}

// Validate enforces the contract before hitting the repo. Returns a
// shared/errors invalid-input error so handler maps to 400.
func (i LookupUsersInput) Validate() error {
	total := len(i.Emails) + len(i.IDs)
	if total == 0 {
		return errors.InvalidInput("emails|ids", "at least one of emails or ids is required")
	}
	if total > 200 {
		return errors.InvalidInput("emails|ids", "max 200 lookup keys per request")
	}
	return nil
}

// dedupEmails returns a copy with duplicates removed (case-insensitive
// because the DB column is CITEXT, so duplicates differing only by case
// would all resolve to the same row anyway).
func dedupEmails(in []types.Email) []types.Email {
	if len(in) == 0 {
		return in
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]types.Email, 0, len(in))
	for _, e := range in {
		k := strings.ToLower(string(e))
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, e)
	}
	return out
}

// dedupIDs returns a copy with duplicate IDs removed.
func dedupIDs(in []types.ID) []types.ID {
	if len(in) == 0 {
		return in
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]types.ID, 0, len(in))
	for _, id := range in {
		k := id.String()
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, id)
	}
	return out
}

// LookupUsers resolves a batch of users by email and/or ID. Single
// round-trip to Postgres via UserRepository.Lookup. Powers
// `POST /admin/users/lookup` — back-office tools, support flows, and
// the PHP/Laravel package's bulk-existence checks.
//
// AuthZ is enforced at the handler layer (system_admin / super_admin).
// This method assumes the caller already passed that gate.
func (s *UserService) LookupUsers(ctx context.Context, in LookupUsersInput) ([]*domain.User, error) {
	if err := in.Validate(); err != nil {
		return nil, err
	}
	return s.userRepo.Lookup(ctx, dedupEmails(in.Emails), dedupIDs(in.IDs))
}

// GetUserOrganizations retrieves organizations a user belongs to
func (s *UserService) GetUserOrganizations(ctx context.Context, userID types.ID) ([]*domain.OrganizationMembership, error) {
	return s.userRepo.GetOrganizations(ctx, userID)
}

// GetUserBaseRolesBulk fetches base roles for many users in one
// round-trip. Returns a map keyed by user id; users with no base
// roles appear with an empty slice. Drives the per-row roles
// column on `/admin/users` without an N+1 fan-out.
func (s *UserService) GetUserBaseRolesBulk(ctx context.Context, userIDs []types.ID) (map[types.ID][]*domain.Role, error) {
	return s.userRepo.GetBaseRolesByUserIDs(ctx, userIDs)
}

// GetUserBaseRoles retrieves base roles assigned to a user
func (s *UserService) GetUserBaseRoles(ctx context.Context, userID types.ID) ([]*domain.Role, error) {
	return s.userRepo.GetBaseRoles(ctx, userID)
}

// AssignBaseRole assigns a base role to a user
func (s *UserService) AssignBaseRole(ctx context.Context, userID, roleID types.ID, assignedBy *types.ID) error {
	// Verify role exists and is not an org-specific role
	role, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		return err
	}

	if role.IsOrgRole {
		return errors.ValidationError("Cannot assign organization role as base role")
	}

	assignment := domain.NewUserBaseRole(userID, roleID, assignedBy)
	return s.userRepo.AssignBaseRole(ctx, assignment)
}

// RemoveBaseRole removes a base role from a user
func (s *UserService) RemoveBaseRole(ctx context.Context, userID, roleID types.ID) error {
	return s.userRepo.RemoveBaseRole(ctx, userID, roleID)
}

// GetUserAuthProviders retrieves linked auth providers for a user
func (s *UserService) GetUserAuthProviders(ctx context.Context, userID types.ID) ([]*domain.UserAuthProvider, error) {
	return s.userRepo.GetUserProviders(ctx, userID)
}

// UnlinkAuthProvider removes an auth provider link from a user
func (s *UserService) UnlinkAuthProvider(ctx context.Context, userID types.ID, provider types.AuthProvider) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	// Don't allow unlinking the primary auth provider if it's the only one
	providers, err := s.userRepo.GetUserProviders(ctx, userID)
	if err != nil {
		return err
	}

	if len(providers) <= 1 && user.AuthProvider == provider {
		return errors.ValidationError("Cannot unlink primary authentication provider")
	}

	return s.userRepo.UnlinkProvider(ctx, userID, provider)
}

// --- User pools (namespaces) administration — system_admin only at the
// route layer. See docs/USER_POOLS.md for the pool model.

// ListNamespaces returns every known pool with user counts + the app
// codes referencing it. Pools are virtual; a row with UserCount 0 is
// referenced by app config only (flagged "empty" in admin UIs).
func (s *UserService) ListNamespaces(ctx context.Context) ([]*repository.NamespaceInfo, error) {
	return s.userRepo.ListNamespaces(ctx)
}

// GetUserNamespaces returns a user's home pool plus tag pools.
func (s *UserService) GetUserNamespaces(ctx context.Context, userID types.ID) (home string, others []string, err error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return "", nil, err
	}
	all, err := s.userRepo.GetUserNamespaces(ctx, userID)
	if err != nil {
		return "", nil, err
	}
	others = make([]string, 0, len(all))
	for _, ns := range all {
		if ns != user.Namespace {
			others = append(others, ns)
		}
	}
	return user.Namespace, others, nil
}

// SetUserHomeNamespace moves a user's home pool (users.namespace).
// Conflicts (same email already present in the target pool) surface as
// 409. The user's tag pools are unchanged except a tag equal to the
// new home pool, which becomes redundant and is removed.
func (s *UserService) SetUserHomeNamespace(ctx context.Context, userID types.ID, namespace string) error {
	ns := strings.ToLower(strings.TrimSpace(namespace))
	if ns == "" {
		ns = domain.DefaultNamespace
	}
	if err := validateNamespace(ns); err != nil {
		return err
	}
	return s.userRepo.SetHomeNamespace(ctx, userID, ns)
}

// AddUserNamespace tags a user into an additional pool. Idempotent.
// Tagging the home pool is rejected — it's already authoritative.
func (s *UserService) AddUserNamespace(ctx context.Context, userID types.ID, namespace string) error {
	ns := strings.ToLower(strings.TrimSpace(namespace))
	if ns == "" {
		return errors.InvalidInput("namespace", "namespace is required")
	}
	if err := validateNamespace(ns); err != nil {
		return err
	}
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	if user.Namespace == ns {
		return errors.InvalidInput("namespace", "'"+ns+"' is already the user's default pool")
	}
	return s.userRepo.AddUserToNamespaces(ctx, userID, []string{ns})
}

// RemoveUserNamespace removes a pool tag. The home pool can't be
// removed — change it with SetUserHomeNamespace instead.
func (s *UserService) RemoveUserNamespace(ctx context.Context, userID types.ID, namespace string) error {
	ns := strings.ToLower(strings.TrimSpace(namespace))
	if ns == "" {
		return errors.InvalidInput("namespace", "namespace is required")
	}
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	if user.Namespace == ns {
		return errors.InvalidInput("namespace", "cannot remove the user's default pool — set a different default pool instead")
	}
	return s.userRepo.RemoveUserFromNamespace(ctx, userID, ns)
}
