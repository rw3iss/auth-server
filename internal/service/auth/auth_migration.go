// Legacy-auth migration — the Cognito (or other LegacyAuthProvider)
// fallback consulted by Login when an email isn't in the internal
// store. Split from auth_service.go (2026-06-11).
// Package service provides business logic services for the auth application
package auth

import (
	"context"
	"fmt"

	"github.com/rw3iss/auth/internal/audit"
	"github.com/rw3iss/auth/internal/domain"
	"github.com/rw3iss/auth/pkg/migration"
	"github.com/rw3iss/auth/pkg/shared/errors"
	"github.com/rw3iss/auth/pkg/shared/models"
	"github.com/rw3iss/auth/pkg/shared/types"
)

// AuthService handles authentication business logic

// tryMigrateFromLegacy verifies the submitted credential against the given
// legacy provider and, on success, provisions the core user in the app's
// write pool (home namespace) with the app's namespace tag(s). Provider +
// mapper are passed in so the per-app registry (§5) selects them; namespace
// + tags carry the user-pool placement (was previously bare `default`).
func (s *AuthService) tryMigrateFromLegacy(
	ctx context.Context,
	email types.Email,
	password string,
	provider migration.LegacyAuthProvider,
	mapper migration.RoleMapper,
	writeNamespace string,
	tags []string,
) (*domain.User, error) {
	legacyUser, err := provider.TryLogin(ctx, string(email), password)
	if err != nil {
		// Both ErrLegacyUserNotFound and ErrLegacyLoginFailed return here.
		// Caller surfaces InvalidCredentials in either case.
		return nil, err
	}

	// Hash the submitted password — this is the password the user has just
	// proven they know (against the legacy store), so we can safely persist
	// it on the new internal account. Same bcrypt cost as any other
	// registration; the hashed value is the only thing that survives.
	passwordHash, err := s.hashPassword(password)
	if err != nil {
		return nil, errors.Internal("Failed to hash password during migration")
	}

	user := domain.NewUser(email, legacyUser.FirstName, legacyUser.LastName)
	user.SetPassword(passwordHash)
	user.Phone = types.PhoneNumber(legacyUser.Phone)
	user.AuthProvider = types.AuthProviderLocal
	user.EmailVerified = legacyUser.EmailVerified
	if user.EmailVerified {
		user.Status = types.UserStatusActive
	}
	if writeNamespace != "" {
		user.Namespace = writeNamespace
	}

	// Map legacy roles → internal role codes via the configured mapper.
	// system_admin is dropped by contract — never inherited from a legacy
	// system. Unknown roles are dropped silently; the user falls back to
	// base_user.
	mappedRoleCodes := mapper.Map(legacyUser.Roles)

	// Persist user + role assignments in a single transaction.
	err = s.txManager.WithTransaction(ctx, func(ctx context.Context) error {
		if err := s.userRepo.Create(ctx, user); err != nil {
			return err
		}

		// Always assign base_user so the new account has the bedrock role.
		baseRole, err := s.roleRepo.GetByCode(ctx, string(models.RoleBaseUser))
		if err != nil {
			return fmt.Errorf("base_user role missing: %w", err)
		}
		if err := s.userRepo.AssignBaseRole(ctx, domain.NewUserBaseRole(user.ID, baseRole.ID, nil)); err != nil {
			return err
		}

		// Add any mapped legacy roles. Each is looked up by code; missing
		// roles in the internal catalog are skipped so migration doesn't
		// fail when a legacy role maps to something we haven't seeded.
		for _, code := range mappedRoleCodes {
			role, err := s.roleRepo.GetByCode(ctx, code)
			if err != nil {
				// Role doesn't exist locally — skip rather than fail.
				continue
			}
			if err := s.userRepo.AssignBaseRole(ctx, domain.NewUserBaseRole(user.ID, role.ID, nil)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, errors.Internal("Migration transaction failed")
	}

	// Tag the migrated user into the app's read pool(s) (excluding home).
	if len(tags) > 0 {
		_ = s.userRepo.AddUserToNamespaces(ctx, user.ID, tags)
	}

	audit.Record(ctx, audit.Event{
		Action:      "user.migrated_from_legacy",
		ActorUserID: &user.ID,
		Details: map[string]any{
			"source":            provider.Name(),
			"legacy_roles":      legacyUser.Roles,
			"mapped_role_codes": mappedRoleCodes,
			"email_verified":    legacyUser.EmailVerified,
			"namespace":         user.Namespace,
		},
	})

	return user, nil
}

// CheckEmail reports whether a user with the given email exists. AUDIT 8.2 —
// gated to service-to-service callers (system_admin role today; M2M token
// flow when that arrives in Phase C). Never expose to public clients
// because it trivially enables user enumeration.
//
// Returns (exists, error). On error, callers should surface a generic
// failure rather than leaking which lookup failed.
