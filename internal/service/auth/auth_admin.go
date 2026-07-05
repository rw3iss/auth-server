// Administrative & destructive account operations — service-only email
// check, admin password set, impersonation, hard delete, and the
// self-service DeleteMyAccount (kept here with HardDeleteUser because
// they share the same destructive machinery). Split from
// auth_service.go (2026-06-11); shared state/helpers live there.
// Package service provides business logic services for the auth application
package auth

import (
	"context"
	"fmt"

	"github.com/rw3iss/auth/internal/audit"
	"github.com/rw3iss/auth/internal/auth/jwt"
	"github.com/rw3iss/auth/internal/domain"
	"github.com/rw3iss/auth/pkg/shared/errors"
	"github.com/rw3iss/auth/pkg/shared/models"
	"github.com/rw3iss/auth/pkg/shared/types"
	"github.com/rw3iss/auth/pkg/shared/utils"
)

// AuthService handles authentication business logic

func (s *AuthService) CheckEmail(ctx context.Context, email, appCode string) (bool, error) {
	normalized := types.Email(utils.NormalizeEmail(email))
	if !utils.IsValidEmail(string(normalized)) {
		return false, errors.InvalidInput("email", "Invalid email format")
	}
	// Resolve within the app's read pools (migration 017). With no app
	// context this is the default pool — identical to the prior behavior.
	_, err := s.userRepo.GetByEmailInNamespaces(ctx, normalized, s.resolveReadNamespaces(ctx, appCode))
	if err == nil {
		return true, nil
	}
	// Treat any not-found-shaped error as "doesn't exist." Genuine backend
	// failures still return false rather than leak which side broke —
	// the caller is service-to-service so they'll retry on transient
	// errors anyway.
	if appErr, ok := errors.AsAppError(err); ok && appErr.Code == errors.ErrCodeUserNotFound {
		return false, nil
	}
	return false, nil
}

// AdminSetPassword sets a user's password without requiring the current password (system_admin only).
func (s *AuthService) AdminSetPassword(ctx context.Context, targetUserID types.ID, newPassword string) error {
	user, err := s.userRepo.GetByID(ctx, targetUserID)
	if err != nil {
		return errors.UserNotFound()
	}

	pwResult := utils.ValidatePassword(newPassword, s.passwordPolicy())
	if !pwResult.IsValid {
		return errors.ValidationError("Password does not meet requirements (minimum " + fmt.Sprintf("%d", s.cfg.Auth.PasswordMinLength) + " characters)")
	}

	passwordHash, err := s.hashPassword(newPassword)
	if err != nil {
		return errors.Internal("Failed to hash password")
	}

	user.SetPassword(passwordHash)
	return s.userRepo.Update(ctx, user)
}

// GetSSOAuthURLInput parameterizes the SSO-URL endpoint. AUDIT C2 added the
// PKCE fields; everything else is the same shape as before. Adding the
// struct keeps the auth-service interface stable as PKCE-style extensions
// accrete (downstream-cookie binding, nonce, etc.).

type HardDeleteUserInput struct {
	RequesterID types.ID
	TargetID    types.ID
	Reason      string
}

// HardDeleteUser physically removes the user row from the database
// (AUDIT C8). Refuses self-delete + ownership-bearing users. Audit-trail
// rows survive via SET NULL FKs added in migration 011.
//
// Authorization is the caller's responsibility — this method assumes the
// requester is a system_admin (routes mount it under systemAdminChain).
// The check that the requester isn't deleting themselves is here, in
// service, because it's a domain invariant rather than an authz concern.
//
// Captures audit metadata BEFORE the delete fires so the audit_log row
// retains target email / name even after the user row is gone (the FK
// will go NULL on the audit_log.user_id column, but `details` is JSONB
// and unaffected).
func (s *AuthService) HardDeleteUser(ctx context.Context, input HardDeleteUserInput) error {
	if input.RequesterID == input.TargetID {
		return errors.InvalidInput("user_id", "cannot hard-delete yourself")
	}
	target, err := s.userRepo.GetByID(ctx, input.TargetID)
	if err != nil {
		return err
	}
	// Owned-org check. organizations.owner_id has no ON DELETE action, so
	// a hard-delete with owned orgs surfaces a raw FK-violation. We
	// surface a clean 409 instead, with an explicit message — operator
	// must transfer ownership first.
	owned, err := s.userRepo.CountOwnedOrganizations(ctx, input.TargetID)
	if err != nil {
		return err
	}
	if owned > 0 {
		return errors.New(errors.ErrCodeConflict,
			"user owns one or more organizations; transfer ownership before hard-delete", 409)
	}

	// Record the audit event BEFORE the delete fires. The audit_log row's
	// own FK to users(id) will SET NULL on delete (migration 011) but the
	// `details` JSONB column retains the snapshot — so a reviewer can
	// still see who was deleted by whom and why.
	audit.Record(ctx, audit.Event{
		Action:        "user.hard_deleted",
		ActorUserID:   &input.RequesterID,
		SubjectUserID: &input.TargetID,
		Details: map[string]any{
			"reason":         input.Reason,
			"target_email":   string(target.Email),
			"target_name":    target.FirstName + " " + target.LastName,
			"target_status":  string(target.Status),
			"target_created": target.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		},
	})

	// Bump token version so any outstanding access token for the target
	// fails validation immediately. Refresh tokens cascade-delete with the
	// user row, but the access tokens are JWTs validated locally without
	// touching the DB — only the token-version primitive can kill them
	// cross-replica.
	_, _ = s.tokenCache.BumpUserTokenVersion(ctx, input.TargetID.String())

	return s.userRepo.HardDelete(ctx, input.TargetID)
}

// DeleteMyAccountInput is the self-service account deletion shape.
// Caller MUST present their current password — same defense-in-depth as
// password change. The typed-confirmation ("DELETE") string is enforced
// at the handler layer; we don't accept anything else as a signal.
type DeleteMyAccountInput struct {
	UserID          types.ID
	CurrentPassword string
}

// DeleteMyAccount lets the authenticated user permanently delete their
// own account. Wraps HardDeleteUser's pre-flight checks (refuses if the
// user owns any org — they have to transfer ownership first) but skips
// the "no self-delete" guard since this IS the self-delete path.
//
// Records the deletion in audit_log with the user as both actor and
// subject so administrators can see why an account vanished.
func (s *AuthService) DeleteMyAccount(ctx context.Context, input DeleteMyAccountInput) error {
	user, err := s.userRepo.GetByID(ctx, input.UserID)
	if err != nil {
		return err
	}

	// Re-auth via password. Service-layer enforcement so the
	// handler can't forget. CheckPassword is constant-time.
	if !utils.CheckPassword(input.CurrentPassword, user.PasswordHash) {
		return errors.InvalidCredentials()
	}

	owned, err := s.userRepo.CountOwnedOrganizations(ctx, input.UserID)
	if err != nil {
		return err
	}
	if owned > 0 {
		return errors.New(errors.ErrCodeConflict,
			"you own one or more organizations — transfer ownership before deleting your account", 409)
	}

	audit.Record(ctx, audit.Event{
		Action:        "user.self_deleted",
		ActorUserID:   &input.UserID,
		SubjectUserID: &input.UserID,
		Details: map[string]any{
			"email":   string(user.Email),
			"name":    user.FirstName + " " + user.LastName,
			"created": user.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		},
	})

	_, _ = s.tokenCache.BumpUserTokenVersion(ctx, input.UserID.String())
	return s.userRepo.HardDelete(ctx, input.UserID)
}

// ImpersonateInput parameterizes the admin → user impersonation request
// (AUDIT C7). Reason is operator-supplied free-text and is recorded in the
// audit log alongside actor + target — it's the "why" that lets an after-
// the-fact reviewer evaluate whether the impersonation was justified.
type ImpersonateInput struct {
	ActorClaims *jwt.TokenClaims // already-validated access-token claims of the admin
	TargetID    types.ID
	Reason      string
	DeviceInfo  string
	IPAddress   string
	UserAgent   string
}

// Impersonate mints a token pair for the target user, stamped with the
// actor's user_id + email so every action under the resulting session
// remains audit-traceable to the impersonating admin. AUDIT C7.
//
// Authorization gates (refused otherwise):
//   - actor is platform-admin (system_admin OR super_admin) → can
//     impersonate ANY user.
//   - actor is org_admin in some org X → can impersonate ONLY users
//     who are members of X. Actor's token MUST carry org context for
//     this branch — without it we can't know which org's authority the
//     actor is exercising.
//   - actor and target are the same user → refused.
//   - actor's own token already carries an impersonator claim → refused
//     (no chaining).
//
// Issued access tokens have the same 15m TTL as a normal session; the
// refresh-token grant gives the admin enough time to do real work, after
// which a normal session-revoke ends the impersonation. Audit events:
//   - user.impersonation_started — at token issuance
//   - user.impersonation_failed — on authorization or target-status reject
func (s *AuthService) Impersonate(ctx context.Context, input ImpersonateInput) (*LoginResult, error) {
	if input.ActorClaims == nil {
		return nil, errors.Unauthorized("actor token required")
	}
	actorID := input.ActorClaims.UserID
	if actorID == input.TargetID {
		return nil, errors.InvalidInput("user_id", "cannot impersonate yourself")
	}
	if input.ActorClaims.IsImpersonating() {
		// AUDIT C7: refuse chained impersonation. A token already stamped
		// imp_uid can't itself become an impersonator — that would let an
		// admin "vouch through" a chain and erase the original actor's
		// accountability.
		return nil, errors.New(errors.ErrCodeForbidden, "cannot impersonate from an impersonation session", 403)
	}

	target, err := s.userRepo.GetByID(ctx, input.TargetID)
	if err != nil {
		return nil, err
	}
	if target.Status == types.UserStatusSuspended {
		return nil, errors.UserSuspended()
	}
	if target.Status == types.UserStatusDeleted || target.IsDeleted() {
		return nil, errors.UserNotFound()
	}

	// Authorization branch.
	isPlatformAdmin := input.ActorClaims.HasAnyRole(string(models.RoleSystemAdmin), string(models.RoleSuperAdmin))
	if !isPlatformAdmin {
		if !input.ActorClaims.HasRole(string(models.RoleOrgAdmin)) {
			audit.Record(ctx, audit.Event{
				Action:        "user.impersonation_failed",
				ActorUserID:   &actorID,
				SubjectUserID: &input.TargetID,
				Details:       map[string]any{"reason": "actor_not_authorized"},
			})
			return nil, errors.New(errors.ErrCodeForbidden, "only platform admins or org admins can impersonate", 403)
		}
		if input.ActorClaims.OrganizationID == nil {
			return nil, errors.New(errors.ErrCodeForbidden, "org admin must impersonate within an org-scoped session", 403)
		}
		// Verify target is a member of the actor's org.
		membership, mErr := s.orgRepo.GetMembership(ctx, input.TargetID, *input.ActorClaims.OrganizationID)
		if mErr != nil || !membership.IsActive() {
			audit.Record(ctx, audit.Event{
				Action:        "user.impersonation_failed",
				ActorUserID:   &actorID,
				SubjectUserID: &input.TargetID,
				Details: map[string]any{
					"reason": "target_not_in_actor_org",
					"org_id": input.ActorClaims.OrganizationID.String(),
				},
			})
			return nil, errors.New(errors.ErrCodeForbidden, "target is not a member of your organization", 403)
		}
	}

	// Load the actor's own user row so we can stamp imp_email. Cheap lookup;
	// fail-shut if it's gone (the actor's token would be useless anyway).
	actor, err := s.userRepo.GetByID(ctx, actorID)
	if err != nil {
		return nil, err
	}

	// Resolve target's roles + permissions. Mirrors the SSOExchange shape:
	// re-fetch state at impersonation time rather than relying on stale
	// claims, so a freshly-promoted target gets the right permissions.
	var roles []*domain.Role
	var org *domain.Organization
	if input.ActorClaims.OrganizationID != nil {
		org, err = s.orgRepo.GetByID(ctx, *input.ActorClaims.OrganizationID)
		if err == nil && org.IsActive() {
			membership, mErr := s.orgRepo.GetMembership(ctx, target.ID, *input.ActorClaims.OrganizationID)
			if mErr == nil && membership.IsActive() {
				roles, _ = s.orgRepo.GetMemberRoles(ctx, membership.ID)
			}
		}
	}
	if len(roles) == 0 {
		roles, _ = s.userRepo.GetBaseRoles(ctx, target.ID)
	}
	roleCodes := make([]string, len(roles))
	for i, r := range roles {
		roleCodes[i] = r.Code
	}
	permissions := s.collectPermissions(ctx, roles)

	tokenPair, err := s.jwtService.GenerateTokenPair(ctx, jwt.GenerateTokenInput{
		User:         target,
		Organization: org,
		Roles:        roles,
		Permissions:  permissions,
		DeviceInfo:   input.DeviceInfo,
		IPAddress:    input.IPAddress,
		UserAgent:    input.UserAgent,
		Impersonator: actor,
	})
	if err != nil {
		return nil, errors.Internal("Failed to generate tokens")
	}

	audit.Record(ctx, audit.Event{
		Action:        "user.impersonation_started",
		ActorUserID:   &actorID,
		SubjectUserID: &target.ID,
		Details: map[string]any{
			"reason":           input.Reason,
			"target_email":     string(target.Email),
			"actor_email":      string(actor.Email),
			"target_status":    string(target.Status),
			"actor_org_scoped": input.ActorClaims.OrganizationID != nil,
		},
	})

	return &LoginResult{
		User:         target,
		Organization: org,
		TokenPair:    tokenPair,
		Roles:        roleCodes,
		Permissions:  permissions,
	}, nil
}

// TwoFactorSetupResult holds the data the client needs to render the
// enrollment UI (AUDIT C4). The Secret + ProvisioningURI are both shown to
// the user; QR code is rendered client-side to keep the secret off any
// third-party renderer.
