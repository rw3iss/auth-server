// App auto-provisioning (§7 of the GlobalSKU integration spec). One
// idempotent helper that grants a user the app's (and any linked apps')
// user_apps membership and, when the app declares a default org, ensures org
// membership with the configured role. Called from registration, the login
// auto-grant branch, and JIT migration so every path delivers the same
// entitlement set.
//
// App-agnostic + config-driven: nothing here hardcodes globalsku/org roles. A
// client may override the role + linked apps per request, but the role is
// always re-validated server-side as an org-scoped role — a client can never
// escalate to a platform role.
package auth

import (
	"context"
	"log/slog"
	"strings"

	"github.com/rw3iss/auth/internal/audit"
	"github.com/rw3iss/auth/internal/domain"
	"github.com/rw3iss/auth/pkg/shared/models"
	"github.com/rw3iss/auth/pkg/shared/types"
)

// EntitlementOverrides carries per-request overrides for app provisioning.
// Empty/unset fields fall back to the app's configured defaults.
type EntitlementOverrides struct {
	// RoleCode overrides app.DefaultRoleCode for the default-org membership.
	// Empty = use the app default. Always validated as an org-scoped role.
	RoleCode string
	// LinkedAppCodes overrides app.LinkedAppCodes. Nil = use the app default;
	// an explicit (possibly empty) slice replaces it.
	LinkedAppCodes []string
	// LinkedAppCodesSet distinguishes "not provided" (nil intent) from
	// "explicitly empty" so a client can clear the linked apps for a request.
	LinkedAppCodesSet bool
}

// ensureAppEntitlements grants app + linked-app memberships and the default-org
// role. Idempotent and best-effort: every step tolerates "already done", and
// failures are logged rather than propagated — provisioning must never block
// an otherwise-valid login/registration. §7.2.
func (s *AuthService) ensureAppEntitlements(ctx context.Context, user *domain.User, app *domain.App, ov EntitlementOverrides) {
	if app == nil || user == nil || s.appService == nil {
		return
	}

	// 1. Primary app membership (idempotent upsert).
	_ = s.appService.GrantUser(ctx, user.ID, app.ID, nil)

	// 2. Linked apps — request override wins over app config.
	linked := []string(app.LinkedAppCodes)
	if ov.LinkedAppCodesSet {
		linked = ov.LinkedAppCodes
	}
	for _, code := range linked {
		code = strings.TrimSpace(code)
		if code == "" || code == app.Code {
			continue
		}
		la, err := s.appService.GetByCode(ctx, code)
		if err != nil || la == nil {
			slog.Warn("ensureAppEntitlements: unknown linked_app_code, skipping",
				"app", app.Code, "linked", code)
			continue
		}
		_ = s.appService.GrantUser(ctx, user.ID, la.ID, nil)
	}

	// 3. Default-org membership + role.
	if app.DefaultOrganizationID != nil {
		roleCode := app.DefaultRole()
		if rc := strings.TrimSpace(ov.RoleCode); rc != "" {
			roleCode = rc
		}
		s.ensureOrgMembershipWithRole(ctx, user, *app.DefaultOrganizationID, roleCode, app.Code)
	}
}

// ensureOrgMembershipWithRole idempotently makes the user a member of orgID
// with the resolved org role. Platform roles are refused (fall back to
// org_member). §7.2.
func (s *AuthService) ensureOrgMembershipWithRole(ctx context.Context, user *domain.User, orgID types.ID, roleCode, appCode string) {
	role := s.resolveOrgRole(ctx, roleCode, appCode)
	if role == nil {
		// Even org_member is missing — can't provision a role. Skip quietly;
		// app membership above still succeeded.
		return
	}

	created := false
	membership, err := s.orgRepo.GetMembership(ctx, user.ID, orgID)
	if err != nil || membership == nil {
		membership = domain.NewOrganizationMembership(user.ID, orgID)
		if aerr := s.orgRepo.AddMember(ctx, membership); aerr != nil {
			slog.Warn("ensureAppEntitlements: add org member failed",
				"app", appCode, "org", orgID.String(), "err", aerr)
			s.auditProvisioningFailed(ctx, user.ID, &orgID, appCode, "add_member", aerr)
			return
		}
		created = true
	}

	assign := domain.NewOrganizationMemberRole(membership.ID, role.ID, user.ID)
	if aerr := s.orgRepo.AssignMemberRole(ctx, assign); aerr != nil {
		slog.Warn("ensureAppEntitlements: assign org role failed",
			"app", appCode, "role", role.Code, "err", aerr)
		s.auditProvisioningFailed(ctx, user.ID, &orgID, appCode, "assign_role", aerr)
		return
	}

	// Audit only on first provisioning so re-logins don't spam the log.
	if created {
		audit.Record(ctx, audit.Event{
			Action:         "user.app_provisioned",
			ActorUserID:    &user.ID,
			OrganizationID: &orgID,
			Details:        map[string]any{"app_code": appCode, "role": role.Code},
		})
	}
}

// auditProvisioningFailed records a best-effort audit event when a provisioning
// step fails. Provisioning is best-effort (never blocks login), so these
// failures are otherwise invisible beyond a warn log — the audit row gives
// operators a queryable trail of users who didn't get their entitlements.
func (s *AuthService) auditProvisioningFailed(ctx context.Context, userID types.ID, orgID *types.ID, appCode, step string, cause error) {
	audit.Record(ctx, audit.Event{
		Action:         "user.app_provisioning_failed",
		ActorUserID:    &userID,
		OrganizationID: orgID,
		Details:        map[string]any{"app_code": appCode, "step": step, "error": cause.Error()},
	})
}

// resolveOrgRole returns the org-scoped role for code, refusing platform roles
// (system_admin / super_admin / base_user) and non-org roles. Falls back to
// org_member when the requested role is missing/forbidden — the security
// guarantee is that a client-supplied role can never escalate privileges.
func (s *AuthService) resolveOrgRole(ctx context.Context, code, appCode string) *domain.Role {
	code = strings.ToLower(strings.TrimSpace(code))
	platform := isPlatformRoleCode(code)

	if code != "" && code != string(models.RoleOrgMember) && !platform {
		if role, err := s.roleRepo.GetByCode(ctx, code); err == nil && role != nil {
			if role.IsOrgRole {
				return role
			}
			slog.Warn("ensureAppEntitlements: role not org-scoped, using org_member",
				"app", appCode, "role", code)
		} else {
			slog.Warn("ensureAppEntitlements: unknown role, using org_member",
				"app", appCode, "role", code)
		}
	} else if platform {
		slog.Warn("ensureAppEntitlements: refusing platform role, using org_member",
			"app", appCode, "role", code)
	}

	role, err := s.roleRepo.GetByCode(ctx, string(models.RoleOrgMember))
	if err != nil || role == nil {
		return nil
	}
	return role
}

// isPlatformRoleCode reports whether a role code is a platform-scoped role
// that must never be granted via app provisioning / a client override
// (the privilege-escalation guard). Case-insensitive.
func isPlatformRoleCode(code string) bool {
	switch strings.ToLower(strings.TrimSpace(code)) {
	case string(models.RoleSystemAdmin), string(models.RoleSuperAdmin), string(models.RoleBaseUser):
		return true
	default:
		return false
	}
}
