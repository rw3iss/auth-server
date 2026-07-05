package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/lib/pq"

	"github.com/ven/auth/internal/domain"
	"github.com/ven/auth/internal/repository"
	"github.com/ven/auth/pkg/shared/errors"
	"github.com/ven/auth/pkg/shared/models"
	"github.com/ven/auth/pkg/shared/types"
)

// AppService is the business-logic layer over AppRepository. Thin —
// validation lives here so handlers stay HTTP-shaped.
type AppService struct {
	repo     repository.AppRepository
	orgRepo  repository.OrganizationRepository
	roleRepo repository.RoleRepository
}

// NewAppService constructs a new app service.
func NewAppService(repo repository.AppRepository) *AppService {
	return &AppService{repo: repo}
}

// WithRoleRepo injects the role repo so Create/Update can validate
// default_role_code at config time (must be an existing org-scoped role).
// Optional — when unwired, the role check is skipped (provision-time
// fallback to org_member still applies).
func (s *AppService) WithRoleRepo(r repository.RoleRepository) *AppService {
	s.roleRepo = r
	return s
}

// WithOrgRepo injects the org repo so AppService can resolve an app's
// default-organization for the public registration-policy endpoint.
// Optional — if not wired, GetDefaultOrganization returns (nil, nil)
// and clients render without the org name.
func (s *AppService) WithOrgRepo(o repository.OrganizationRepository) *AppService {
	s.orgRepo = o
	return s
}

// GetDefaultOrganization returns the org row backing an app's
// default_organization_id, or (nil, nil) when the repo wasn't injected
// (graceful degradation — never break the policy endpoint over a
// missing org lookup).
func (s *AppService) GetDefaultOrganization(ctx context.Context, orgID types.ID) (*domain.Organization, error) {
	if s.orgRepo == nil {
		return nil, nil
	}
	return s.orgRepo.GetByID(ctx, orgID)
}

// CreateAppInput is what /admin/apps accepts on creation.
//
// Fields below the `// Registration policy (migration 013 / 015)` line
// are optional with safe defaults — empty arrays for the policy lists,
// nil pointers for the org default + frontend URL. The repository
// column constraints are NOT NULL on the array columns, so the service
// always coalesces nil → empty array before insert.
type CreateAppInput struct {
	Code                string
	Name                string
	Description         string
	AllowedRedirectURLs []string
	ServiceCodes        []string // optional; defaults to [Code]
	AutoGrantOnSignup   bool

	// Registration policy (migration 013 / 015).
	AllowedEmailDomains   []string  // empty = any domain
	AllowedAuthMethods    []string  // empty = every enabled method
	DefaultOrganizationID *types.ID // nil = no auto-org-membership on signup
	FrontendURL           *string   // nil = fall back to CLIENT_URL env

	// User pools (migrations 017 + 018 / docs/USER_POOLS.md).
	RegistrationNamespace  *string  // nil/empty = "default" (singular WRITE pool, 017 back-compat)
	RegistrationNamespaces []string // ordered multi-WRITE pools; first = home namespace (018)
	ReadNamespaces         []string // empty = [write namespaces] (READ pools)

	// Webhooks — migration 019. Outbound hooks for app-scoped events.
	Webhooks []domain.AppWebhook

	// Auto-provisioning config — migration 020 (§7).
	DefaultRoleCode *string  // org role for the default-org membership; nil = org_member
	LinkedAppCodes  []string // additional app codes to grant; empty = none
}

// Create validates and persists a new app row.
func (s *AppService) Create(ctx context.Context, in CreateAppInput) (*domain.App, error) {
	if in.Code = strings.TrimSpace(in.Code); in.Code == "" {
		return nil, errors.InvalidInput("code", "code is required")
	}
	if len(in.Code) > 100 {
		return nil, errors.InvalidInput("code", "code must be ≤100 chars")
	}
	if in.Name = strings.TrimSpace(in.Name); in.Name == "" {
		return nil, errors.InvalidInput("name", "name is required")
	}
	// service_codes defaults to [code] if not supplied — the 1:1 common
	// case from docs/APP_REGISTRATION.md.
	if len(in.ServiceCodes) == 0 {
		in.ServiceCodes = []string{in.Code}
	}

	// Coalesce nil slices to empty pq.StringArray so lib/pq sends
	// SQL `'{}'` rather than NULL. The DB columns are NOT NULL with a
	// DEFAULT '{}' from migration 013, but lib/pq passes Go nil as
	// SQL NULL regardless of the column default — sending an empty
	// array is the only way to land on the DEFAULT branch.
	allowedEmailDomains := pq.StringArray{}
	if in.AllowedEmailDomains != nil {
		allowedEmailDomains = pq.StringArray(in.AllowedEmailDomains)
	}
	allowedAuthMethods := pq.StringArray{}
	if in.AllowedAuthMethods != nil {
		allowedAuthMethods = pq.StringArray(in.AllowedAuthMethods)
	}

	// User pools (migration 017). Normalize + validate the write pool
	// and each read pool; coalesce nil → empty array (NOT NULL column).
	regNamespace := normalizeNamespacePtr(in.RegistrationNamespace)
	if regNamespace != nil {
		if err := validateNamespace(*regNamespace); err != nil {
			return nil, err
		}
	}
	readNamespaces := pq.StringArray{}
	for _, ns := range in.ReadNamespaces {
		v := strings.ToLower(strings.TrimSpace(ns))
		if v == "" {
			continue
		}
		if err := validateNamespace(v); err != nil {
			return nil, err
		}
		readNamespaces = append(readNamespaces, v)
	}
	registrationNamespaces, err := normalizeNamespaceList(in.RegistrationNamespaces)
	if err != nil {
		return nil, err
	}
	webhooksList, err := validateWebhooks(in.Webhooks)
	if err != nil {
		return nil, err
	}

	linkedAppCodes := normalizeAppCodes(in.LinkedAppCodes)
	defaultRoleCode := normalizeRoleCodePtr(in.DefaultRoleCode)

	app := &domain.App{
		BaseModel:              models.NewBaseModel(),
		Code:                   in.Code,
		Name:                   in.Name,
		Description:            in.Description,
		AllowedRedirectURLs:    in.AllowedRedirectURLs,
		ServiceCodes:           in.ServiceCodes,
		AutoGrantOnSignup:      in.AutoGrantOnSignup,
		Status:                 "active",
		Metadata:               []byte("{}"),
		AllowedEmailDomains:    allowedEmailDomains,
		AllowedAuthMethods:     allowedAuthMethods,
		DefaultOrganizationID:  in.DefaultOrganizationID,
		FrontendURL:            in.FrontendURL,
		RegistrationNamespace:  regNamespace,
		RegistrationNamespaces: registrationNamespaces,
		ReadNamespaces:         readNamespaces,
		Webhooks:               webhooksList,
		DefaultRoleCode:        defaultRoleCode,
		LinkedAppCodes:         linkedAppCodes,
	}
	if err := s.validateAppProvisioning(ctx, app); err != nil {
		return nil, err
	}
	if err := s.repo.Create(ctx, app); err != nil {
		return nil, err
	}
	return app, nil
}

// validateAppProvisioning enforces the §7 config-time rules on the FINAL app
// state: when default_role_code is set it must (a) have a default_organization_id
// to attach to, and (b) name an existing org-scoped role. Rejecting here gives
// the admin immediate feedback instead of a silent provision-time fallback to
// org_member. linked_app_codes are intentionally NOT existence-checked here —
// an app may be linked before its target exists; the provision path skips
// unknown codes with a warning.
func (s *AppService) validateAppProvisioning(ctx context.Context, app *domain.App) error {
	if app.DefaultRoleCode == nil {
		return nil
	}
	code := strings.TrimSpace(*app.DefaultRoleCode)
	if code == "" {
		return nil
	}
	if app.DefaultOrganizationID == nil {
		return errors.InvalidInput("default_role_code", "default_role_code requires default_organization_id to be set (the role is assigned in that org)")
	}
	if s.roleRepo == nil {
		return nil
	}
	role, err := s.roleRepo.GetByCode(ctx, code)
	if err != nil || role == nil {
		return errors.InvalidInput("default_role_code", "role '"+code+"' does not exist")
	}
	if !role.IsOrgRole {
		return errors.InvalidInput("default_role_code", "role '"+code+"' is not an organization-scoped role")
	}
	return nil
}

// GetByCode is the hot lookup during /auth/login — must be fast and
// tolerant of "not found" without panicking.
func (s *AppService) GetByCode(ctx context.Context, code string) (*domain.App, error) {
	return s.repo.GetByCode(ctx, code)
}

// GetByID looks up an app by id, used by /admin paths.
func (s *AppService) GetByID(ctx context.Context, id types.ID) (*domain.App, error) {
	return s.repo.GetByID(ctx, id)
}

// List returns every non-deleted app.
func (s *AppService) List(ctx context.Context) ([]*domain.App, error) {
	return s.repo.List(ctx)
}

// UpdateAppInput is what /admin/apps/{id} PATCH accepts.
type UpdateAppInput struct {
	Name                *string
	Description         *string
	AllowedRedirectURLs *[]string
	ServiceCodes        *[]string
	AutoGrantOnSignup   *bool
	Status              *string

	// Registration policy (migration 013 / 015) — PATCH-editable since
	// 2026-06. Outer nil = field absent (unchanged).
	//
	// FrontendURL: non-nil empty string clears to NULL (fall back to the
	// CLIENT_URL env). Changing it redirects every verify / reset /
	// magic-link / invitation email at the new origin — a wrong value
	// strands those flows.
	FrontendURL         *string
	AllowedEmailDomains *[]string
	AllowedAuthMethods  *[]string
	// DefaultOrganizationID: double pointer so "absent" (outer nil),
	// "clear to NULL" (inner nil) and "set" are all expressible.
	DefaultOrganizationID **types.ID

	// User pools (migrations 017 + 018). Pointer-wrapped so "absent"
	// (nil) is distinguishable from "clear to default" (non-nil empty).
	RegistrationNamespace  *string
	RegistrationNamespaces *[]string
	ReadNamespaces         *[]string

	// Webhooks — migration 019. Non-nil replaces the whole list (set
	// semantics; pass [] to remove every hook).
	Webhooks *[]domain.AppWebhook

	// Auto-provisioning config — migration 020 (§7). Outer nil = absent.
	// DefaultRoleCode: non-nil empty string clears to NULL (⇒ org_member).
	DefaultRoleCode *string
	LinkedAppCodes  *[]string
}

// Update applies a partial patch. Only supplied fields are modified.
func (s *AppService) Update(ctx context.Context, id types.ID, in UpdateAppInput) (*domain.App, error) {
	app, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if in.Name != nil {
		app.Name = *in.Name
	}
	if in.Description != nil {
		app.Description = *in.Description
	}
	if in.AllowedRedirectURLs != nil {
		app.AllowedRedirectURLs = *in.AllowedRedirectURLs
	}
	if in.ServiceCodes != nil {
		app.ServiceCodes = *in.ServiceCodes
	}
	if in.AutoGrantOnSignup != nil {
		app.AutoGrantOnSignup = *in.AutoGrantOnSignup
	}
	if in.Status != nil {
		app.Status = *in.Status
	}
	if in.FrontendURL != nil {
		fu := strings.TrimSpace(*in.FrontendURL)
		if fu == "" {
			app.FrontendURL = nil
		} else {
			if !strings.HasPrefix(fu, "http://") && !strings.HasPrefix(fu, "https://") {
				return nil, errors.InvalidInput("frontend_url", "must be an absolute http(s) URL")
			}
			app.FrontendURL = &fu
		}
	}
	if in.AllowedEmailDomains != nil {
		domains := pq.StringArray{}
		for _, d := range *in.AllowedEmailDomains {
			v := strings.ToLower(strings.TrimSpace(d))
			if v != "" {
				domains = append(domains, v)
			}
		}
		app.AllowedEmailDomains = domains
	}
	if in.AllowedAuthMethods != nil {
		methods := pq.StringArray{}
		for _, m := range *in.AllowedAuthMethods {
			v := strings.ToLower(strings.TrimSpace(m))
			if v != "" {
				methods = append(methods, v)
			}
		}
		app.AllowedAuthMethods = methods
	}
	if in.DefaultOrganizationID != nil {
		app.DefaultOrganizationID = *in.DefaultOrganizationID
	}
	if in.RegistrationNamespace != nil {
		ns := normalizeNamespacePtr(in.RegistrationNamespace)
		if ns != nil {
			if err := validateNamespace(*ns); err != nil {
				return nil, err
			}
		}
		app.RegistrationNamespace = ns
	}
	if in.ReadNamespaces != nil {
		readNamespaces := pq.StringArray{}
		for _, raw := range *in.ReadNamespaces {
			v := strings.ToLower(strings.TrimSpace(raw))
			if v == "" {
				continue
			}
			if err := validateNamespace(v); err != nil {
				return nil, err
			}
			readNamespaces = append(readNamespaces, v)
		}
		app.ReadNamespaces = readNamespaces
	}
	if in.RegistrationNamespaces != nil {
		registrationNamespaces, err := normalizeNamespaceList(*in.RegistrationNamespaces)
		if err != nil {
			return nil, err
		}
		app.RegistrationNamespaces = registrationNamespaces
	}
	if in.Webhooks != nil {
		webhooksList, err := validateWebhooks(*in.Webhooks)
		if err != nil {
			return nil, err
		}
		app.Webhooks = webhooksList
	}
	if in.DefaultRoleCode != nil {
		app.DefaultRoleCode = normalizeRoleCodePtr(in.DefaultRoleCode)
	}
	if in.LinkedAppCodes != nil {
		app.LinkedAppCodes = normalizeAppCodes(*in.LinkedAppCodes)
	}
	if err := s.validateAppProvisioning(ctx, app); err != nil {
		return nil, err
	}
	if err := s.repo.Update(ctx, app); err != nil {
		return nil, err
	}
	return app, nil
}

// normalizeNamespaceList trims, lower-cases, de-duplicates (order
// preserved) and validates a namespace list. Empty entries are
// dropped. Migration 018.
func normalizeNamespaceList(raw []string) (pq.StringArray, error) {
	out := pq.StringArray{}
	seen := map[string]bool{}
	for _, ns := range raw {
		v := strings.ToLower(strings.TrimSpace(ns))
		if v == "" || seen[v] {
			continue
		}
		if err := validateNamespace(v); err != nil {
			return nil, err
		}
		seen[v] = true
		out = append(out, v)
	}
	return out, nil
}

// normalizeAppCodes trims, de-duplicates (order preserved) and drops empty
// entries from a list of app codes. Returns a non-nil empty array so lib/pq
// sends SQL '{}' rather than NULL (the column is NOT NULL). Migration 020.
func normalizeAppCodes(raw []string) pq.StringArray {
	out := pq.StringArray{}
	seen := map[string]bool{}
	for _, c := range raw {
		v := strings.TrimSpace(c)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// normalizeRoleCodePtr trims a role-code pointer; nil or whitespace-only ⇒
// nil (⇒ org_member fallback at provision time). Migration 020.
func normalizeRoleCodePtr(p *string) *string {
	if p == nil {
		return nil
	}
	v := strings.TrimSpace(*p)
	if v == "" {
		return nil
	}
	return &v
}

// normalizeNamespacePtr trims + lower-cases a namespace pointer.
// Returns nil for nil input or whitespace-only values, so callers treat
// both as "unset" (⇒ the default pool). Migration 017.
func normalizeNamespacePtr(p *string) *string {
	if p == nil {
		return nil
	}
	v := strings.ToLower(strings.TrimSpace(*p))
	if v == "" {
		return nil
	}
	return &v
}

// validateWebhooks normalizes + validates an app's webhook list
// (migration 019): absolute http(s) URL required, events must be known
// (domain.KnownWebhookEvents) and non-empty, name trimmed to ≤200.
func validateWebhooks(raw []domain.AppWebhook) (domain.AppWebhooks, error) {
	out := domain.AppWebhooks{}
	known := map[string]bool{}
	for _, e := range domain.KnownWebhookEvents {
		known[e] = true
	}
	for i, w := range raw {
		w.Name = strings.TrimSpace(w.Name)
		if len(w.Name) > 200 {
			w.Name = w.Name[:200]
		}
		w.URL = strings.TrimSpace(w.URL)
		if !strings.HasPrefix(w.URL, "http://") && !strings.HasPrefix(w.URL, "https://") {
			return nil, errors.InvalidInput("webhooks", fmt.Sprintf("webhook %d: url must be an absolute http(s) URL", i+1))
		}
		events := []string{}
		for _, e := range w.Events {
			e = strings.TrimSpace(e)
			if e == "" {
				continue
			}
			if !known[e] {
				return nil, errors.InvalidInput("webhooks", fmt.Sprintf("webhook %d: unknown event %q (known: %s)", i+1, e, strings.Join(domain.KnownWebhookEvents, ", ")))
			}
			events = append(events, e)
		}
		if len(events) == 0 {
			return nil, errors.InvalidInput("webhooks", fmt.Sprintf("webhook %d: at least one event is required", i+1))
		}
		w.Events = events
		out = append(out, w)
	}
	return out, nil
}

// validateNamespace enforces the user-pool identifier shape: ≤100
// chars, lower-case letters / digits / '-' / '_', no spaces. Empty is
// the caller's concern (treated as default). Migration 017.
func validateNamespace(ns string) error {
	if len(ns) > 100 {
		return errors.InvalidInput("namespace", "namespace must be ≤100 chars")
	}
	for _, r := range ns {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			return errors.InvalidInput("namespace", "namespace must be lower-case letters, digits, '-' or '_'")
		}
	}
	return nil
}

// Delete soft-deletes an app. The row stays in the DB for audit; revoking
// any existing user_apps memberships is left to the caller (admin can do
// it explicitly via /admin/users/{userId}/apps/{appId}).
func (s *AppService) Delete(ctx context.Context, id types.ID) error {
	return s.repo.SoftDelete(ctx, id)
}

// GrantUser links a user to an app. Idempotent — re-grants reactivate a
// revoked row. AUDIT 8.4. grantedBy is the system_admin or org admin
// performing the grant; nil for auto-grant-on-signup.
func (s *AppService) GrantUser(ctx context.Context, userID, appID types.ID, grantedBy *types.ID) error {
	return s.repo.Grant(ctx, userID, appID, grantedBy)
}

// RevokeUser revokes a user's access to an app. The user's existing
// refresh tokens for that app should also be revoked at the JWT-service
// layer — that's done by the handler that calls this method.
func (s *AppService) RevokeUser(ctx context.Context, userID, appID types.ID) error {
	return s.repo.Revoke(ctx, userID, appID)
}

// IsUserAuthorized reports whether the user has an active membership in
// the app. Called by AuthService.Login before issuing a token; on
// false, AuthService either grants on the fly (auto_grant_on_signup) or
// refuses the login.
func (s *AppService) IsUserAuthorized(ctx context.Context, userID, appID types.ID) (bool, error) {
	m, err := s.repo.GetMembership(ctx, userID, appID)
	if err != nil {
		if appErr, ok := errors.AsAppError(err); ok && appErr.Code == errors.ErrCodeNotFound {
			return false, nil
		}
		return false, err
	}
	return m.IsActive(), nil
}

// ListForUser returns every app the given user has active membership in.
// Powers GET /me/apps.
func (s *AppService) ListForUser(ctx context.Context, userID types.ID) ([]*domain.App, error) {
	return s.repo.ListForUser(ctx, userID)
}
