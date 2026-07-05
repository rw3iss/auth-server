package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/rw3iss/auth/internal/api/middleware"
	"github.com/rw3iss/auth/internal/domain"
	"github.com/rw3iss/auth/internal/service"
	"github.com/rw3iss/auth/pkg/shared/errors"
	"github.com/rw3iss/auth/pkg/shared/types"
)

// AppHandler exposes app-registration admin endpoints and the user-facing
// /me/apps lookup. Admin routes are gated at the router layer
// (adminChain in routes.go) so this handler doesn't repeat the
// system_admin check.
type AppHandler struct {
	apps *service.AppService
}

func NewAppHandler(apps *service.AppService) *AppHandler {
	return &AppHandler{apps: apps}
}

// Create handles POST /admin/apps.
func (h *AppHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code                string   `json:"code"`
		Name                string   `json:"name"`
		Description         string   `json:"description"`
		AllowedRedirectURLs []string `json:"allowed_redirect_urls"`
		ServiceCodes        []string `json:"service_codes"`
		AutoGrantOnSignup   bool     `json:"auto_grant_on_signup"`

		// Registration policy (migration 013 / 015). All optional —
		// service layer coalesces nil → empty arrays for the NOT NULL
		// columns, and nil → SQL NULL for the optional pointer fields.
		AllowedEmailDomains   []string `json:"allowed_email_domains"`
		AllowedAuthMethods    []string `json:"allowed_auth_methods"`
		DefaultOrganizationID string   `json:"default_organization_id"`
		FrontendURL           string   `json:"frontend_url"`

		// User pools (migrations 017 + 018 / docs/USER_POOLS.md).
		// Optional — empty/absent ⇒ the `default` pool, identical to
		// pre-017. `registration_namespaces` (plural, ordered: first =
		// home pool) supersedes the singular form when non-empty.
		RegistrationNamespace  string   `json:"registration_namespace"`
		RegistrationNamespaces []string `json:"registration_namespaces"`
		ReadNamespaces         []string `json:"read_namespaces"`

		// Webhooks — migration 019.
		Webhooks []domain.AppWebhook `json:"webhooks"`

		// Auto-provisioning config — migration 020 (§7).
		DefaultRoleCode string   `json:"default_role_code"`
		LinkedAppCodes  []string `json:"linked_app_codes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.InvalidInput("body", "invalid request body"))
		return
	}

	in := service.CreateAppInput{
		Code:                   req.Code,
		Name:                   req.Name,
		Description:            req.Description,
		AllowedRedirectURLs:    req.AllowedRedirectURLs,
		ServiceCodes:           req.ServiceCodes,
		AutoGrantOnSignup:      req.AutoGrantOnSignup,
		AllowedEmailDomains:    req.AllowedEmailDomains,
		AllowedAuthMethods:     req.AllowedAuthMethods,
		ReadNamespaces:         req.ReadNamespaces,
		RegistrationNamespaces: req.RegistrationNamespaces,
		Webhooks:               req.Webhooks,
		LinkedAppCodes:         req.LinkedAppCodes,
	}
	if req.DefaultRoleCode != "" {
		drc := req.DefaultRoleCode
		in.DefaultRoleCode = &drc
	}
	if req.RegistrationNamespace != "" {
		rn := req.RegistrationNamespace
		in.RegistrationNamespace = &rn
	}
	if req.DefaultOrganizationID != "" {
		orgID, err := types.ParseID(req.DefaultOrganizationID)
		if err != nil {
			writeError(w, errors.InvalidInput("default_organization_id", "must be a valid UUID"))
			return
		}
		in.DefaultOrganizationID = &orgID
	}
	if req.FrontendURL != "" {
		fu := req.FrontendURL
		in.FrontendURL = &fu
	}

	app, err := h.apps.Create(r.Context(), in)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, app)
}

// List handles GET /admin/apps.
func (h *AppHandler) List(w http.ResponseWriter, r *http.Request) {
	apps, err := h.apps.List(r.Context())
	if err != nil {
		handleServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apps": apps})
}

// Get handles GET /admin/apps/{appId}.
func (h *AppHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := types.ParseID(r.PathValue("appId"))
	if err != nil {
		writeError(w, errors.InvalidInput("appId", "invalid app ID"))
		return
	}
	app, err := h.apps.GetByID(r.Context(), id)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, app)
}

// Update handles PATCH /admin/apps/{appId}. Body uses pointer fields so
// partial updates work cleanly.
func (h *AppHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := types.ParseID(r.PathValue("appId"))
	if err != nil {
		writeError(w, errors.InvalidInput("appId", "invalid app ID"))
		return
	}
	var req struct {
		Name                *string   `json:"name"`
		Description         *string   `json:"description"`
		AllowedRedirectURLs *[]string `json:"allowed_redirect_urls"`
		ServiceCodes        *[]string `json:"service_codes"`
		AutoGrantOnSignup   *bool     `json:"auto_grant_on_signup"`
		Status              *string   `json:"status"`

		// Registration policy — PATCH-editable. frontend_url and
		// default_organization_id accept "" to clear back to NULL.
		FrontendURL           *string   `json:"frontend_url"`
		AllowedEmailDomains   *[]string `json:"allowed_email_domains"`
		AllowedAuthMethods    *[]string `json:"allowed_auth_methods"`
		DefaultOrganizationID *string   `json:"default_organization_id"`

		// User pools (migrations 017 + 018). Pointer-wrapped for
		// partial PATCH.
		RegistrationNamespace  *string   `json:"registration_namespace"`
		RegistrationNamespaces *[]string `json:"registration_namespaces"`
		ReadNamespaces         *[]string `json:"read_namespaces"`

		// Webhooks — migration 019. Non-nil replaces the whole list.
		Webhooks *[]domain.AppWebhook `json:"webhooks"`

		// Auto-provisioning config — migration 020 (§7). default_role_code
		// accepts "" to clear back to NULL (⇒ org_member).
		DefaultRoleCode *string   `json:"default_role_code"`
		LinkedAppCodes  *[]string `json:"linked_app_codes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.InvalidInput("body", "invalid request body"))
		return
	}
	in := service.UpdateAppInput{
		Name:                   req.Name,
		Description:            req.Description,
		AllowedRedirectURLs:    req.AllowedRedirectURLs,
		ServiceCodes:           req.ServiceCodes,
		AutoGrantOnSignup:      req.AutoGrantOnSignup,
		Status:                 req.Status,
		FrontendURL:            req.FrontendURL,
		AllowedEmailDomains:    req.AllowedEmailDomains,
		AllowedAuthMethods:     req.AllowedAuthMethods,
		RegistrationNamespace:  req.RegistrationNamespace,
		RegistrationNamespaces: req.RegistrationNamespaces,
		ReadNamespaces:         req.ReadNamespaces,
		Webhooks:               req.Webhooks,
		DefaultRoleCode:        req.DefaultRoleCode,
		LinkedAppCodes:         req.LinkedAppCodes,
	}
	if req.DefaultOrganizationID != nil {
		if *req.DefaultOrganizationID == "" {
			var cleared *types.ID
			in.DefaultOrganizationID = &cleared
		} else {
			orgID, err := types.ParseID(*req.DefaultOrganizationID)
			if err != nil {
				writeError(w, errors.InvalidInput("default_organization_id", "must be a valid UUID or empty string to clear"))
				return
			}
			ptr := &orgID
			in.DefaultOrganizationID = &ptr
		}
	}
	app, err := h.apps.Update(r.Context(), id, in)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, app)
}

// Delete handles DELETE /admin/apps/{appId}.
func (h *AppHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := types.ParseID(r.PathValue("appId"))
	if err != nil {
		writeError(w, errors.InvalidInput("appId", "invalid app ID"))
		return
	}
	if err := h.apps.Delete(r.Context(), id); err != nil {
		handleServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GrantUser handles POST /admin/users/{userId}/apps/{appId}.
func (h *AppHandler) GrantUser(w http.ResponseWriter, r *http.Request) {
	userID, err := types.ParseID(r.PathValue("userId"))
	if err != nil {
		writeError(w, errors.InvalidInput("userId", "invalid user ID"))
		return
	}
	appID, err := types.ParseID(r.PathValue("appId"))
	if err != nil {
		writeError(w, errors.InvalidInput("appId", "invalid app ID"))
		return
	}
	grantedBy := middleware.GetUserID(r.Context())
	if err := h.apps.GrantUser(r.Context(), userID, appID, grantedBy); err != nil {
		handleServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// RevokeUser handles DELETE /admin/users/{userId}/apps/{appId}.
func (h *AppHandler) RevokeUser(w http.ResponseWriter, r *http.Request) {
	userID, err := types.ParseID(r.PathValue("userId"))
	if err != nil {
		writeError(w, errors.InvalidInput("userId", "invalid user ID"))
		return
	}
	appID, err := types.ParseID(r.PathValue("appId"))
	if err != nil {
		writeError(w, errors.InvalidInput("appId", "invalid app ID"))
		return
	}
	if err := h.apps.RevokeUser(r.Context(), userID, appID); err != nil {
		handleServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// RegistrationPolicyResponse is the public, anonymous-readable subset of
// an app's registration policy. Clients use it to pre-filter SSO
// buttons + show a "must be a @ryanweiss.net email" hint BEFORE the user
// submits. The server re-enforces on register — the client signal is UX
// only, never security.
type RegistrationPolicyResponse struct {
	Code                string   `json:"code"`
	Name                string   `json:"name"`
	AllowedEmailDomains []string `json:"allowed_email_domains"`
	AllowedAuthMethods  []string `json:"allowed_auth_methods"`
	HasDefaultOrg       bool     `json:"has_default_organization"`
	DefaultOrgName      string   `json:"default_organization_name,omitempty"`
}

// RegistrationPolicy handles GET /apps/{code}/registration-policy.
// Public endpoint — no auth required. Returns the policy fields a
// client needs to render an accurate register/login form for this app.
// Deliberately omits app internals (id, redirect URLs, service codes,
// metadata) so we don't accidentally expose configuration that should
// stay admin-side.
func (h *AppHandler) RegistrationPolicy(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	if code == "" {
		writeError(w, errors.InvalidInput("code", "app code is required"))
		return
	}
	app, err := h.apps.GetByCode(r.Context(), code)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	resp := RegistrationPolicyResponse{
		Code:                code,
		Name:                app.Name,
		AllowedEmailDomains: []string(app.AllowedEmailDomains),
		AllowedAuthMethods:  []string(app.AllowedAuthMethods),
		HasDefaultOrg:       app.DefaultOrganizationID != nil,
	}
	if app.DefaultOrganizationID != nil {
		if org, err := h.apps.GetDefaultOrganization(r.Context(), *app.DefaultOrganizationID); err == nil && org != nil {
			resp.DefaultOrgName = org.Name
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// ListUserApps handles GET /admin/users/{userId}/apps — admin view of a
// user's active app memberships. Same shape as /me/apps so shared
// renderers work; pairs with GrantUser / RevokeUser for management.
func (h *AppHandler) ListUserApps(w http.ResponseWriter, r *http.Request) {
	userID, err := types.ParseID(r.PathValue("userId"))
	if err != nil {
		writeError(w, errors.InvalidInput("userId", "invalid user ID"))
		return
	}
	apps, err := h.apps.ListForUser(r.Context(), userID)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apps": apps})
}

// MyApps handles GET /me/apps — the authenticated user lists their active
// app memberships.
func (h *AppHandler) MyApps(w http.ResponseWriter, r *http.Request) {
	uid := middleware.GetUserID(r.Context())
	if uid == nil {
		writeError(w, errors.Unauthorized("authentication required"))
		return
	}
	apps, err := h.apps.ListForUser(r.Context(), *uid)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apps": apps})
}
