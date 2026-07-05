package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/rw3iss/auth/internal/api/dto"
	"github.com/rw3iss/auth/internal/api/middleware"
	"github.com/rw3iss/auth/internal/domain"
	"github.com/rw3iss/auth/internal/service"
	"github.com/rw3iss/auth/pkg/shared/errors"
	"github.com/rw3iss/auth/pkg/shared/types"
)

// OrganizationHandler handles organization management endpoints
type OrganizationHandler struct {
	orgService  *service.OrganizationService
	userService *service.UserService
}

// NewOrganizationHandler creates a new organization handler
func NewOrganizationHandler(orgService *service.OrganizationService, userService *service.UserService) *OrganizationHandler {
	return &OrganizationHandler{
		orgService:  orgService,
		userService: userService,
	}
}

// ListOrganizations returns a paginated list of organizations
// GET /admin/organizations
func (h *OrganizationHandler) ListOrganizations(w http.ResponseWriter, r *http.Request) {
	if !requireSystemAdmin(w, r) {
		return
	}

	input := service.ListOrganizationsInput{
		Page:      getQueryParamInt(r, "page", 1),
		PageSize:  getQueryParamInt(r, "page_size", 25),
		SortBy:    getQueryParam(r, "sort_by", ""),
		SortOrder: types.SortOrder(getQueryParam(r, "sort_order", "")),
	}

	if statusStr := getQueryParam(r, "status", ""); statusStr != "" {
		s := types.OrganizationStatus(statusStr)
		input.Status = &s
	}

	result, err := h.orgService.ListOrganizations(r.Context(), input)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	orgResponses := make([]*dto.OrganizationResponse, len(result.Organizations))
	for i, org := range result.Organizations {
		orgResponses[i] = dto.ToOrganizationResponse(org)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"organizations": orgResponses,
		"pagination": map[string]any{
			"page":      result.Pagination.Page,
			"page_size": result.Pagination.PageSize,
			"total":     result.Pagination.Total,
		},
	})
}

// CreateOrganization creates a new organization
// POST /admin/organizations
func (h *OrganizationHandler) CreateOrganization(w http.ResponseWriter, r *http.Request) {
	if !requireSystemAdmin(w, r) {
		return
	}

	callerID := middleware.GetUserID(r.Context())
	if callerID == nil {
		writeError(w, errors.Unauthorized("Authentication required"))
		return
	}

	var req dto.CreateOrganizationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.InvalidInput("body", "Invalid request body"))
		return
	}

	org, err := h.orgService.CreateOrganization(r.Context(), *callerID, service.CreateOrganizationInput{
		Name:         req.Name,
		Description:  req.Description,
		Website:      req.Website,
		ContactEmail: req.ContactEmail,
		ContactPhone: req.ContactPhone,
		Address:      req.Address,
		City:         req.City,
		State:        req.State,
		Country:      req.Country,
		PostalCode:   req.PostalCode,
	})
	if err != nil {
		handleServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, dto.ToOrganizationResponse(org))
}

// GetOrganization returns an organization by ID
// GET /admin/organizations/{orgId}
func (h *OrganizationHandler) GetOrganization(w http.ResponseWriter, r *http.Request) {
	if !requireSystemAdmin(w, r) {
		return
	}

	orgIDStr := r.PathValue("orgId")
	if orgIDStr == "" {
		writeError(w, errors.InvalidInput("orgId", "Organization ID is required"))
		return
	}

	orgID, err := types.ParseID(orgIDStr)
	if err != nil {
		writeError(w, errors.InvalidInput("orgId", "Invalid organization ID"))
		return
	}

	org, err := h.orgService.GetOrganization(r.Context(), orgID)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, dto.ToOrganizationResponse(org))
}

// UpdateOrganization updates an organization
// PUT /admin/organizations/{orgId}
func (h *OrganizationHandler) UpdateOrganization(w http.ResponseWriter, r *http.Request) {
	if !requireSystemAdmin(w, r) {
		return
	}

	orgIDStr := r.PathValue("orgId")
	if orgIDStr == "" {
		writeError(w, errors.InvalidInput("orgId", "Organization ID is required"))
		return
	}

	orgID, err := types.ParseID(orgIDStr)
	if err != nil {
		writeError(w, errors.InvalidInput("orgId", "Invalid organization ID"))
		return
	}

	var req dto.UpdateOrganizationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.InvalidInput("body", "Invalid request body"))
		return
	}

	input := service.UpdateOrganizationInput{
		Name:         req.Name,
		Description:  req.Description,
		LogoURL:      req.LogoURL,
		Website:      req.Website,
		ContactEmail: req.ContactEmail,
		ContactPhone: req.ContactPhone,
		Address:      req.Address,
		City:         req.City,
		State:        req.State,
		Country:      req.Country,
		PostalCode:   req.PostalCode,
	}

	org, err := h.orgService.UpdateOrganization(r.Context(), orgID, input)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, dto.ToOrganizationResponse(org))
}

// DeleteOrganization deletes an organization
// DELETE /admin/organizations/{orgId}
func (h *OrganizationHandler) DeleteOrganization(w http.ResponseWriter, r *http.Request) {
	if !requireSystemAdmin(w, r) {
		return
	}

	orgIDStr := r.PathValue("orgId")
	if orgIDStr == "" {
		writeError(w, errors.InvalidInput("orgId", "Organization ID is required"))
		return
	}

	orgID, err := types.ParseID(orgIDStr)
	if err != nil {
		writeError(w, errors.InvalidInput("orgId", "Invalid organization ID"))
		return
	}

	if err := h.orgService.DeleteOrganization(r.Context(), orgID); err != nil {
		handleServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// ListMembers returns the members of an organization
// GET /admin/organizations/{orgId}/members
func (h *OrganizationHandler) ListMembers(w http.ResponseWriter, r *http.Request) {
	if !requireSystemAdmin(w, r) {
		return
	}

	orgIDStr := r.PathValue("orgId")
	if orgIDStr == "" {
		writeError(w, errors.InvalidInput("orgId", "Organization ID is required"))
		return
	}

	orgID, err := types.ParseID(orgIDStr)
	if err != nil {
		writeError(w, errors.InvalidInput("orgId", "Invalid organization ID"))
		return
	}

	input := service.ListMembersInput{
		Page:     getQueryParamInt(r, "page", 1),
		PageSize: getQueryParamInt(r, "page_size", 25),
	}

	if statusStr := getQueryParam(r, "status", ""); statusStr != "" {
		s := domain.MembershipStatus(statusStr)
		input.Status = &s
	}

	result, err := h.orgService.ListMembers(r.Context(), orgID, input)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	memberResponses := make([]*dto.MemberResponse, len(result.Members))
	for i, m := range result.Members {
		memberResponses[i] = dto.ToMemberResponse(m)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"members": memberResponses,
		"pagination": map[string]any{
			"page":      result.Pagination.Page,
			"page_size": result.Pagination.PageSize,
			"total":     result.Pagination.Total,
		},
	})
}

// AddMember adds a member to an organization
// POST /admin/organizations/{orgId}/members
func (h *OrganizationHandler) AddMember(w http.ResponseWriter, r *http.Request) {
	if !requireSystemAdmin(w, r) {
		return
	}

	callerID := middleware.GetUserID(r.Context())
	if callerID == nil {
		writeError(w, errors.Unauthorized("Authentication required"))
		return
	}

	orgIDStr := r.PathValue("orgId")
	if orgIDStr == "" {
		writeError(w, errors.InvalidInput("orgId", "Organization ID is required"))
		return
	}

	orgID, err := types.ParseID(orgIDStr)
	if err != nil {
		writeError(w, errors.InvalidInput("orgId", "Invalid organization ID"))
		return
	}

	var req struct {
		UserID  string   `json:"user_id"`
		RoleIDs []string `json:"role_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.InvalidInput("body", "Invalid request body"))
		return
	}

	userID, err := types.ParseID(req.UserID)
	if err != nil {
		writeError(w, errors.InvalidInput("user_id", "Invalid user ID"))
		return
	}

	roleIDs := make([]types.ID, 0, len(req.RoleIDs))
	for _, idStr := range req.RoleIDs {
		id, err := types.ParseID(idStr)
		if err != nil {
			writeError(w, errors.InvalidInput("role_ids", "Invalid role ID: "+idStr))
			return
		}
		roleIDs = append(roleIDs, id)
	}

	if err := h.orgService.AddMember(r.Context(), orgID, userID, roleIDs, *callerID); err != nil {
		handleServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// RemoveMember removes a member from an organization
// DELETE /admin/organizations/{orgId}/members/{userId}
func (h *OrganizationHandler) RemoveMember(w http.ResponseWriter, r *http.Request) {
	if !requireSystemAdmin(w, r) {
		return
	}

	orgIDStr := r.PathValue("orgId")
	if orgIDStr == "" {
		writeError(w, errors.InvalidInput("orgId", "Organization ID is required"))
		return
	}

	orgID, err := types.ParseID(orgIDStr)
	if err != nil {
		writeError(w, errors.InvalidInput("orgId", "Invalid organization ID"))
		return
	}

	userIDStr := r.PathValue("userId")
	if userIDStr == "" {
		writeError(w, errors.InvalidInput("userId", "User ID is required"))
		return
	}

	userID, err := types.ParseID(userIDStr)
	if err != nil {
		writeError(w, errors.InvalidInput("userId", "Invalid user ID"))
		return
	}

	if err := h.orgService.RemoveMember(r.Context(), orgID, userID); err != nil {
		handleServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// UpdateMemberStatus updates the status of a member in an organization
// PUT /admin/organizations/{orgId}/members/{userId}/status
func (h *OrganizationHandler) UpdateMemberStatus(w http.ResponseWriter, r *http.Request) {
	if !requireSystemAdmin(w, r) {
		return
	}

	orgIDStr := r.PathValue("orgId")
	if orgIDStr == "" {
		writeError(w, errors.InvalidInput("orgId", "Organization ID is required"))
		return
	}

	orgID, err := types.ParseID(orgIDStr)
	if err != nil {
		writeError(w, errors.InvalidInput("orgId", "Invalid organization ID"))
		return
	}

	userIDStr := r.PathValue("userId")
	if userIDStr == "" {
		writeError(w, errors.InvalidInput("userId", "User ID is required"))
		return
	}

	userID, err := types.ParseID(userIDStr)
	if err != nil {
		writeError(w, errors.InvalidInput("userId", "Invalid user ID"))
		return
	}

	var req struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.InvalidInput("body", "Invalid request body"))
		return
	}

	if err := h.orgService.UpdateMemberStatus(r.Context(), userID, orgID, domain.MembershipStatus(req.Status)); err != nil {
		handleServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// SetMemberRoles handles PUT /admin/organizations/{orgId}/members/{userId}/roles
// — replace a member's organization-role set (set semantics). Backs
// the demo's "change organization admin" flow: promote the new admin
// with roles ∪ {org_admin}, demote the old one with roles ∖ {org_admin}.
func (h *OrganizationHandler) SetMemberRoles(w http.ResponseWriter, r *http.Request) {
	if !requireSystemAdmin(w, r) {
		return
	}

	orgID, err := types.ParseID(r.PathValue("orgId"))
	if err != nil {
		writeError(w, errors.InvalidInput("orgId", "Invalid organization ID"))
		return
	}
	userID, err := types.ParseID(r.PathValue("userId"))
	if err != nil {
		writeError(w, errors.InvalidInput("userId", "Invalid user ID"))
		return
	}

	var req struct {
		RoleCodes []string `json:"role_codes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.InvalidInput("body", "Invalid request body"))
		return
	}
	if req.RoleCodes == nil {
		writeError(w, errors.InvalidInput("role_codes", "role_codes is required (use [] to clear)"))
		return
	}

	actor := middleware.GetUserID(r.Context())
	if actor == nil {
		writeError(w, errors.Unauthorized("authentication required"))
		return
	}

	membership, err := h.orgService.SetMemberRoles(r.Context(), userID, orgID, req.RoleCodes, *actor)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, dto.ToMemberResponse(membership))
}
