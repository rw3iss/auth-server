package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/rw3iss/auth/internal/api/dto"
	"github.com/rw3iss/auth/internal/domain"
	"github.com/rw3iss/auth/internal/repository"
	"github.com/rw3iss/auth/pkg/shared/errors"
)

// PermissionHandler handles service-to-auth permission operations.
type PermissionHandler struct {
	permRepo repository.PermissionRepository
}

// NewPermissionHandler constructs a PermissionHandler.
func NewPermissionHandler(permRepo repository.PermissionRepository) *PermissionHandler {
	return &PermissionHandler{permRepo: permRepo}
}

// RegisterPermissions upserts a service's permission catalog and prunes any
// rows previously owned by the service but no longer declared.
//
// POST /api/v1/admin/permissions/register
//
// Requires system_admin in the access token. When service-to-service auth
// lands, switch this gate to a dedicated machine principal instead of reusing
// a human admin's JWT.
func (h *PermissionHandler) RegisterPermissions(w http.ResponseWriter, r *http.Request) {
	if !requireSystemAdmin(w, r) {
		return
	}

	var req dto.RegisterPermissionsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.InvalidInput("body", "Invalid JSON body"))
		return
	}

	req.Service = strings.TrimSpace(req.Service)
	if req.Service == "" {
		writeError(w, errors.InvalidInput("service", "service is required"))
		return
	}
	if req.Service == "core" {
		writeError(w, errors.InvalidInput("service", "service=\"core\" is reserved for auth-owned permissions"))
		return
	}

	// Convert DTO entries to domain objects. SyncForService will set Service on
	// each permission and handle the upsert + prune in a single transaction.
	perms := make([]*domain.Permission, 0, len(req.Permissions))
	for _, p := range req.Permissions {
		if p.Code == "" || p.Resource == "" || p.Action == "" {
			writeError(w, errors.InvalidInput("permissions", "code, resource, and action are required for every permission"))
			return
		}
		// Use NewPermission for the BaseModel fields (id, timestamps); then
		// overwrite Code to honor the caller's explicit value (may be prefixed).
		perm := domain.NewPermission(p.Resource, p.Action, p.Name, p.Description, p.Category)
		perm.Code = p.Code
		perms = append(perms, perm)
	}

	if err := h.permRepo.SyncForService(r.Context(), req.Service, perms); err != nil {
		handleServiceError(w, err)
		return
	}

	// PrunedCodes is intentionally empty for now — computing the exact set
	// would require a second query per request. Add a PermissionFilter.Service
	// field when a consumer actually needs that info. The sync itself is
	// still declarative: what's not in `Permissions` is gone.
	writeJSON(w, http.StatusOK, dto.RegisterPermissionsResponse{
		Service:       req.Service,
		UpsertedCount: len(perms),
	})
}
