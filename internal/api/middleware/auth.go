// Package middleware provides HTTP middleware for the API
package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/rw3iss/auth/internal/auth/jwt"
	"github.com/rw3iss/auth/internal/logging"
	"github.com/rw3iss/auth/pkg/shared/errors"
	"github.com/rw3iss/auth/pkg/shared/types"
)

// contextKey is a type for context keys
type contextKey string

const (
	// ContextKeyClaims is the context key for JWT claims
	ContextKeyClaims contextKey = "claims"
	// ContextKeyUserID is the context key for user ID
	ContextKeyUserID contextKey = "user_id"
	// ContextKeyOrgID is the context key for organization ID
	ContextKeyOrgID contextKey = "org_id"
)

// AuthMiddleware provides authentication middleware
type AuthMiddleware struct {
	jwtService *jwt.Service
}

// NewAuthMiddleware creates a new auth middleware
func NewAuthMiddleware(jwtService *jwt.Service) *AuthMiddleware {
	return &AuthMiddleware{
		jwtService: jwtService,
	}
}

// Authenticate validates the JWT token and adds claims to context
func (m *AuthMiddleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractToken(r)
		if token == "" {
			writeError(w, errors.Unauthorized("Missing authorization token"))
			return
		}

		claims, err := m.jwtService.ValidateAccessToken(token)
		if err != nil {
			if appErr, ok := errors.AsAppError(err); ok {
				writeError(w, appErr)
			} else {
				writeError(w, errors.TokenInvalid())
			}
			return
		}

		// Add claims to context + stamp the user_id onto the logging
		// context so any service-layer log line emitted during this
		// request carries the user_id field automatically.
		ctx := context.WithValue(r.Context(), ContextKeyClaims, claims)
		ctx = context.WithValue(ctx, ContextKeyUserID, claims.UserID)
		ctx = logging.WithUserID(ctx, claims.UserID.String())
		if claims.OrganizationID != nil {
			ctx = context.WithValue(ctx, ContextKeyOrgID, *claims.OrganizationID)
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// OptionalAuth optionally validates the JWT token if present
func (m *AuthMiddleware) OptionalAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractToken(r)
		if token != "" {
			claims, err := m.jwtService.ValidateAccessToken(token)
			if err == nil {
				ctx := context.WithValue(r.Context(), ContextKeyClaims, claims)
				ctx = context.WithValue(ctx, ContextKeyUserID, claims.UserID)
				ctx = logging.WithUserID(ctx, claims.UserID.String())
				if claims.OrganizationID != nil {
					ctx = context.WithValue(ctx, ContextKeyOrgID, *claims.OrganizationID)
				}
				r = r.WithContext(ctx)
			}
		}
		next.ServeHTTP(w, r)
	})
}

// RequireRole requires the user to have a specific role
func (m *AuthMiddleware) RequireRole(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := GetClaims(r.Context())
			if claims == nil {
				writeError(w, errors.Unauthorized("Authentication required"))
				return
			}

			hasRole := false
			for _, role := range roles {
				if claims.HasRole(role) {
					hasRole = true
					break
				}
			}

			if !hasRole {
				writeError(w, errors.InsufficientPermissions("access this resource"))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequirePermission requires the user to have a specific permission
func (m *AuthMiddleware) RequirePermission(permissions ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := GetClaims(r.Context())
			if claims == nil {
				writeError(w, errors.Unauthorized("Authentication required"))
				return
			}

			// system_admin is a platform superuser (a strict superset of every scoped permission), so it
			// bypasses per-permission checks — consistent with RequireOrgContext's system_admin bypass. This
			// lets a system_admin operate the org self-service endpoints (members/invitations/roles/…) for any
			// org without holding the org-scoped permission grants a member would.
			if claims.IsSystemAdmin() {
				next.ServeHTTP(w, r)
				return
			}

			hasPermission := false
			for _, perm := range permissions {
				if claims.HasPermission(perm) {
					hasPermission = true
					break
				}
			}

			if !hasPermission {
				writeError(w, errors.InsufficientPermissions("perform this action"))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAllPermissions requires the user to have all specified permissions
func (m *AuthMiddleware) RequireAllPermissions(permissions ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := GetClaims(r.Context())
			if claims == nil {
				writeError(w, errors.Unauthorized("Authentication required"))
				return
			}

			if claims.IsSystemAdmin() { // superuser bypass (see RequirePermission)
				next.ServeHTTP(w, r)
				return
			}

			if !claims.HasAllPermissions(permissions...) {
				writeError(w, errors.InsufficientPermissions("perform this action"))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireOrgContext requires the caller's JWT to carry org context AND for
// that org_id to match the {orgId} path param when one is present.
//
// AUDIT 2.4 + 2.8: gates the /orgs/{orgId}/... self-service endpoints.
// system_admin bypasses the path-match check so they can operate in any org
// without re-authenticating. When mounted on a route without an {orgId}
// param, behaves like the original "just require org context" check.
func (m *AuthMiddleware) RequireOrgContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := GetClaims(r.Context())
		if claims == nil {
			writeError(w, errors.Unauthorized("Authentication required"))
			return
		}
		if claims.IsSystemAdmin() {
			next.ServeHTTP(w, r)
			return
		}
		if claims.OrganizationID == nil {
			writeError(w, errors.Forbidden("Organization context required"))
			return
		}
		orgIDFromPath := r.PathValue("orgId")
		if orgIDFromPath != "" {
			parsed, err := types.ParseID(orgIDFromPath)
			if err != nil {
				writeError(w, errors.InvalidInput("orgId", "Invalid organization ID"))
				return
			}
			if *claims.OrganizationID != parsed {
				writeError(w, errors.Forbidden("Token is not scoped to this organization"))
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// RequireSystemAdmin requires the user to be a system admin. Apply at the
// route layer so every /admin/* platform-internal path inherits the same
// gate; AUDIT 2.5 flagged that this was previously duplicated per-handler.
//
// Use this for routes that touch platform internals (app registration,
// service permission self-registration, JWT secret rotation, etc.).
// For routes that just manage data across orgs (users, orgs, members,
// background jobs), use RequirePlatformAdmin which also accepts
// super_admin.
func (m *AuthMiddleware) RequireSystemAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := GetClaims(r.Context())
		if claims == nil {
			writeError(w, errors.Unauthorized("Authentication required"))
			return
		}

		if !claims.IsSystemAdmin() {
			writeError(w, errors.InsufficientPermissions("access this resource"))
			return
		}

		next.ServeHTTP(w, r)
	})
}

// RequirePlatformAdmin gates a route on system_admin OR super_admin.
// Use this for cross-org data administration (users, organizations,
// members, background jobs) where operations / customer-success staff
// (super_admin) should have access alongside platform owners
// (system_admin).
//
// system_admin is a strict superset of super_admin's reach, so checking
// either role is sufficient; downstream handler logic can still depend on
// IsSystemAdmin() for the few cases where the distinction matters.
func (m *AuthMiddleware) RequirePlatformAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := GetClaims(r.Context())
		if claims == nil {
			writeError(w, errors.Unauthorized("Authentication required"))
			return
		}
		if !claims.IsSystemAdmin() && !claims.HasRole("super_admin") {
			writeError(w, errors.InsufficientPermissions("access this resource"))
			return
		}
		next.ServeHTTP(w, r)
	})
}


// GetClaims retrieves claims from context
func GetClaims(ctx context.Context) *jwt.TokenClaims {
	claims, ok := ctx.Value(ContextKeyClaims).(*jwt.TokenClaims)
	if !ok {
		return nil
	}
	return claims
}

// GetUserID retrieves user ID from context
func GetUserID(ctx context.Context) *types.ID {
	id, ok := ctx.Value(ContextKeyUserID).(types.ID)
	if !ok {
		return nil
	}
	return &id
}

// GetOrgID retrieves organization ID from context
func GetOrgID(ctx context.Context) *types.ID {
	id, ok := ctx.Value(ContextKeyOrgID).(types.ID)
	if !ok {
		return nil
	}
	return &id
}

// extractToken returns the bearer access token from the request, accepting
// ONLY the `Authorization: Bearer <token>` header (AUDIT 1.18).
//
// The previous implementation also accepted `?access_token=...` query
// strings and `access_token` cookies. Both were unsafe in this server's
// threat model:
//
//   - Query-string tokens leak into every access log, every browser
//     history entry, every Referer header, every server-side observability
//     pipeline. There's no way to grep them out after the fact.
//   - Unrestricted `access_token` cookies have no SameSite / Secure /
//     HttpOnly enforcement at the read side, and the server doesn't
//     issue cookies in the first place. The path was dead-letter at best
//     and a CSRF vector at worst.
//
// Cookie-based auth is a legitimate design — it's covered by a separate
// custom middleware (`internal/api/middleware/cookie.go` for the future
// HttpOnly-cookie path) that explicitly Set-Cookies + reads paired with
// CSRF double-submit. We don't conflate it with bearer extraction.
func extractToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return ""
	}
	return parts[1]
}
