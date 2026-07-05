// Package dto contains request and response types for API handlers
package dto

// RegisterPermissionsRequest is sent by a service (usually at boot) to
// declare the full set of permissions it owns. Auth reconciles — upserts
// every declared permission and removes previously-declared permissions
// the service no longer claims.
//
// This is the "service self-registers its slice of the catalog" API. It's
// idempotent and safe to call on every boot.
type RegisterPermissionsRequest struct {
	Service     string                        `json:"service"`     // e.g. "release-manager"
	Permissions []RegisterPermissionEntry     `json:"permissions"`
}

// RegisterPermissionEntry describes one permission the caller claims.
type RegisterPermissionEntry struct {
	Code        string `json:"code"`                  // Globally unique. Format: "resource:action".
	Name        string `json:"name"`                  // Human-readable label.
	Description string `json:"description,omitempty"` // Optional description.
	Resource    string `json:"resource"`              // Resource slug, e.g. "releases".
	Action      string `json:"action"`                // Action slug, e.g. "create".
	Category    string `json:"category,omitempty"`    // Optional grouping.
}

// RegisterPermissionsResponse reports how many permissions landed on each
// side of the reconciliation.
type RegisterPermissionsResponse struct {
	Service       string   `json:"service"`
	UpsertedCount int      `json:"upserted_count"`
	PrunedCodes   []string `json:"pruned_codes,omitempty"` // Codes removed because no longer declared
}
