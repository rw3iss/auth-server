// Package migration defines the contract for "auxiliary" identity providers
// that the auth-server can consult during login when the internal user
// database doesn't know the email.
//
// Why a separate package — and under pkg/, not internal/:
//
//   - The auth-server's core has no business knowing about AWS Cognito,
//     Auth0, or any other legacy identity store. Those are implementation
//     details of *one specific deployment* (rw3iss's migration off
//     Cognito). Other consumers of this codebase should be able to ignore
//     the whole tree.
//   - SOLID-shaped: the auth-server depends on the LegacyAuthProvider
//     interface declared here, never on a concrete implementation. The
//     concrete impl (pkg/migration/cognito) is wired in by main.go when
//     the relevant env is set; absent that, the auth-server runs without
//     any awareness of legacy systems.
//   - Future replacement: when an Auth0 or Okta migration shows up, drop
//     another package alongside cognito/ implementing the same interface.
//     No auth-server changes required.
//
// The whole point of this package is that you can read the auth-server
// without ever opening it, and you can read this without ever opening the
// auth-server.
package migration

import "context"

// LegacyAuthProvider is implemented by adapters that can answer
// "does this email exist in the legacy system, and can it authenticate?"
//
// Implementations MUST be safe for concurrent use. Implementations SHOULD
// be tolerant of upstream outages — returning a transient error is fine;
// returning a misleading "user not found" when the upstream is down is not.
// Callers (AuthService.Login) treat any error other than ErrLegacyUserNotFound
// as transient and fail the login with a generic InvalidCredentials response.
type LegacyAuthProvider interface {
	// Name returns a stable identifier ("cognito", "auth0", etc.). Used in
	// audit logs and the per-user "migrated_from" attribute.
	Name() string

	// TryLogin attempts to authenticate the user against the legacy system
	// using the submitted password. Returns the legacy user profile on
	// success, ErrLegacyUserNotFound when the user doesn't exist in the
	// legacy store, or any other error (treated as transient failure).
	//
	// The submitted password is consumed in cleartext here, by design —
	// the adapter passes it through to the legacy auth provider's own
	// password-verification API. The caller (AuthService.Login) hashes it
	// with bcrypt before persisting the migrated user in the internal DB.
	TryLogin(ctx context.Context, email, password string) (*LegacyUser, error)
}

// LegacyUser is the profile fetched from the legacy system after a
// successful login. Used by AuthService to seed the internal user row.
//
// Fields map roughly to internal/domain/user.User columns; missing values
// (nil string fields) default to empty on the internal side.
type LegacyUser struct {
	// Email is normalised (lowercased) before being returned.
	Email     string
	FirstName string
	LastName  string
	Phone     string

	// Roles are the legacy system's role identifiers — e.g. Cognito group
	// names like "SELLER", "ADMIN", "CUSTOMER". The auth-server's RoleMapper
	// translates these to internal role codes; what the adapter ships is
	// the raw legacy strings so the mapping policy lives in one place.
	Roles []string

	// Attributes carries any extra profile fields (display_name, avatar_url,
	// custom org-scoped attributes, etc.). Map keys are lowercased.
	// Unknown keys are ignored by the migration handler; known ones get
	// merged into the new internal user row.
	Attributes map[string]string

	// EmailVerified mirrors the legacy system's verification flag. The
	// migrated internal user inherits this — we trust the source of truth
	// that previously held the user.
	EmailVerified bool
}

// ErrLegacyUserNotFound is returned by TryLogin when the email is not
// present in the legacy system. AuthService distinguishes this from
// transient errors so the response can be a clean InvalidCredentials
// (matching the response shape of a bad password against an internal user)
// without leaking which side failed.
type Error string

func (e Error) Error() string { return string(e) }

const (
	// ErrLegacyUserNotFound — TryLogin signals that the email isn't in the
	// legacy store. AuthService treats this as "no fallback available."
	ErrLegacyUserNotFound = Error("legacy user not found")
	// ErrLegacyLoginFailed — the user exists in the legacy store but the
	// password didn't match. AuthService surfaces this as a plain
	// InvalidCredentials so the response shape matches a normal failed
	// internal login. The leak we're preventing: an attacker discovering
	// "this user used to be on Cognito" via error-class differences.
	ErrLegacyLoginFailed = Error("legacy login failed")
)

// RoleMapper translates legacy role strings to internal role codes. The
// default implementation (DefaultRoleMapper) is a best-guess case-insensitive
// table; operators can replace it for environment-specific mappings.
//
// Contract: NEVER return "system_admin" — the system admin role is reserved
// for explicit grants by existing system admins; legacy systems may have
// used a similarly-named role for any number of things, and an attacker
// who could create such a role in the legacy system could escalate via
// migration. The DefaultRoleMapper enforces this.
type RoleMapper interface {
	// Map returns the internal role codes for the given legacy role strings.
	// Order doesn't matter; duplicates are de-duplicated by the caller.
	// Returning an empty slice is valid — the user gets the platform's
	// default base_user role assigned automatically by AuthService.
	Map(legacyRoles []string) []string
}

// DefaultRoleMapper is the built-in mapping table. Covers the rw3iss
// Cognito groups; extend or replace for other deployments.
//
// Mappings (case-insensitive):
//
//	SELLER                       → seller
//	SELLERADMIN                  → seller, org_admin
//	ADMIN                        → org_admin
//	SUPER_ADMIN, SUPERADMIN      → super_admin  (cross-org, but not platform owner)
//	CUSTOMER, BUYER              → customer
//	LISTER                       → lister
//	MANAGER                      → manager
//	SELLERTESTER                 → sellertester
//	BUYERTESTER                  → buyertester
//	SYSTEM_ADMIN, SYSTEMADMIN    → (DROPPED — never auto-grant the platform-owner role)
//
// Anything not in the table is dropped silently; the user falls back to
// base_user via the standard registration flow.
//
// Note: super_admin auto-mapping is intentional. The role is granular —
// cross-org data management only — and migration from Cognito SUPER_ADMIN
// to internal super_admin preserves operational continuity for existing
// rw3iss ops staff. The platform-owner role (system_admin) is
// deliberately distinct and never inherited from a legacy system.
type DefaultRoleMapper struct{}

func (DefaultRoleMapper) Map(legacyRoles []string) []string {
	out := make([]string, 0, len(legacyRoles))
	seen := make(map[string]struct{}, len(legacyRoles))
	add := func(code string) {
		if code == "" {
			return
		}
		if _, exists := seen[code]; exists {
			return
		}
		seen[code] = struct{}{}
		out = append(out, code)
	}
	for _, raw := range legacyRoles {
		switch normalizeLegacyRole(raw) {
		case "seller":
			add("seller")
		case "selleradmin":
			add("seller")
			add("org_admin")
		case "admin":
			add("org_admin")
		case "super_admin", "superadmin":
			add("super_admin")
		case "customer", "buyer":
			add("customer")
		case "lister":
			add("lister")
		case "manager":
			add("manager")
		case "sellertester":
			add("sellertester")
		case "buyertester":
			add("buyertester")
		case "system_admin", "systemadmin":
			// Deliberately dropped — system_admin is the platform-owner
			// role and is never granted via migration. An attacker who
			// created such a group in the legacy system could otherwise
			// escalate via migration.
		default:
			// Unknown role; drop silently.
		}
	}
	return out
}

// normalizeLegacyRole lowercases + trims a legacy role string so the
// comparison table can stay tidy.
func normalizeLegacyRole(raw string) string {
	b := make([]byte, 0, len(raw))
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c == ' ' || c == '\t' {
			continue
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b = append(b, c)
	}
	return string(b)
}
