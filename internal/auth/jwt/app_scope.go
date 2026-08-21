package jwt

import (
	"sort"

	"github.com/rw3iss/auth/internal/domain"
)

// coreService owns the auth server's own permissions (users, orgs, roles). Every app can see them —
// they describe THIS server, not any consuming application.
const coreService = "core"

// scopePermissionsToApp filters a user's permissions down to the ones the TOKEN'S APP may actually use,
// and returns them both flat and grouped by owning service.
//
// WHY THIS EXISTS. A person's roles are platform-wide facts; a token is issued for ONE app. Without this
// filter, someone who belongs to three portals carried the union of all their permissions in every token
// — so a token minted for a city portal advertised authority granted by a state one. Nothing exploited it
// (each service checks for its own codes), but the token overstated what it was for, and a resource
// server that trusted the list rather than a specific code would have been wrong.
//
// The allow-list is `apps.service_codes`: an app declares which services it consumes. That column already
// existed for exactly this relationship; nothing new is invented here.
//
// WHY BOTH SHAPES. `permissions` stays a flat []string so existing consumers and `HasPermission` keep
// working unchanged. `perm_scopes` groups the same codes by service, which is what makes the claim
// UNAMBIGUOUS — codes are unique per (service, code) since migration 026, so two services may legitimately
// define `reports.publish` and a flat list cannot tell them apart.
//
// FAIL-CLOSED ON AN UNSCOPED TOKEN. A nil app (base-user mode) yields `core` permissions only. The
// alternative — passing everything through — would make "no app" the widest possible token, which is
// exactly backwards.
func scopePermissionsToApp(roles []*domain.Role, app *domain.App) (flat []string, byService map[string][]string) {
	allowed := map[string]bool{coreService: true}
	if app != nil {
		for _, sc := range app.ServiceCodes {
			if sc != "" {
				allowed[sc] = true
			}
		}
	}

	byService = map[string][]string{}
	seen := map[string]bool{}
	for _, r := range roles {
		if r == nil {
			continue
		}
		for _, p := range r.Permissions {
			svc := p.Service
			if svc == "" {
				// A permission predating migration 005 has no owner recorded. Treat it as core rather
				// than dropping it: these are the auth server's own, and silently removing a permission
				// is a worse failure than including one too many.
				svc = coreService
			}
			if !allowed[svc] {
				continue
			}
			key := svc + "\x00" + p.Code
			if seen[key] {
				continue
			}
			seen[key] = true
			byService[svc] = append(byService[svc], p.Code)
		}
	}

	// Deterministic ordering: a token whose claims reshuffle between issues is needlessly hard to diff
	// in a log or a test.
	for svc := range byService {
		sort.Strings(byService[svc])
	}
	flatSeen := map[string]bool{}
	services := make([]string, 0, len(byService))
	for svc := range byService {
		services = append(services, svc)
	}
	sort.Strings(services)
	for _, svc := range services {
		for _, code := range byService[svc] {
			// The flat list de-dupes across services, so two services sharing a code appear once here.
			// `perm_scopes` is the shape that distinguishes them.
			if !flatSeen[code] {
				flatSeen[code] = true
				flat = append(flat, code)
			}
		}
	}
	if flat == nil {
		flat = []string{}
	}
	return flat, byService
}
