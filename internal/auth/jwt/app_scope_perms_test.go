package jwt

import (
	"testing"

	"github.com/rw3iss/auth/internal/domain"
	"github.com/rw3iss/auth/pkg/shared/models"
)

func perm(service, code string) *domain.Permission {
	return &domain.Permission{Permission: models.Permission{Code: code, Service: service}}
}

func TestScopePermissionsToApp(t *testing.T) {
	perms := []*domain.Permission{
		perm("philly-civics", "reports.publish"),
		perm("pa-votes", "ballots.certify"),
		perm("core", "users:read"),
		perm("", "legacy:thing"), // pre-005 row with no owner recorded
	}

	t.Run("only the app's own services plus core", func(t *testing.T) {
		app := &domain.App{Code: "philly-civics", ServiceCodes: []string{"philly-civics"}}
		flat, by := scopePermissionsToApp(perms, app)

		if has(flat, "ballots.certify") {
			t.Fatalf("a permission from another app's service leaked into the token: %v", flat)
		}
		if !has(flat, "reports.publish") || !has(flat, "users:read") {
			t.Fatalf("own-service and core permissions must survive, got %v", flat)
		}
		// A permission with no recorded service is treated as core, not dropped.
		if !has(flat, "legacy:thing") {
			t.Fatalf("unowned legacy permission was dropped: %v", flat)
		}
		if len(by["pa-votes"]) != 0 {
			t.Fatalf("perm_scopes exposed another service: %v", by)
		}
	})

	t.Run("a shared service is included when the app declares it", func(t *testing.T) {
		app := &domain.App{Code: "philly-civics", ServiceCodes: []string{"philly-civics", "pa-votes"}}
		flat, _ := scopePermissionsToApp(perms, app)
		if !has(flat, "ballots.certify") {
			t.Fatalf("a declared service's permission must be included, got %v", flat)
		}
	})

	t.Run("no app fails CLOSED to core only", func(t *testing.T) {
		flat, _ := scopePermissionsToApp(perms, nil)
		if has(flat, "reports.publish") || has(flat, "ballots.certify") {
			t.Fatalf("an unscoped token must not carry app permissions, got %v", flat)
		}
		if !has(flat, "users:read") {
			t.Fatalf("core must still be present, got %v", flat)
		}
	})

	t.Run("same code in two services stays distinguishable", func(t *testing.T) {
		rs := []*domain.Permission{
			perm("philly-civics", "reports.publish"),
			perm("pa-votes", "reports.publish"),
		}
		app := &domain.App{ServiceCodes: []string{"philly-civics", "pa-votes"}}
		flat, by := scopePermissionsToApp(rs, app)
		if len(flat) != 1 {
			t.Fatalf("the flat list should de-dupe identical codes, got %v", flat)
		}
		// This is the case the flat list CANNOT express and perm_scopes must.
		if len(by["philly-civics"]) != 1 || len(by["pa-votes"]) != 1 {
			t.Fatalf("perm_scopes must keep both services distinct, got %v", by)
		}
	})
}

func TestHasServicePermission(t *testing.T) {
	c := &TokenClaims{
		Permissions: []string{"reports.publish"},
		PermScopes:  map[string][]string{"philly-civics": {"reports.publish"}},
	}
	if !c.HasServicePermission("philly-civics", "reports.publish") {
		t.Fatal("owning service should match")
	}
	// The whole point: another service's identically-named code must NOT satisfy the check.
	if c.HasServicePermission("pa-votes", "reports.publish") {
		t.Fatal("a different service must not satisfy a service-scoped check")
	}
	if !c.HasPermission("reports.publish") {
		t.Fatal("the bare-code check must stay backward compatible")
	}
}

func has(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
