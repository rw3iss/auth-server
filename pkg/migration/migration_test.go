package migration

import (
	"slices"
	"testing"
)

// AUDIT B7b: the default role mapper MUST never auto-grant system_admin,
// no matter what the legacy system called it. An attacker who could
// create such a role in the legacy store would otherwise gain platform-
// level control via migration.
//
// Note: super_admin IS allowed via migration (different role — cross-org
// data admin, not platform owner). It's only system_admin that's reserved.
func TestDefaultRoleMapperRefusesSystemAdmin(t *testing.T) {
	m := DefaultRoleMapper{}
	for _, evil := range []string{
		"system_admin", "SYSTEM_ADMIN", "SystemAdmin", "systemadmin",
		"  SYSTEM_ADMIN  ",
	} {
		got := m.Map([]string{evil})
		if slices.Contains(got, "system_admin") {
			t.Fatalf("legacy role %q must never produce system_admin: %v", evil, got)
		}
	}
}

func TestDefaultRoleMapperAllowsSuperAdmin(t *testing.T) {
	m := DefaultRoleMapper{}
	for _, variant := range []string{"SUPER_ADMIN", "super_admin", "SuperAdmin", "superadmin"} {
		got := m.Map([]string{variant})
		if !slices.Contains(got, "super_admin") {
			t.Fatalf("legacy role %q should map to super_admin, got %v", variant, got)
		}
	}
}

func TestDefaultRoleMapperKnownRoles(t *testing.T) {
	m := DefaultRoleMapper{}
	cases := []struct {
		legacy []string
		want   []string
	}{
		{[]string{"SELLER"}, []string{"seller"}},
		{[]string{"selleradmin"}, []string{"seller", "org_admin"}},
		{[]string{"CUSTOMER"}, []string{"customer"}},
		{[]string{"BUYER"}, []string{"customer"}}, // alias
		{[]string{"LISTER", "MANAGER"}, []string{"lister", "manager"}},
		{[]string{"unknown_role"}, []string{}},
		// De-dup: same role twice with different casing → single output
		{[]string{"SELLER", "Seller", "seller"}, []string{"seller"}},
		// Combined: seller + selleradmin → seller appears once
		{[]string{"selleradmin", "seller"}, []string{"seller", "org_admin"}},
	}
	for _, tc := range cases {
		got := m.Map(tc.legacy)
		if !slices.Equal(got, tc.want) {
			t.Errorf("Map(%v) = %v, want %v", tc.legacy, got, tc.want)
		}
	}
}

func TestDefaultRoleMapperEmptyInput(t *testing.T) {
	m := DefaultRoleMapper{}
	if got := m.Map(nil); len(got) != 0 {
		t.Fatalf("expected empty result for nil input, got %v", got)
	}
	if got := m.Map([]string{}); len(got) != 0 {
		t.Fatalf("expected empty result for empty slice, got %v", got)
	}
}
